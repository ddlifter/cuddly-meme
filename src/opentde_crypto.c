/*
 * opentde_crypto.c — Криптографический модуль OpenTDE.
 *
 * Отвечает за:
 *   - Генерацию криптографически стойких случайных чисел
 *   - Обёртывание (wrap) и разворачивание (unwrap) DEK мастер-ключом
 *   - Получение или создание DEK для конкретной таблицы
 *   - Шифрование/дешифрование данных шифром «Кузнечик» (ГОСТ Р 34.12-2015)
 *     в режиме CTR (гаммирование)
 *   - Шифрование payload кортежа в памяти перед записью в heap
 *
 * Схема шифрования:
 *   1. Для каждого кортежа генерируется случайный 128-битный IV
 *   2. DEK таблицы используется как ключ шифра «Кузнечик»
 *   3. Шифрование выполняется в режиме CTR: XOR открытого текста с гаммой
 *   4. Дешифрование — повторное применение той же операции (CTR симметричен)
 *
 * Шифрование выполняется ДО вызова heap_insert/heap_update/heap_multi_insert,
 * чтобы в WAL-журнал попадали уже зашифрованные данные.
 */
#include "opentde.h"

#include "port.h"                  /* PG_BINARY */

#include <string.h>

/* =====================================================================
 * Генерация случайных чисел
 * ===================================================================== */

/*
 * Генерация криптографически стойких случайных байт.
 * Использует pg_strong_random() из PostgreSQL (обёртка над /dev/urandom
 * или CryptGenRandom на Windows).
 *
 * context_name — описание контекста для сообщения об ошибке.
 */
void
opentde_fill_random_bytes(uint8_t *buf, size_t len,
                          const char *context_name)
{
    if (!pg_strong_random(buf, len))
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("failed to generate random bytes for %s",
                        context_name)));
}

/* =====================================================================
 * Обёртывание / разворачивание DEK
 *
 * DEK хранится на диске в обёрнутом виде:
 *   wrapped_dek = [IV (16 байт)] [зашифрованный DEK (32 байта)]
 *
 * Для обёртывания: генерируем случайный IV, шифруем DEK в режиме CTR
 * мастер-ключом. Для разворачивания: берём IV из первых 16 байт,
 * расшифровываем оставшиеся 32 байта.
 * ===================================================================== */

/*
 * Обёртывание DEK: шифрование мастер-ключом для хранения на диске.
 * wrapped — буфер WRAPPED_DEK_SIZE (48 байт): [IV][encrypted_DEK].
 */
void
opentde_wrap_dek(const uint8_t *master_key, const uint8_t *dek,
                 uint8_t *wrapped)
{
    uint8_t iv[DATA_IV_SIZE];

    opentde_fill_random_bytes(iv, DATA_IV_SIZE, "DEK wrapping IV");
    memcpy(wrapped, iv, DATA_IV_SIZE);
    memcpy(wrapped + DATA_IV_SIZE, dek, DEK_SIZE);
    kuz_ctr_crypt(master_key, iv, wrapped + DATA_IV_SIZE, DEK_SIZE);
}

/*
 * Разворачивание DEK: расшифровка из файла на диске.
 * Извлекает IV из первых 16 байт wrapped_dek, затем
 * расшифровывает оставшиеся 32 байт.
 */
bool
opentde_unwrap_dek(const uint8_t *master_key, const uint8_t *wrapped_dek,
                   uint8_t *dek)
{
    uint8_t iv[DATA_IV_SIZE];

    memcpy(iv, wrapped_dek, DATA_IV_SIZE);
    memcpy(dek, wrapped_dek + DATA_IV_SIZE, DEK_SIZE);
    kuz_ctr_crypt(master_key, iv, dek, DEK_SIZE);
    return true;
}

/* =====================================================================
 * Управление DEK таблиц
 * ===================================================================== */

/*
 * Получение DEK для таблицы по её OID.
 *
 * Если DEK уже существует в менеджере ключей — возвращает копию.
 * Если нет — генерирует новый случайный DEK, оборачивает мастер-ключом,
 * сохраняет в менеджер и на диск, возвращает копию.
 *
 * Возвращённый указатель должен быть освобождён вызывающей стороной (pfree).
 */
uint8_t *
opentde_get_table_dek(Oid table_oid)
{
    uint8_t  temp_dek[DEK_SIZE];
    uint8_t *result_dek;
    int      idx;
    int      i;

    if (!master_key_set || !global_key_mgr)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("master key not set")));
    }

    /* Поиск существующего DEK для таблицы */
    for (idx = 0; idx < global_key_mgr->key_count; idx++)
    {
        if (global_key_mgr->keys[idx].table_oid == table_oid)
        {
            result_dek = palloc(DEK_SIZE);
            memcpy(result_dek, global_key_mgr->keys[idx].dek, DEK_SIZE);
            return result_dek;
        }
    }

    /* DEK не найден — создаём новый */
    elog(LOG, "[OpenTDE] Creating DEK for table %u", table_oid);

    /* Расширение массива ключей при необходимости */
    if (global_key_mgr->key_count >= global_key_mgr->key_capacity)
    {
        global_key_mgr->key_capacity *= 2;
        global_key_mgr->keys = repalloc(
            global_key_mgr->keys,
            global_key_mgr->key_capacity * sizeof(opentde_key_entry));
    }

    idx = global_key_mgr->key_count;
    global_key_mgr->keys[idx].table_oid = table_oid;

    /* Генерация случайного 256-битного DEK */
    opentde_fill_random_bytes(temp_dek, DEK_SIZE, "table DEK");

    memcpy(global_key_mgr->keys[idx].dek, temp_dek, DEK_SIZE);
    for (i = 0; i < WRAPPED_DEK_SIZE; i++)
        global_key_mgr->keys[idx].wrapped_dek[i] = 0;

    /* Обёртывание DEK мастер-ключом для хранения на диске */
    opentde_wrap_dek(global_key_mgr->master_key,
                     temp_dek,
                     global_key_mgr->keys[idx].wrapped_dek);

    global_key_mgr->key_count++;
    opentde_save_key_file();

    result_dek = palloc(DEK_SIZE);
    memcpy(result_dek, temp_dek, DEK_SIZE);
    return result_dek;
}

/* =====================================================================
 * Шифрование / дешифрование данных
 * ===================================================================== */

/*
 * Шифрование (или дешифрование) блока данных шифром «Кузнечик» в режиме CTR.
 * Операция симметрична: повторное применение расшифровывает данные.
 *
 * data      — указатель на данные (шифруются in-place)
 * len       — длина данных в байтах
 * table_oid — OID таблицы (для получения правильного DEK)
 * iv        — вектор инициализации (128 бит)
 */
void
opentde_gost_encrypt_decrypt(char *data, int len, Oid table_oid,
                             const uint8_t *iv)
{
    uint8_t *table_key;

    if (len <= 0)
        return;

    table_key = opentde_get_table_dek(table_oid);
    kuz_ctr_crypt(table_key, iv, (uint8_t *) data, (size_t) len);
    pfree(table_key);
}

/* =====================================================================
 * Шифрование кортежа в памяти (перед записью в heap)
 * ===================================================================== */

/*
 * Шифрование payload кортежа в памяти (in-place).
 *
 * Генерирует случайный 128-битный IV и шифрует всё после t_hoff
 * шифром «Кузнечик» CTR.  Кортеж модифицируется на месте — вызывающая
 * сторона должна передать записываемую (writable) копию.
 *
 * ВАЖНО: вызывается ДО heap_insert / heap_update / heap_multi_insert,
 * чтобы в WAL-журнал попадали уже зашифрованные данные.
 *
 * iv_out — выходной буфер для IV (DATA_IV_SIZE байт).
 * Возвращает длину зашифрованного payload (0 если нечего шифровать).
 */
int
opentde_encrypt_tuple_inplace(HeapTuple tuple, Oid table_oid,
                              uint8_t *iv_out)
{
    char *payload;
    int   payload_len;

    payload     = (char *) tuple->t_data + tuple->t_data->t_hoff;
    payload_len = tuple->t_len - tuple->t_data->t_hoff;

    if (payload_len <= 0)
        return 0;

    opentde_fill_random_bytes(iv_out, DATA_IV_SIZE, "tuple payload IV");
    opentde_gost_encrypt_decrypt(payload, payload_len, table_oid, iv_out);

    return payload_len;
}
