/*
 * opentde_crypto.c — Криптографический модуль OpenTDE.
 *
 * Отвечает за:
 *   - Генерацию криптографически стойких случайных чисел
 *   - Обёртывание (wrap) и разворачивание (unwrap) DEK мастер-ключом
 *   - Получение или создание DEK для конкретной таблицы
 *   - Шифрование/дешифрование данных шифром «Кузнечик» (ГОСТ Р 34.12-2015)
 *     в режиме CTR (гаммирование)
 *   - Шифрование payload кортежа непосредственно в буферной странице
 *
 * Схема шифрования:
 *   1. Для каждого кортежа генерируется случайный 128-битный IV
 *   2. DEK таблицы используется как ключ шифра «Кузнечик»
 *   3. Шифрование выполняется в режиме CTR: XOR открытого текста с гаммой
 *   4. Дешифрование — повторное применение той же операции (CTR симметричен)
 */
#include "opentde.h"

#include "access/generic_xlog.h"   /* GenericXLogState */
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
 * Шифрование кортежа в буферной странице
 * ===================================================================== */

/*
 * Шифрование payload кортежа, только что записанного в heap-буфер.
 *
 * Алгоритм:
 *   1. Читает буферную страницу, содержащую кортеж (по TID)
 *   2. Блокирует страницу эксклюзивно (BUFFER_LOCK_EXCLUSIVE)
 *   3. Находит кортеж по смещению (OffsetNumber)
 *   4. Генерирует случайный IV (128 бит)
 *   5. Шифрует payload (всё после t_hoff) шифром «Кузнечик» CTR
 *   6. Фиксирует изменения через GenericXLog (для WAL-записи)
 *   7. Освобождает буфер
 *
 * row_iv_out — выходной буфер для сгенерированного IV (DATA_IV_SIZE байт).
 * Возвращает длину зашифрованного payload (0 если нечего шифровать).
 *
 * ВАЖНО: должна вызываться сразу после heap_insert/heap_update,
 * пока страница ещё в shared_buffers и не видна другим бэкендам.
 */
int
opentde_encrypt_in_buffer(Relation relation, Oid table_oid,
                          const ItemPointer tid, uint8_t *row_iv_out)
{
    Buffer              buf;
    Page                page;
    OffsetNumber        offnum;
    ItemId              itemid;
    HeapTupleHeader     htup;
    char               *payload;
    int                 payload_len;
    GenericXLogState   *xlog_state;

    offnum = ItemPointerGetOffsetNumber(tid);
    buf    = ReadBuffer(relation, ItemPointerGetBlockNumber(tid));
    LockBuffer(buf, BUFFER_LOCK_EXCLUSIVE);

    /* Регистрация буфера для WAL-журнала через GenericXLog */
    xlog_state = GenericXLogStart(relation);
    page       = GenericXLogRegisterBuffer(xlog_state, buf, 0);

    /* Нахождение кортежа на странице по смещению */
    itemid      = PageGetItemId(page, offnum);
    htup        = (HeapTupleHeader) PageGetItem(page, itemid);
    payload_len = (int) ItemIdGetLength(itemid) - htup->t_hoff;
    payload     = (char *) htup + htup->t_hoff;

    if (payload_len > 0)
    {
        elog(LOG, "[OpenTDE] ENC tid=(%u,%u) hoff=%u ilen=%u plain[0..3]=[%02x %02x %02x %02x]",
             (unsigned) ItemPointerGetBlockNumber(tid),
             (unsigned) ItemPointerGetOffsetNumber(tid),
             (unsigned) htup->t_hoff,
             (unsigned) ItemIdGetLength(itemid),
             (unsigned char) payload[0], (unsigned char) payload[1],
             (unsigned char) payload[2], (unsigned char) payload[3]);

        /* Генерация случайного IV и шифрование payload */
        opentde_fill_random_bytes(row_iv_out, DATA_IV_SIZE,
                                  "tuple payload IV");
        opentde_gost_encrypt_decrypt(payload, payload_len, table_oid,
                                     row_iv_out);

        elog(LOG, "[OpenTDE] ENC tid=(%u,%u) ciph[0..3]=[%02x %02x %02x %02x]",
             (unsigned) ItemPointerGetBlockNumber(tid),
             (unsigned) ItemPointerGetOffsetNumber(tid),
             (unsigned char) payload[0], (unsigned char) payload[1],
             (unsigned char) payload[2], (unsigned char) payload[3]);

        GenericXLogFinish(xlog_state);
    }
    else
    {
        GenericXLogAbort(xlog_state);
    }

    UnlockReleaseBuffer(buf);
    return payload_len;
}
