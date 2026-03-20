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

/* Увеличивает массив ключей при необходимости. */
static void
opentde_ensure_key_array_capacity(void)
{
    if (global_key_mgr->key_count >= global_key_mgr->key_capacity)
    {
        global_key_mgr->key_capacity *= 2;
        global_key_mgr->keys = repalloc(
            global_key_mgr->keys,
            global_key_mgr->key_capacity * sizeof(opentde_key_entry));
    }
}

/* Ищет запись DEK по (table_oid, key_version). */
static int
opentde_find_table_key_index(Oid table_oid, uint32_t key_version)
{
    int i;

    for (i = 0; i < global_key_mgr->key_count; i++)
    {
        opentde_key_entry *entry = &global_key_mgr->keys[i];

        if (entry->table_oid == table_oid && entry->key_version == key_version)
            return i;
    }

    return -1;
}

/* Ищет активный DEK для таблицы; если активный флаг потерян, активирует max(version). */
static int
opentde_find_active_table_key_index(Oid table_oid)
{
    int      i;
    int      active_idx = -1;
    int      fallback_idx = -1;
    uint32_t active_max_version = 0;
    uint32_t fallback_max_version = 0;

    for (i = 0; i < global_key_mgr->key_count; i++)
    {
        opentde_key_entry *entry = &global_key_mgr->keys[i];

        if (entry->table_oid != table_oid)
            continue;

        if (entry->key_version >= fallback_max_version)
        {
            fallback_max_version = entry->key_version;
            fallback_idx = i;
        }

        if (entry->is_active && entry->key_version >= active_max_version)
        {
            active_max_version = entry->key_version;
            active_idx = i;
        }
    }

    if (active_idx >= 0)
        return active_idx;

    if (fallback_idx >= 0)
    {
        global_key_mgr->keys[fallback_idx].is_active = true;
        return fallback_idx;
    }

    return -1;
}

/* Создаёт начальный DEK (версия 1) для таблицы. */
static int
opentde_create_initial_table_key(Oid table_oid)
{
    uint8_t temp_dek[DEK_SIZE];
    int     idx;

    opentde_ensure_key_array_capacity();

    idx = global_key_mgr->key_count;
    global_key_mgr->keys[idx].table_oid = table_oid;
    global_key_mgr->keys[idx].key_version = DEFAULT_DEK_VERSION;
    global_key_mgr->keys[idx].is_active = true;

    opentde_fill_random_bytes(temp_dek, DEK_SIZE, "table DEK");
    memcpy(global_key_mgr->keys[idx].dek, temp_dek, DEK_SIZE);
    memset(global_key_mgr->keys[idx].wrapped_dek, 0, WRAPPED_DEK_SIZE);

    opentde_wrap_dek(global_key_mgr->master_key,
                     temp_dek,
                     global_key_mgr->keys[idx].wrapped_dek);

    global_key_mgr->key_count++;
    opentde_save_key_file();

    return idx;
}

/* Возвращает активную версию DEK для таблицы, создавая DEK при первом обращении. */
uint32_t
opentde_get_active_table_key_version(Oid table_oid)
{
    int idx;

    if (!master_key_set || !global_key_mgr)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("master key not set")));
    }

    idx = opentde_find_active_table_key_index(table_oid);
    if (idx < 0)
    {
        elog(LOG, "[OpenTDE] Creating initial DEK for table %u", table_oid);
        idx = opentde_create_initial_table_key(table_oid);
    }

    return global_key_mgr->keys[idx].key_version;
}

/* Возвращает копию DEK указанной версии для таблицы. */
uint8_t *
opentde_get_table_dek_by_version(Oid table_oid, uint32_t key_version)
{
    uint8_t *result_dek;
    int      idx;

    if (!master_key_set || !global_key_mgr)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("master key not set")));
    }

    idx = opentde_find_table_key_index(table_oid, key_version);
    if (idx < 0)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("DEK version %u not found for table %u",
                        key_version, table_oid)));
    }

    result_dek = palloc(DEK_SIZE);
    memcpy(result_dek, global_key_mgr->keys[idx].dek, DEK_SIZE);
    return result_dek;
}

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
    uint32_t key_version;

    key_version = opentde_get_active_table_key_version(table_oid);
    return opentde_get_table_dek_by_version(table_oid, key_version);
}

/*
 * Ротация DEK таблицы.
 *
 * Создаёт новую активную версию DEK для table_oid.
 * Старые версии остаются в key-ring и используются для чтения старых строк.
 */
uint32_t
opentde_rotate_table_dek(Oid table_oid)
{
    uint8_t  new_dek[DEK_SIZE];
    uint32_t max_version = 0;
    uint32_t new_version;
    int      i;
    int      idx;

    if (!master_key_set || !global_key_mgr)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("master key not set")));
    }

    /* Гарантируем наличие хотя бы одной версии DEK. */
    (void) opentde_get_active_table_key_version(table_oid);

    /* Деактивируем текущие ключи таблицы и ищем максимальную версию. */
    for (i = 0; i < global_key_mgr->key_count; i++)
    {
        opentde_key_entry *entry = &global_key_mgr->keys[i];

        if (entry->table_oid != table_oid)
            continue;

        entry->is_active = false;
        if (entry->key_version > max_version)
            max_version = entry->key_version;
    }

    new_version = max_version + 1;

    opentde_ensure_key_array_capacity();
    idx = global_key_mgr->key_count;

    global_key_mgr->keys[idx].table_oid = table_oid;
    global_key_mgr->keys[idx].key_version = new_version;
    global_key_mgr->keys[idx].is_active = true;

    opentde_fill_random_bytes(new_dek, DEK_SIZE, "rotated table DEK");
    memcpy(global_key_mgr->keys[idx].dek, new_dek, DEK_SIZE);
    memset(global_key_mgr->keys[idx].wrapped_dek, 0, WRAPPED_DEK_SIZE);

    opentde_wrap_dek(global_key_mgr->master_key,
                     new_dek,
                     global_key_mgr->keys[idx].wrapped_dek);

    global_key_mgr->key_count++;
    opentde_save_key_file();

    elog(LOG,
         "[OpenTDE] Rotated DEK for table %u: new version %u",
         table_oid, new_version);

    return new_version;
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
 * key_version — версия DEK (0 = активная версия таблицы)
 * iv        — вектор инициализации (128 бит)
 */
void
opentde_gost_encrypt_decrypt(char *data, int len, Oid table_oid,
                             uint32_t key_version, const uint8_t *iv)
{
    uint8_t *table_key;

    if (len <= 0)
        return;

    if (key_version == 0)
        key_version = opentde_get_active_table_key_version(table_oid);

    table_key = opentde_get_table_dek_by_version(table_oid, key_version);
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
 * key_version_out — версия DEK, которой зашифрован кортеж.
 * Возвращает длину зашифрованного payload (0 если нечего шифровать).
 */
int
opentde_encrypt_tuple_inplace(HeapTuple tuple, Oid table_oid,
                              uint8_t *iv_out,
                              uint32_t *key_version_out)
{
    char     *payload;
    int       payload_len;
    uint32_t  key_version;

    payload     = (char *) tuple->t_data + tuple->t_data->t_hoff;
    payload_len = tuple->t_len - tuple->t_data->t_hoff;

    if (payload_len <= 0)
    {
        if (key_version_out)
            *key_version_out = 0;
        return 0;
    }

    key_version = opentde_get_active_table_key_version(table_oid);

    opentde_fill_random_bytes(iv_out, DATA_IV_SIZE, "tuple payload IV");
    opentde_gost_encrypt_decrypt(payload, payload_len, table_oid, key_version, iv_out);

    if (key_version_out)
        *key_version_out = key_version;

    return payload_len;
}
