#include "opentde.h"
#include "port.h"
#include <string.h>

/*
 * Генерация криптографически стойких случайных байт.
 * Использует pg_strong_random() из PostgreSQL (обёртка над /dev/urandom)
 *
 */
void
opentde_fill_random_bytes(uint8_t *buf, size_t len, const char *context_name)
{
    if (!pg_strong_random(buf, len))
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("failed to generate random bytes for %s",
                        context_name)));
}

/*
 * Шифруем DEK
 * На диске лежит как [IV][encrypted_DEK]
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
 * Дешифруем DEK
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

static int opentde_find_active_table_key_index(Oid table_oid);

bool
opentde_storage_key_exists(Oid storage_oid)
{
    int i;

    opentde_ensure_keys_loaded();
    if (!global_key_mgr)
        return false;

    for (i = 0; i < global_key_mgr->key_count; i++)
    {
        if (global_key_mgr->keys[i].table_oid == storage_oid)
            return true;
    }

    return false;
}

void
opentde_copy_active_storage_key(Oid source_storage_oid, Oid target_storage_oid)
{
    int source_idx;
    int target_idx;

    if (!OidIsValid(source_storage_oid) ||
        !OidIsValid(target_storage_oid) ||
        source_storage_oid == target_storage_oid)
        return;

    opentde_ensure_keys_loaded();
    if (!master_key_set || !global_key_mgr)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("master key not set")));
    }

    target_idx = opentde_find_active_table_key_index(target_storage_oid);
    if (target_idx >= 0)
        return;

    source_idx = opentde_find_active_table_key_index(source_storage_oid);
    if (source_idx < 0)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("active DEK not found for source storage %u",
                        source_storage_oid)));
    }

    opentde_ensure_key_array_capacity();
    target_idx = global_key_mgr->key_count;

    global_key_mgr->keys[target_idx].table_oid = target_storage_oid;
    global_key_mgr->keys[target_idx].key_version =
        global_key_mgr->keys[source_idx].key_version;
    global_key_mgr->keys[target_idx].is_active = true;

    memcpy(global_key_mgr->keys[target_idx].dek,
           global_key_mgr->keys[source_idx].dek,
           DEK_SIZE);
    memset(global_key_mgr->keys[target_idx].wrapped_dek, 0, WRAPPED_DEK_SIZE);

    opentde_wrap_dek(global_key_mgr->master_key,
                     global_key_mgr->keys[target_idx].dek,
                     global_key_mgr->keys[target_idx].wrapped_dek);

    global_key_mgr->key_count++;
    opentde_save_key_file();
}

/* Возвращает прямой указатель на DEK указанной версии без лишних аллокаций. */

static const uint8_t *
opentde_get_table_dek_ptr_by_version(Oid table_oid, uint32_t key_version)
{
    static Oid      cached_table_oid = InvalidOid;
    static uint32_t cached_key_version = 0;
    static int      cached_idx = -1;
    static int      cached_key_count = -1;
    int idx;

    opentde_ensure_keys_loaded();
    if (!master_key_set || !global_key_mgr)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("master key not set")));
    }

    if (cached_idx >= 0 &&
        cached_key_count == global_key_mgr->key_count &&
        cached_idx < global_key_mgr->key_count)
    {
        opentde_key_entry *cached = &global_key_mgr->keys[cached_idx];

        if (cached_table_oid == table_oid &&
            cached_key_version == key_version &&
            cached->table_oid == table_oid &&
            cached->key_version == key_version)
            return cached->dek;
    }

    idx = opentde_find_table_key_index(table_oid, key_version);
    if (idx < 0)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("DEK version %u not found for table %u",
                        key_version, table_oid)));
    }

    cached_table_oid = table_oid;
    cached_key_version = key_version;
    cached_idx = idx;
    cached_key_count = global_key_mgr->key_count;

    return global_key_mgr->keys[idx].dek;
}

/*
 * Кэширует expanded key schedule Кузнечика для активного (table_oid, key_version).
 * Это убирает дорогое kuz_set_key() на каждый кортеж в Seq Scan.
 */
static const kuz_key_t *
opentde_get_cached_kuz_ctx(Oid table_oid, uint32_t key_version, const uint8_t *table_key)
{
    static bool      cache_valid = false;
    static Oid       cached_table_oid = InvalidOid;
    static uint32_t  cached_key_version = 0;
    static uint8_t   cached_raw_key[DEK_SIZE];
    static kuz_key_t cached_ctx;

    if (cache_valid &&
        cached_table_oid == table_oid &&
        cached_key_version == key_version &&
        memcmp(cached_raw_key, table_key, DEK_SIZE) == 0)
        return &cached_ctx;

    kuz_set_key(&cached_ctx, table_key);
    memcpy(cached_raw_key, table_key, DEK_SIZE);
    cached_table_oid = table_oid;
    cached_key_version = key_version;
    cache_valid = true;

    return &cached_ctx;
}

/* Ищет активный DEK для таблицы; если активный флаг потерян, активирует max(version) */
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

    opentde_ensure_keys_loaded();
    if (!master_key_set || !global_key_mgr)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("master key not set")));
    }

    idx = opentde_find_active_table_key_index(table_oid);
    if (idx < 0)
    {
        elog(DEBUG1, "[OpenTDE] Creating initial DEK for table %u", table_oid);
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

    opentde_ensure_keys_loaded();
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
 * Получение DEK для таблицы по её OID
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


    opentde_ensure_keys_loaded();
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

    elog(DEBUG1,
         "[OpenTDE] Rotated DEK for table %u: new version %u",
         table_oid, new_version);

    return new_version;
}

/*
 * Шифрование (или дешифрование) блока данных шифром «Кузнечик» в режиме CTR.
 * Операция симметрична
 *
 * data      — указатель на данные (шифруются in-place)
 * len       — длина данных в байтах
 * table_oid — OID таблицы
 * key_version — версия DEK
 * iv        — вектор инициализации
 */
void
opentde_gost_encrypt_decrypt(char *data, int len, Oid table_oid,
                             uint32_t key_version, const uint8_t *iv)
{
    const uint8_t *table_key;
    const kuz_key_t *kuz_ctx;

    if (len <= 0)
        return;

    if (key_version == 0)
        key_version = opentde_get_active_table_key_version(table_oid);

    table_key = opentde_get_table_dek_ptr_by_version(table_oid, key_version);
    kuz_ctx = opentde_get_cached_kuz_ctx(table_oid, key_version, table_key);
    kuz_ctr_crypt_ctx(kuz_ctx, iv, (uint8_t *) data, (size_t) len);
}

