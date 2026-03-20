/*
 * opentde_sql.c — SQL-функции расширения OpenTDE.
 *
 * Содержит функции, вызываемые пользователем через SQL:
 *
 *   opentde_set_master_key(bytea) — установка мастер-ключа шифрования
 *   opentde_rotate_master_key(bytea) — ротация мастер-ключа (rewrap DEK)
 *   opentde_rotate_table_dek(oid) — ротация DEK конкретной таблицы
 *   opentde_debug_keys()          — вывод всех DEK (для отладки)
 *   opentde_get_dek_hex(oid)      — получение DEK таблицы в HEX
 *   opentde_blind_index(text)     — слепой индекс (HMAC-SHA256)
 *
 * Все функции зарегистрированы в opentde--1.0.sql через CREATE FUNCTION.
 */
#include "opentde.h"

#include <openssl/hmac.h>   /* HMAC, EVP_sha256 */
#include <string.h>

/* Регистрация SQL-функций в PostgreSQL */
PG_FUNCTION_INFO_V1(opentde_set_master_key);
PG_FUNCTION_INFO_V1(opentde_rotate_master_key);
PG_FUNCTION_INFO_V1(opentde_rotate_table_dek_sql);
PG_FUNCTION_INFO_V1(opentde_debug_keys);
PG_FUNCTION_INFO_V1(opentde_get_dek_hex);
PG_FUNCTION_INFO_V1(opentde_blind_index);

/* =====================================================================
 * opentde_set_master_key(bytea) → void
 *
 * Устанавливает мастер-ключ шифрования (256 бит = 32 байта).
 * Мастер-ключ используется для обёртывания/разворачивания DEK таблиц.
 *
 * После установки:
 *   - Сохраняет ключ в файл pg_encryption/master.key
 *   - Загружает ранее сохранённые DEK из pg_encryption/keys
 *   - Загружает IV из pg_encryption/ivs
 *
 * Пример вызова:
 *   SELECT opentde_set_master_key('\x0102030405...'::bytea);
 * ===================================================================== */
Datum
opentde_set_master_key(PG_FUNCTION_ARGS)
{
    bytea *key_data;
    uint8_t *new_key;
    int    key_len;

    key_data = PG_GETARG_BYTEA_P(0);
    key_len  = VARSIZE_ANY_EXHDR(key_data);
    new_key  = (uint8_t *) VARDATA_ANY(key_data);

    /* Проверка длины: ровно 32 байта (256 бит) */
    if (key_len != MASTER_KEY_SIZE)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("master key must be exactly %d bytes",
                        MASTER_KEY_SIZE)));
    }

    opentde_init_key_manager();

    memcpy(global_key_mgr->master_key, new_key, MASTER_KEY_SIZE);
    master_key_set = true;

    /* Сохранение ключа и загрузка существующих DEK/IV */
    opentde_save_master_key_to_file();
    opentde_load_key_file();
    opentde_load_iv_file();

    elog(INFO,
         "[OpenTDE] Master key set and %d keys loaded+decrypted",
         global_key_mgr->key_count);
    PG_RETURN_VOID();
}

/* =====================================================================
 * opentde_rotate_master_key(bytea) → int4
 *
 * Быстрая ротация мастер-ключа без перешифрования пользовательских данных.
 *
 * Что делает:
 *   1) проверяет новый ключ (32 байта)
 *   2) загружает DEK в память (если ещё не загружены)
 *   3) заменяет мастер-ключ в памяти
 *   4) заново оборачивает все DEK новым мастер-ключом и сохраняет keys
 *   5) сохраняет новый мастер-ключ в pg_encryption/master.key
 *
 * Возвращает количество переобёрнутых DEK.
 * ===================================================================== */
Datum
opentde_rotate_master_key(PG_FUNCTION_ARGS)
{
    bytea    *key_data;
    uint8_t  *new_key;
    int       key_len;

    key_data = PG_GETARG_BYTEA_P(0);
    key_len  = VARSIZE_ANY_EXHDR(key_data);
    new_key  = (uint8_t *) VARDATA_ANY(key_data);

    if (key_len != MASTER_KEY_SIZE)
    {
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("master key must be exactly %d bytes", MASTER_KEY_SIZE)));
    }

    opentde_init_key_manager();

    if (!master_key_set)
    {
        ereport(ERROR,
                (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                 errmsg("master key is not set"),
                 errhint("Call opentde_set_master_key() first.")));
    }

    if (global_key_mgr->key_count == 0)
        opentde_load_key_file();

    if (memcmp(global_key_mgr->master_key, new_key, MASTER_KEY_SIZE) == 0)
        PG_RETURN_INT32(global_key_mgr->key_count);

    memcpy(global_key_mgr->master_key, new_key, MASTER_KEY_SIZE);

    /* Быстрая ротация: re-wrap DEK новым мастер-ключом. */
    opentde_save_key_file();
    opentde_save_master_key_to_file();

    ereport(WARNING,
            (errmsg("blind index values depend on master key"),
             errhint("Rebuild indexes created with opentde_blind_index() after rotation.")));

    PG_RETURN_INT32(global_key_mgr->key_count);
}

/* =====================================================================
 * opentde_rotate_table_dek(oid) → int4
 *
 * Создаёт новую активную версию DEK для указанной таблицы.
 * Старые версии остаются для чтения ранее зашифрованных строк.
 *
 * Возвращает новую версию DEK.
 * ===================================================================== */
Datum
opentde_rotate_table_dek_sql(PG_FUNCTION_ARGS)
{
    Oid      table_oid;
    uint32_t new_version;

    table_oid = PG_GETARG_OID(0);

    opentde_init_key_manager();

    if (!master_key_set)
    {
        ereport(ERROR,
                (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                 errmsg("master key is not set"),
                 errhint("Call opentde_set_master_key() first.")));
    }

    if (global_key_mgr->key_count == 0)
        opentde_load_key_file();

    new_version = opentde_rotate_table_dek(table_oid);
    PG_RETURN_INT32((int32) new_version);
}

/* =====================================================================
 * opentde_debug_keys() → text
 *
 * Возвращает текстовое представление всех DEK в памяти.
 * Используется для отладки — выводит OID таблицы и DEK в HEX.
 *
 * ВНИМАНИЕ: выводит открытые ключи! Использовать только для отладки.
 * ===================================================================== */
Datum
opentde_debug_keys(PG_FUNCTION_ARGS)
{
    StringInfoData buf;
    int i;
    int j;

    initStringInfo(&buf);

    if (!master_key_set || !global_key_mgr)
    {
        appendStringInfoString(&buf, "Master key not set");
        PG_RETURN_TEXT_P(cstring_to_text(buf.data));
    }

    appendStringInfo(&buf, "=== OpenTDE Key Debug ===\n");
    appendStringInfo(&buf, "Total keys: %d\n\n", global_key_mgr->key_count);

    for (i = 0; i < global_key_mgr->key_count; i++)
    {
        opentde_key_entry *key = &global_key_mgr->keys[i];

        appendStringInfo(&buf, "Key[%d] oid=%u:\n", i, key->table_oid);
        appendStringInfoString(&buf, "  DEK: ");
        for (j = 0; j < DEK_SIZE; j++)
            appendStringInfo(&buf, "%02x", key->dek[j]);

        appendStringInfoChar(&buf, '\n');
    }

    PG_RETURN_TEXT_P(cstring_to_text(buf.data));
}

/* =====================================================================
 * opentde_get_dek_hex(oid) → text
 *
 * Возвращает DEK указанной таблицы в виде HEX-строки.
 * Если DEK для таблицы не существует — создаёт новый.
 *
 * Пример: SELECT opentde_get_dek_hex('my_table'::regclass);
 * ===================================================================== */
Datum
opentde_get_dek_hex(PG_FUNCTION_ARGS)
{
    Oid              table_oid;
    uint8_t         *dek;
    StringInfoData   buf;
    int              i;

    table_oid = PG_GETARG_OID(0);
    dek = opentde_get_table_dek(table_oid);

    initStringInfo(&buf);
    for (i = 0; i < DEK_SIZE; i++)
        appendStringInfo(&buf, "%02x", dek[i]);

    pfree(dek);
    PG_RETURN_TEXT_P(cstring_to_text(buf.data));
}

/* =====================================================================
 * opentde_blind_index(text) → bytea
 *
 * Слепой индекс: вычисляет HMAC-SHA256 от входного значения,
 * используя мастер-ключ как секрет.
 *
 * Назначение: позволяет строить B-tree индексы по зашифрованным данным.
 * В индексных файлах хранятся только HMAC-дайджесты (32 байта),
 * а не открытые значения. Поддерживает только equality-запросы (=).
 * Range-запросы (<, >, BETWEEN) невозможны, т.к. HMAC не сохраняет порядок.
 *
 * Пример использования:
 *   CREATE INDEX ON t (opentde_blind_index(s));
 *   SELECT * FROM t WHERE opentde_blind_index(s) = opentde_blind_index('hello');
 *
 * Безопасность:
 *   - Без знания мастер-ключа невозможно восстановить исходное значение
 *   - Одинаковые входные значения дают одинаковый HMAC (детерминистично)
 *   - Используется HMAC-SHA256 из OpenSSL
 * ===================================================================== */
Datum
opentde_blind_index(PG_FUNCTION_ARGS)
{
    text          *input;
    char          *input_data;
    int            input_len;
    unsigned char  hmac_result[32];
    unsigned int   hmac_len;
    bytea         *result;

    /* Проверка: мастер-ключ должен быть установлен */
    if (!master_key_set)
        ereport(ERROR,
                (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                 errmsg("master key is not set"),
                 errhint("Call opentde_set_master_key() first.")));

    input      = PG_GETARG_TEXT_PP(0);
    input_data = VARDATA_ANY(input);
    input_len  = VARSIZE_ANY_EXHDR(input);

    /* Вычисление HMAC-SHA256(master_key, input_value) */
    HMAC(EVP_sha256(),
         global_key_mgr->master_key, MASTER_KEY_SIZE,
         (unsigned char *) input_data, input_len,
         hmac_result, &hmac_len);

    /* Упаковка результата в bytea */
    result = (bytea *) palloc(VARHDRSZ + hmac_len);
    SET_VARSIZE(result, VARHDRSZ + hmac_len);
    memcpy(VARDATA(result), hmac_result, hmac_len);

    PG_RETURN_BYTEA_P(result);
}
