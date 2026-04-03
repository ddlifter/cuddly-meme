#include "postgres.h"
#include "fmgr.h"

PG_FUNCTION_INFO_V1(opentde_page_crypto_selftest);

Datum
opentde_page_crypto_selftest(PG_FUNCTION_ARGS)
{
    PG_RETURN_VOID();
}
#include "opentde.h"
#include "postgres.h"
#include <stdbool.h>
#include <stdio.h>
#include "access/genam.h"
#include "access/table.h"
#include "catalog/namespace.h"
#include "catalog/pg_class.h"
#include "catalog/pg_type_d.h"
#include "commands/defrem.h"
#include "nodes/parsenodes.h"
#include "tcop/utility.h"
#include "utils/array.h"
#include "utils/lsyscache.h"
#include "utils/relcache.h"
#include <openssl/hmac.h>
#include <string.h>

PG_FUNCTION_INFO_V1(opentde_set_master_key);
PG_FUNCTION_INFO_V1(opentde_enable_table_encryption);
PG_FUNCTION_INFO_V1(opentde_disable_table_encryption);
PG_FUNCTION_INFO_V1(opentde_rotate_master_key);
PG_FUNCTION_INFO_V1(opentde_rotate_table_dek_sql);
PG_FUNCTION_INFO_V1(opentde_debug_keys);
PG_FUNCTION_INFO_V1(opentde_get_dek_hex);
PG_FUNCTION_INFO_V1(opentde_blind_index);
PG_FUNCTION_INFO_V1(opentde_blind_bucket_int4);
PG_FUNCTION_INFO_V1(opentde_blind_bucket_int8);
PG_FUNCTION_INFO_V1(opentde_blind_bucket_tokens_int8);

#define OPENTDE_MAX_BUCKET_TOKEN_COUNT 65536

static ProcessUtility_hook_type prev_ProcessUtility_hook = NULL;
static bool opentde_utility_hook_installed = false;
Oid opentde_pending_index_parent_storage_oid = InvalidOid;
Oid opentde_pending_index_child_storage_oid = InvalidOid;

static bool
opentde_has_key_for_storage_oid(Oid storage_oid)
{
    int i;

    if (!master_key_set || !global_key_mgr)
        return false;

    for (i = 0; i < global_key_mgr->key_count; i++)
    {
        if (global_key_mgr->keys[i].table_oid == storage_oid)
            return true;
    }

    return false;
}

static Oid
opentde_relation_storage_oid_locked(Oid relation_oid, LOCKMODE lockmode)
{
    char     relkind;
    Relation rel;
    Oid      storage_oid;

    relkind = get_rel_relkind(relation_oid);
    if (relkind == RELKIND_INDEX)
    {
        rel = index_open(relation_oid, lockmode);
        storage_oid = rel->rd_locator.relNumber;
        index_close(rel, lockmode);
    }
    else
    {
        rel = table_open(relation_oid, lockmode);
        storage_oid = rel->rd_locator.relNumber;
        table_close(rel, lockmode);
    }

    return storage_oid;
}

static Oid
opentde_relation_storage_oid(Oid relation_oid)
{
    return opentde_relation_storage_oid_locked(relation_oid, AccessShareLock);
}

static void
opentde_enable_relation_storage_key(Oid relation_oid)
{
    Oid storage_oid;

    storage_oid = opentde_relation_storage_oid(relation_oid);
    if (opentde_storage_key_exists(storage_oid))
        return;

    (void) opentde_get_active_table_key_version(storage_oid);
}

static void
opentde_disable_relation_storage_key(Oid relation_oid)
{
    Oid storage_oid;

    storage_oid = opentde_relation_storage_oid(relation_oid);
    opentde_forget_table_keys(storage_oid);
}

static bool
opentde_is_relation_encrypted(Oid relation_oid)
{
    Oid storage_oid;

    storage_oid = opentde_relation_storage_oid(relation_oid);
    return opentde_has_key_for_storage_oid(storage_oid);
}

static void
opentde_enable_table_family_encryption(Oid table_oid)
{
    Relation rel;
    List    *index_list;
    ListCell *lc;

    rel = table_open(table_oid, AccessShareLock);

    if (rel->rd_rel->relkind != RELKIND_RELATION &&
        rel->rd_rel->relkind != RELKIND_MATVIEW)
    {
        table_close(rel, AccessShareLock);
        ereport(ERROR,
                (errcode(ERRCODE_WRONG_OBJECT_TYPE),
                 errmsg("relation %u is not a plain table", table_oid)));
    }

    (void) opentde_get_active_table_key_version(rel->rd_locator.relNumber);

    if (OidIsValid(rel->rd_rel->reltoastrelid))
        opentde_enable_relation_storage_key(rel->rd_rel->reltoastrelid);

    index_list = RelationGetIndexList(rel);
    foreach(lc, index_list)
    {
        Oid index_oid = lfirst_oid(lc);
        Oid index_storage_oid;

        index_storage_oid = opentde_relation_storage_oid(index_oid);
        if (!opentde_storage_key_exists(index_storage_oid))
        {
            opentde_copy_active_storage_key(rel->rd_locator.relNumber,
                                            index_storage_oid);
            opentde_reencrypt_relation_storage(index_oid);
        }
    }

    list_free(index_list);
    table_close(rel, AccessShareLock);
}

static void
opentde_disable_table_family_encryption(Oid table_oid)
{
    Relation rel;
    List    *index_list;
    ListCell *lc;

    rel = table_open(table_oid, AccessShareLock);

    if (rel->rd_rel->relkind != RELKIND_RELATION &&
        rel->rd_rel->relkind != RELKIND_MATVIEW)
    {
        table_close(rel, AccessShareLock);
        ereport(ERROR,
                (errcode(ERRCODE_WRONG_OBJECT_TYPE),
                 errmsg("relation %u is not a plain table", table_oid)));
    }

    opentde_forget_table_keys(rel->rd_locator.relNumber);

    if (OidIsValid(rel->rd_rel->reltoastrelid))
        opentde_disable_relation_storage_key(rel->rd_rel->reltoastrelid);

    index_list = RelationGetIndexList(rel);
    foreach(lc, index_list)
    {
        Oid index_oid = lfirst_oid(lc);

        opentde_disable_relation_storage_key(index_oid);
    }

    list_free(index_list);
    table_close(rel, AccessShareLock);
}

static void
opentde_maybe_encrypt_indexes_for_table(Oid table_oid)
{
    Relation rel;
    List    *index_list;
    ListCell *lc;
    Oid      table_storage_oid;

    rel = table_open(table_oid, AccessShareLock);
    table_storage_oid = rel->rd_locator.relNumber;
    index_list = RelationGetIndexList(rel);

    foreach(lc, index_list)
    {
        Oid index_oid = lfirst_oid(lc);
        Oid index_storage_oid;

        index_storage_oid = opentde_relation_storage_oid(index_oid);
        opentde_copy_active_storage_key(table_storage_oid, index_storage_oid);
    }

    list_free(index_list);
    table_close(rel, AccessShareLock);
}

static void
opentde_ProcessUtility(PlannedStmt *pstmt,
                       const char *queryString,
                       bool readOnlyTree,
                       ProcessUtilityContext context,
                       ParamListInfo params,
                       QueryEnvironment *queryEnv,
                       DestReceiver *dest,
                       QueryCompletion *qc)
{
    Node *parsetree = pstmt->utilityStmt;
    Oid   saved_pending_index_parent_storage_oid = opentde_pending_index_parent_storage_oid;
    Oid   saved_pending_index_child_storage_oid = opentde_pending_index_child_storage_oid;

    opentde_pending_index_parent_storage_oid = InvalidOid;
    opentde_pending_index_child_storage_oid = InvalidOid;

    if (IsA(parsetree, IndexStmt))
    {
        IndexStmt *stmt = (IndexStmt *) parsetree;
        Oid        table_oid;

        if (stmt->relation != NULL)
        {
            table_oid = RangeVarGetRelid(stmt->relation, NoLock, true);
            if (OidIsValid(table_oid) && opentde_is_relation_encrypted(table_oid))
                opentde_pending_index_parent_storage_oid = opentde_relation_storage_oid(table_oid);
        }
    }

    if (prev_ProcessUtility_hook)
        prev_ProcessUtility_hook(pstmt, queryString, readOnlyTree,
                                 context, params, queryEnv, dest, qc);
    else
        standard_ProcessUtility(pstmt, queryString, readOnlyTree,
                                context, params, queryEnv, dest, qc);

    if (!master_key_set)
        goto done;

    if (IsA(parsetree, IndexStmt))
    {
        IndexStmt *stmt = (IndexStmt *) parsetree;
        Oid        table_oid;

        if (stmt->relation == NULL)
            return;

        table_oid = RangeVarGetRelid(stmt->relation, NoLock, true);
        if (!OidIsValid(table_oid))
            return;

        if (opentde_is_relation_encrypted(table_oid))
            opentde_maybe_encrypt_indexes_for_table(table_oid);

        goto done;
    }

    if (IsA(parsetree, ReindexStmt))
    {
        ReindexStmt *stmt = (ReindexStmt *) parsetree;
        Oid          table_oid;

        if (stmt->kind != REINDEX_OBJECT_TABLE || stmt->relation == NULL)
            return;

        table_oid = RangeVarGetRelid(stmt->relation, NoLock, true);
        if (!OidIsValid(table_oid))
            return;

        if (opentde_is_relation_encrypted(table_oid))
            opentde_maybe_encrypt_indexes_for_table(table_oid);
    }

done:
    opentde_pending_index_parent_storage_oid = saved_pending_index_parent_storage_oid;
    opentde_pending_index_child_storage_oid = saved_pending_index_child_storage_oid;
}

void
opentde_init_utility_hooks(void)
{
    if (opentde_utility_hook_installed)
        return;

    prev_ProcessUtility_hook = ProcessUtility_hook;
    ProcessUtility_hook = opentde_ProcessUtility;
    opentde_utility_hook_installed = true;
}

/* Floor division для int64 и положительного делителя. */
static int64
opentde_floor_div_int64(int64 value, int64 divisor)
{
    int64 q;
    int64 r;

    q = value / divisor;
    r = value % divisor;

    if (r != 0 && value < 0)
        q--;

    return q;
}

/* Общий helper: HMAC(master_key, payload) -> bytea. */
static bytea *
opentde_hmac_token(const unsigned char *payload, size_t payload_len)
{
    unsigned char hmac_result[EVP_MAX_MD_SIZE];
    unsigned int  hmac_len = 0;
    bytea        *result;

    if (!master_key_set || !global_key_mgr)
        ereport(ERROR,
                (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                 errmsg("master key is not set")));

    HMAC(EVP_sha256(),
         global_key_mgr->master_key, MASTER_KEY_SIZE,
         payload, payload_len,
         hmac_result, &hmac_len);

    result = (bytea *) palloc(VARHDRSZ + hmac_len);
    SET_VARSIZE(result, VARHDRSZ + hmac_len);
    memcpy(VARDATA(result), hmac_result, hmac_len);

    return result;
}

/*
 * Токен бакета для bigint.
 */
static bytea *
opentde_blind_bucket_token_int8(int64 bucket_id, int64 bucket_size)
{
    StringInfoData payload;
    bytea         *token;

    initStringInfo(&payload);
    appendStringInfo(&payload,
                     "opentde:rng:int8:v1:%lld:%lld",
                     (long long) bucket_size,
                     (long long) bucket_id);

    token = opentde_hmac_token((unsigned char *) payload.data,
                               (size_t) payload.len);
    pfree(payload.data);
    return token;
}

/*
 * Устанавливает мастер-ключ шифрования
 */
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
    opentde_install_md_hooks();

    /* Сохранение ключа и загрузка существующих DEK/IV */
    opentde_save_master_key_to_file();
    opentde_load_key_file();

    elog(DEBUG1,
         "[OpenTDE] Master key set and %d keys loaded+decrypted",
         global_key_mgr->key_count);
    PG_RETURN_VOID();
}

/*
 * Делает обычную heap-таблицу шифрованной на storage level.
 * Фактическое шифрование начнется при первом обращении smgr к relation.
 */
Datum
opentde_enable_table_encryption(PG_FUNCTION_ARGS)
{
    Oid table_oid;

    table_oid = PG_GETARG_OID(0);

    opentde_init_key_manager();

    if (!master_key_set)
    {
        ereport(ERROR,
                (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                 errmsg("master key is not set")));
    }

    opentde_enable_table_family_encryption(table_oid);

    PG_RETURN_VOID();
}

/*
 * Убирает relation из списка шифруемых таблиц.
 */
Datum
opentde_disable_table_encryption(PG_FUNCTION_ARGS)
{
    Oid table_oid;

    table_oid = PG_GETARG_OID(0);

    opentde_init_key_manager();

    if (!master_key_set)
    {
        ereport(ERROR,
                (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                 errmsg("master key is not set")));
    }

    opentde_disable_table_family_encryption(table_oid);

    PG_RETURN_VOID();
}

/*
 * Быстрая ротация мастер-ключа без перешифрования пользовательских данных.
 *
 * Возвращает количество переобёрнутых DEK.
 */
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
                 errmsg("master key is not set")));
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
            (errmsg("blind index values depend on master key; rebuild related indexes after rotation")));

    PG_RETURN_INT32(global_key_mgr->key_count);
}

/* 
 * Создаёт новую активную версию DEK для указанной таблицы.
 * Старые версии остаются для чтения ранее зашифрованных строк.
 */
Datum
opentde_rotate_table_dek_sql(PG_FUNCTION_ARGS)
{
    Oid      table_oid;
    uint32_t new_version;
    Oid      storage_oid;

    table_oid = PG_GETARG_OID(0);
    storage_oid = opentde_relation_storage_oid(table_oid);

    opentde_init_key_manager();

    if (!master_key_set)
    {
        ereport(ERROR,
                (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                 errmsg("master key is not set")));
    }

    if (global_key_mgr->key_count == 0)
        opentde_load_key_file();

    new_version = opentde_rotate_table_dek(storage_oid);
    PG_RETURN_INT32((int32) new_version);
}

/*
 * Возвращает текстовое представление всех DEK в памяти.
 */
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

/*
 * Возвращает DEK указанной таблицы в виде HEX-строки.
 * Если DEK для таблицы не существует — создаёт новый.
 */
Datum
opentde_get_dek_hex(PG_FUNCTION_ARGS)
{
    Oid              table_oid;
    Oid              storage_oid;
    uint8_t         *dek;
    StringInfoData   buf;
    int              i;

    table_oid = PG_GETARG_OID(0);
    storage_oid = opentde_relation_storage_oid(table_oid);
    dek = opentde_get_table_dek(storage_oid);

    initStringInfo(&buf);
    for (i = 0; i < DEK_SIZE; i++)
        appendStringInfo(&buf, "%02x", dek[i]);

    pfree(dek);
    PG_RETURN_TEXT_P(cstring_to_text(buf.data));
}

/*
 * opentde_blind_index(text) → bytea
 *
 * Слепой индекс: вычисляет HMAC-SHA256 от входного значения,
 * используя мастер-ключ как секрет.
 *
 * Позволяет строить B-tree индексы по зашифрованным данным.
 * В индексных файлах хранятся только HMAC-дайджесты
 */
Datum
opentde_blind_index(PG_FUNCTION_ARGS)
{
    text  *input;
    char  *input_data;
    int    input_len;

    input      = PG_GETARG_TEXT_PP(0);
    input_data = VARDATA_ANY(input);
    input_len  = VARSIZE_ANY_EXHDR(input);

    PG_RETURN_BYTEA_P(
        opentde_hmac_token((unsigned char *) input_data, (size_t) input_len));
}

/*
 * Возвращает blind-токен бакета для int4-значения.
 * Используется для equality-предикатов и expression-index rewrite.
 */
Datum
opentde_blind_bucket_int4(PG_FUNCTION_ARGS)
{
    int32 value;
    int32 bucket_size;
    int64 bucket_id;

    value = PG_GETARG_INT32(0);
    bucket_size = PG_GETARG_INT32(1);

    if (bucket_size <= 0)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("bucket size must be greater than zero")));

    bucket_id = opentde_floor_div_int64((int64) value, (int64) bucket_size);

    PG_RETURN_BYTEA_P(opentde_blind_bucket_token_int8(bucket_id,
                                                      (int64) bucket_size));
}

/*
 * Возвращает blind-токен бакета для bigint-значения.
 * bucket_size > 0, bucket_id = floor(value / bucket_size).
 */
Datum
opentde_blind_bucket_int8(PG_FUNCTION_ARGS)
{
    int64 value;
    int64 bucket_size;
    int64 bucket_id;

    value = PG_GETARG_INT64(0);
    bucket_size = PG_GETARG_INT64(1);

    if (bucket_size <= 0)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("bucket size must be greater than zero")));

    bucket_id = opentde_floor_div_int64(value, bucket_size);

    PG_RETURN_BYTEA_P(opentde_blind_bucket_token_int8(bucket_id, bucket_size));
}

/*
 * Возвращает массив blind-токенов всех бакетов, покрывающих диапазон
 * [lo, hi]
 */
Datum
opentde_blind_bucket_tokens_int8(PG_FUNCTION_ARGS)
{
    int64            lo;
    int64            hi;
    int64            bucket_size;
    int64            start_bucket;
    int64            end_bucket;
    __int128         bucket_count;
    ArrayBuildState *astate;
    int64            bucket_id;

    lo = PG_GETARG_INT64(0);
    hi = PG_GETARG_INT64(1);
    bucket_size = PG_GETARG_INT64(2);

    if (bucket_size <= 0)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("bucket size must be greater than zero")));

    if (hi < lo)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("upper bound must be greater than or equal to lower bound")));

    start_bucket = opentde_floor_div_int64(lo, bucket_size);
    end_bucket = opentde_floor_div_int64(hi, bucket_size);

    bucket_count = ((__int128) end_bucket - (__int128) start_bucket) + 1;
    if (bucket_count <= 0 || bucket_count > OPENTDE_MAX_BUCKET_TOKEN_COUNT)
        ereport(ERROR,
                (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
                 errmsg("range expands to too many buckets")));

    astate = NULL;
    bucket_id = start_bucket;

    for (;;)
    {
        bytea *token;

        token = opentde_blind_bucket_token_int8(bucket_id, bucket_size);
        astate = accumArrayResult(astate,
                                  PointerGetDatum(token),
                                  false,
                                  BYTEAOID,
                                  CurrentMemoryContext);
        pfree(token);

        if (bucket_id == end_bucket)
            break;

        bucket_id++;
    }

    PG_RETURN_DATUM(makeArrayResult(astate, CurrentMemoryContext));
}
