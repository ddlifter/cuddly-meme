#include "postgres.h"
#include "access/tableam.h"
#include "access/heapam.h"
#include "fmgr.h"
#include "utils/rel.h"
#include "utils/memutils.h"
#include "access/htup_details.h"
#include "executor/executor.h"
#include "executor/tuptable.h"
#include "utils/builtins.h"
#include "utils/pg_lsn.h"
#include "kuznechik.h"
#include <string.h>
#include <time.h>

PG_MODULE_MAGIC;  /* ← ЭТО ОБЯЗАТЕЛЬНО! */

typedef struct {
    uint8_t dek[32];
    uint8_t wrapped_dek[48];
    Oid table_oid;
} opentde_key_entry;

typedef struct {
    uint8_t master_key[32];
    opentde_key_entry *keys;
    int key_count;
    int key_capacity;
} opentde_key_manager;

static opentde_key_manager *global_key_mgr = NULL;
static bool master_key_set = false;

PG_FUNCTION_INFO_V1(opentde_tableam_handler);
PG_FUNCTION_INFO_V1(opentde_set_master_key);

/* Инициализация */
static void
init_key_manager(void)
{
    if (global_key_mgr) return;
    
    global_key_mgr = MemoryContextAlloc(TopMemoryContext, sizeof(opentde_key_manager));
    memset(global_key_mgr, 0, sizeof(opentde_key_manager));
    global_key_mgr->key_capacity = 64;
    global_key_mgr->keys = MemoryContextAlloc(TopMemoryContext, 
        global_key_mgr->key_capacity * sizeof(opentde_key_entry));
}

/* Генерация IV */
static void
generate_iv(uint8_t *iv, Oid table_oid)
{
    uint64_t seed = (uint64_t)table_oid ^ 0xDEADBEEFu;
    for (int i = 0; i < 16; i++) {
        iv[i] = (seed >> (i * 4)) & 0xFF;
    }
}

/* DEK операции */
static void
wrap_dek(const uint8_t *master_key, const uint8_t *dek, uint8_t *wrapped)
{
    uint8_t iv[16];
    generate_iv(iv, 0);
    memcpy(wrapped, iv, 16);
    memcpy(wrapped + 16, dek, 32);
    kuz_ctr_crypt(master_key, iv, (uint8_t*)dek, 32);
}

static bool
unwrap_dek(const uint8_t *master_key, const uint8_t *wrapped_dek, uint8_t *dek)
{
    uint8_t iv[16];
    memcpy(iv, wrapped_dek, 16);
    memcpy(dek, wrapped_dek + 16, 32);
    kuz_ctr_crypt(master_key, iv, dek, 32);
    return true;
}

/* Получить DEK */
static uint8_t*
get_table_dek(Oid table_oid)
{
    uint8_t temp_dek[32];
    
    if (!master_key_set || !global_key_mgr) {
        ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
            errmsg("Master key not set. Call opentde_set_master_key() first")));
    }
    
    /* Поиск */
    for (int i = 0; i < global_key_mgr->key_count; i++) {
        if (global_key_mgr->keys[i].table_oid == table_oid) {
            uint8_t *dek = palloc(32);
            if (unwrap_dek(global_key_mgr->master_key, 
                          global_key_mgr->keys[i].wrapped_dek, dek)) {
                return dek;
            }
            pfree(dek);
        }
    }
    
    /* Новый DEK */
    elog(LOG, "[OpenTDE] Creating DEK for table %u", table_oid);
    
    for (int i = 0; i < 32; i++) {
        temp_dek[i] = (uint8_t)(table_oid ^ i ^ 0x12345678u);
    }
    
    if (global_key_mgr->key_count >= global_key_mgr->key_capacity) {
        global_key_mgr->key_capacity *= 2;
        global_key_mgr->keys = repalloc(global_key_mgr->keys,
            global_key_mgr->key_capacity * sizeof(opentde_key_entry));
    }
    
    wrap_dek(global_key_mgr->master_key, temp_dek,
        global_key_mgr->keys[global_key_mgr->key_count].wrapped_dek);
    global_key_mgr->keys[global_key_mgr->key_count].table_oid = table_oid;
    global_key_mgr->key_count++;
    
    uint8_t *dek = palloc(32);
    memcpy(dek, temp_dek, 32);
    return dek;
}

/* Шифрование */
static void
gost_encrypt_decrypt(char *data, int len, Oid table_oid)
{
    uint8_t *table_key = get_table_dek(table_oid);
    uint8_t iv[16];
    generate_iv(iv, table_oid);
    
    kuz_ctr_crypt(table_key, iv, (uint8_t*)data, len);
    pfree(table_key);
}

/* INSERT */
static void
opentde_tuple_insert(Relation relation, TupleTableSlot *slot,
                     CommandId cid, int options, BulkInsertState bistate)
{
    bool should_free;
    HeapTuple tuple, encrypted_tuple;
    char *payload_start;
    int payload_len;
    Oid table_oid = RelationGetRelid(relation);

    elog(INFO, "[OpenTDE] Encrypting INSERT for table %u", table_oid);

    tuple = ExecFetchSlotHeapTuple(slot, true, &should_free);
    if (!tuple) return;

    encrypted_tuple = heap_copytuple(tuple);
    payload_start = (char *) encrypted_tuple->t_data + encrypted_tuple->t_data->t_hoff;
    payload_len = encrypted_tuple->t_len - encrypted_tuple->t_data->t_hoff;

    gost_encrypt_decrypt(payload_start, payload_len, table_oid);

    heap_insert(relation, encrypted_tuple, cid, options, bistate);
    heap_freetuple(encrypted_tuple);
    if (should_free) heap_freetuple(tuple);
}

/* SCAN */
static bool
opentde_scan_getnextslot(TableScanDesc sscan, ScanDirection direction, TupleTableSlot *slot)
{
    const TableAmRoutine *heap_am = GetHeapamTableAmRoutine();
    bool found, should_free;
    HeapTuple tuple, decrypted_tuple;
    char *dec_payload;
    int dec_len;
    ItemPointerData tid;
    Oid table_oid = slot->tts_tableOid;

    found = heap_am->scan_getnextslot(sscan, direction, slot);
    if (!found) return false;

    tuple = ExecFetchSlotHeapTuple(slot, true, &should_free);
    if (!tuple) return true;

    decrypted_tuple = heap_copytuple(tuple);
    decrypted_tuple->t_self = tuple->t_self;
    tid = tuple->t_self;

    dec_payload = (char *) decrypted_tuple->t_data + decrypted_tuple->t_data->t_hoff;
    dec_len = decrypted_tuple->t_len - decrypted_tuple->t_data->t_hoff;
    
    gost_encrypt_decrypt(dec_payload, dec_len, table_oid);

    ExecForceStoreHeapTuple(decrypted_tuple, slot, true);
    slot->tts_tid = tid;
    if (should_free) heap_freetuple(tuple);
    
    return true;
}

/* Мастер-ключ */
Datum
opentde_set_master_key(PG_FUNCTION_ARGS)
{
    bytea *key_data = PG_GETARG_BYTEA_P(0);
    int key_len = VARSIZE_ANY_EXHDR(key_data);
    
    if (key_len != 32) {
        ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
            errmsg("Master key must be exactly 32 bytes, got %d", key_len)));
    }
    
    init_key_manager();
    memcpy(global_key_mgr->master_key, key_data + VARHDRSZ, 32);
    master_key_set = true;
    
    elog(INFO, "[OpenTDE] Master key set successfully");
    PG_RETURN_VOID();
}

/* Handler */
Datum
opentde_tableam_handler(PG_FUNCTION_ARGS)
{
    const TableAmRoutine *heap_am = GetHeapamTableAmRoutine();
    TableAmRoutine *tde_am = MemoryContextAlloc(TopMemoryContext, sizeof(TableAmRoutine));
    
    memcpy(tde_am, heap_am, sizeof(TableAmRoutine));
    tde_am->type = T_TableAmRoutine;
    tde_am->tuple_insert = opentde_tuple_insert;
    tde_am->scan_getnextslot = opentde_scan_getnextslot;
    
    PG_RETURN_POINTER(tde_am);
}
