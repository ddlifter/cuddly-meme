#include "postgres.h"
#include "access/tableam.h"
#include "access/heapam.h"
#include "fmgr.h"
#include "utils/rel.h"
#include "utils/memutils.h"
#include "access/htup_details.h"
#include "executor/executor.h"
#include "executor/tuptable.h"
#include "kuznechik.h"

static const uint8_t MY_SECRET_KEY[32] = {
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
};

PG_FUNCTION_INFO_V1(opentde_tableam_handler);

static void gost_encrypt_decrypt(char *data, int len);
static void opentde_tuple_insert(Relation relation, TupleTableSlot *slot,
                                 CommandId cid, int options,
                                 BulkInsertState bistate);
static bool opentde_scan_getnextslot(TableScanDesc sscan, ScanDirection direction, TupleTableSlot *slot);


static void
gost_encrypt_decrypt(char *data, int len)
{

    uint8_t iv[16] = {0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0,0,0,0,0,0,0,0};
    
    kuz_ctr_crypt(MY_SECRET_KEY, iv, (uint8_t*)data, len);
}

/* Реализация INSERT */
static void
opentde_tuple_insert(Relation relation, TupleTableSlot *slot,
                     CommandId cid, int options,
                     BulkInsertState bistate)
{
    bool should_free;
    HeapTuple tuple;
    HeapTuple encrypted_tuple;
    char *payload_start;
    int payload_len;
    const TableAmRoutine *heap_am;

    elog(INFO, "[OpenTDE] Encrypting INSERT...");

    /* Получаем данные из слота */
    tuple = ExecFetchSlotHeapTuple(slot, true, &should_free);

    /* Создаем копию для шифрования */
    encrypted_tuple = heap_copytuple(tuple);

    /* Вычисляем payload */
    payload_start = (char *) encrypted_tuple->t_data + encrypted_tuple->t_data->t_hoff;
    payload_len = encrypted_tuple->t_len - encrypted_tuple->t_data->t_hoff;

    /* Шифруем */
    gost_encrypt_decrypt(payload_start, payload_len);

    /* Вызываем оригинал */
    heap_am = GetHeapamTableAmRoutine();

    heap_insert(relation, encrypted_tuple, cid, options, bistate);

    /* Чистим память */
    heap_freetuple(encrypted_tuple);
    if (should_free)
        heap_freetuple(tuple);
}

/* Реализация SCAN */
static bool
opentde_scan_getnextslot(TableScanDesc sscan, ScanDirection direction, TupleTableSlot *slot)
{
    const TableAmRoutine *heap_am = GetHeapamTableAmRoutine();
    bool found;
    bool should_free;
    HeapTuple tuple;
    HeapTuple decrypted_tuple;
    char *payload_start;
    char *dec_payload;
    int payload_len;
    int dec_len;

    found = heap_am->scan_getnextslot(sscan, direction, slot);

    if (!found)
        return false;
    
    /* Достаем tuple из слота */
    tuple = ExecFetchSlotHeapTuple(slot, true, &should_free);

    decrypted_tuple = heap_copytuple(tuple);

    /* Дешифруем копию */
    dec_payload = (char *) decrypted_tuple->t_data + decrypted_tuple->t_data->t_hoff;
    dec_len = decrypted_tuple->t_len - decrypted_tuple->t_data->t_hoff;
    
    gost_encrypt_decrypt(dec_payload, dec_len);

    /* Засовываем чистую копию обратно в слот */
    /* true = слот должен освободить память этого тупла сам потом */
    ExecForceStoreHeapTuple(decrypted_tuple, slot, true);
    if (should_free)
        heap_freetuple(tuple);

    return true;
}

/* Основной хендлер */
Datum
opentde_tableam_handler(PG_FUNCTION_ARGS)
{
    const TableAmRoutine *heap_am = GetHeapamTableAmRoutine();
    TableAmRoutine *tde_am = (TableAmRoutine *) MemoryContextAlloc(TopMemoryContext, sizeof(TableAmRoutine));
    
    memcpy(tde_am, heap_am, sizeof(TableAmRoutine));
    tde_am->type = T_TableAmRoutine;

    tde_am->tuple_insert = opentde_tuple_insert;
    tde_am->scan_getnextslot = opentde_scan_getnextslot;

    PG_RETURN_POINTER(tde_am);
}
