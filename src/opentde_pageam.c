 #include "opentde.h"

#include "catalog/pg_am_d.h"
#include "catalog/index.h"
#include "executor/executor.h"
#include "miscadmin.h"
#include "utils/snapmgr.h"
#include "utils/hsearch.h"

#include <string.h>

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(opentde_pageam_handler);
PG_FUNCTION_INFO_V1(opentde_tableam_handler);

static TableAmRoutine opentde_pageam_methods;
static HTAB          *opentde_pagestore_scans = NULL;

typedef struct {
    TableScanDesc          sscan;
    opentde_pagestore_scan scan;
} opentde_pagestore_scan_entry;

static TM_Result opentde_page_tuple_delete(Relation relation,
                                           ItemPointer tid,
                                           CommandId cid,
                                           Snapshot snapshot,
                                           Snapshot crosscheck,
                                           bool wait,
                                           TM_FailureData *tmfd,
                                           bool changingPart);
static double opentde_page_index_build_range_scan(Relation table_rel,
                                                  Relation index_rel,
                                                  struct IndexInfo *index_info,
                                                  bool allow_sync,
                                                  bool anyvisible,
                                                  bool progress,
                                                  BlockNumber start_blockno,
                                                  BlockNumber numblocks,
                                                  IndexBuildCallback callback,
                                                  void *callback_state,
                                                  TableScanDesc scan);
static const TupleTableSlotOps *opentde_page_slot_callbacks(Relation rel);

static void
opentde_page_fixup_slot_tid(TupleTableSlot *slot,
                            const ItemPointerData *tid)
{
    bool      should_free;
    HeapTuple stored;

    if (!slot || !tid)
        return;

    slot->tts_tid = *tid;
    stored = ExecFetchSlotHeapTuple(slot, false, &should_free);
    if (stored)
    {
        stored->t_self = *tid;
        ItemPointerCopy(tid, &stored->t_data->t_ctid);
        if (should_free)
            heap_freetuple(stored);
    }
}

void _PG_fini(void);

static void
opentde_pagestore_scan_registry_init(void)
{
    HASHCTL ctl;

    if (opentde_pagestore_scans)
        return;

    MemSet(&ctl, 0, sizeof(ctl));
    ctl.keysize = sizeof(TableScanDesc);
    ctl.entrysize = sizeof(opentde_pagestore_scan_entry);
    ctl.hcxt = TopMemoryContext;

    opentde_pagestore_scans = hash_create("OpenTDE page image scans",
                                          128,
                                          &ctl,
                                          HASH_ELEM | HASH_BLOBS | HASH_CONTEXT);
}

static opentde_pagestore_scan_entry *
opentde_pagestore_get_scan_entry(TableScanDesc sscan, bool create)
{
    bool found;

    if (!opentde_pagestore_scans)
        return NULL;

    return (opentde_pagestore_scan_entry *) hash_search(opentde_pagestore_scans,
                                                        &sscan,
                                                        create ? HASH_ENTER : HASH_FIND,
                                                        &found);
}

void
_PG_init(void)
{
    opentde_init_key_manager();
    opentde_pagestore_scan_registry_init();
    elog(DEBUG1, "[OpenTDE] Extension loaded (page-level only)");

    if (opentde_load_master_key_from_file())
    {
        opentde_load_key_file();
        elog(DEBUG1, "[OpenTDE] Auto-loaded %d keys", global_key_mgr->key_count);
    }

}

void
_PG_fini(void)
{
    HASH_SEQ_STATUS seq;
    opentde_pagestore_scan_entry *entry;

    if (opentde_pagestore_scans)
    {
        hash_seq_init(&seq, opentde_pagestore_scans);
        while ((entry = (opentde_pagestore_scan_entry *) hash_seq_search(&seq)) != NULL)
            opentde_pagestore_scan_close(&entry->scan);
    }

}

static void
opentde_page_tuple_insert(Relation relation,
                          TupleTableSlot *slot,
                          CommandId cid,
                          int options,
                          BulkInsertState bistate)
{
    bool      should_free;
    HeapTuple tuple;
    Oid       table_oid;
    ItemPointerData stored_tid;

    (void) cid;
    (void) options;
    (void) bistate;

    table_oid = RelationGetRelid(relation);

    tuple = ExecFetchSlotHeapTuple(slot, true, &should_free);
    if (!tuple)
        return;

    if (!opentde_pagestore_append_tuple(table_oid, tuple, &stored_tid))
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("page image append failed for table %u", table_oid)));

    slot->tts_tid = stored_tid;

    if (should_free)
        heap_freetuple(tuple);
}

static TM_Result
opentde_page_tuple_update(Relation relation,
                          ItemPointer otid,
                          TupleTableSlot *slot,
                          CommandId cid,
                          Snapshot snapshot,
                          Snapshot crosscheck,
                          bool wait,
                          TM_FailureData *tmfd,
                          LockTupleMode *lockmode,
                          TU_UpdateIndexes *update_indexes)
{
    bool       should_free;
    HeapTuple  tuple;
    ItemPointerData stored_tid;
    BlockNumber row_blockno = InvalidBlockNumber;

    (void) cid;
    (void) snapshot;
    (void) crosscheck;
    (void) wait;

    if (otid)
        row_blockno = ItemPointerGetBlockNumberNoCheck(otid);
    else if (ItemPointerIsValid(&slot->tts_tid))
        row_blockno = ItemPointerGetBlockNumber(&slot->tts_tid);

    if (row_blockno == InvalidBlockNumber)
        return TM_Invisible;

    tuple = ExecFetchSlotHeapTuple(slot, true, &should_free);
    if (!tuple)
        return TM_Invisible;

    if (!opentde_pagestore_update_tuple(RelationGetRelid(relation),
                                        row_blockno,
                                        tuple,
                                        &stored_tid))
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("page image update failed for table %u block %u",
                        RelationGetRelid(relation),
                        row_blockno)));

    slot->tts_tid = stored_tid;

    if (tmfd)
    {
        memset(tmfd, 0, sizeof(*tmfd));
        tmfd->ctid = stored_tid;
    }
    if (lockmode)
        *lockmode = LockTupleNoKeyExclusive;
    if (update_indexes)
        *update_indexes = TU_All;

    if (should_free)
        heap_freetuple(tuple);

    return TM_Ok;
}

static TM_Result
opentde_page_tuple_delete(Relation relation,
                          ItemPointer tid,
                          CommandId cid,
                          Snapshot snapshot,
                          Snapshot crosscheck,
                          bool wait,
                          TM_FailureData *tmfd,
                          bool changingPart)
{
    BlockNumber row_blockno = InvalidBlockNumber;

    (void) cid;
    (void) snapshot;
    (void) crosscheck;
    (void) wait;
    (void) changingPart;

    if (tid)
        row_blockno = ItemPointerGetBlockNumberNoCheck(tid);

    if (row_blockno == InvalidBlockNumber)
        return TM_Deleted;

    if (!opentde_pagestore_delete_tuple(RelationGetRelid(relation),
                                        row_blockno))
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("page image delete failed for table %u block %u",
                        RelationGetRelid(relation),
                        row_blockno)));

    if (tmfd)
        memset(tmfd, 0, sizeof(*tmfd));

    return TM_Ok;
}

static void
opentde_page_multi_insert(Relation relation,
                          TupleTableSlot **slots,
                          int nslots,
                          CommandId cid,
                          int options,
                          BulkInsertState bistate)
{
    int       i;

    for (i = 0; i < nslots; i++)
        opentde_page_tuple_insert(relation, slots[i], cid, options, bistate);
}

static bool
opentde_page_scan_getnextslot(TableScanDesc sscan,
                              ScanDirection direction,
                              TupleTableSlot *slot)
{
    opentde_pagestore_scan_entry *entry;
    HeapTuple                     tuple;

    if (direction != ForwardScanDirection)
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("only forward scan is supported for page image storage path")));

    entry = opentde_pagestore_get_scan_entry(sscan, false);
    if (!entry)
    {
        entry = opentde_pagestore_get_scan_entry(sscan, true);
        if (!entry)
            ereport(ERROR,
                    (errcode(ERRCODE_OUT_OF_MEMORY),
                     errmsg("cannot allocate page store scan entry")));

        if (!opentde_pagestore_scan_open(RelationGetRelid(sscan->rs_rd), &entry->scan))
        {
            hash_search(opentde_pagestore_scans, &sscan, HASH_REMOVE, NULL);
            return false;
        }
    }

    if (!opentde_pagestore_scan_next(&entry->scan, &tuple))
    {
        opentde_pagestore_scan_close(&entry->scan);
        hash_search(opentde_pagestore_scans, &sscan, HASH_REMOVE, NULL);
        return false;
    }

    ExecStoreHeapTuple(tuple, slot, true);
    opentde_page_fixup_slot_tid(slot, &tuple->t_self);
    return true;
}

static bool
opentde_page_index_fetch_tuple(struct IndexFetchTableData *scan,
                               ItemPointer tid,
                               Snapshot snapshot,
                               TupleTableSlot *slot,
                               bool *call_again,
                               bool *all_dead)
{
    HeapTuple tuple;
    BlockNumber row_blockno;

    (void) snapshot;

    if (!tid)
        return false;

    row_blockno = ItemPointerGetBlockNumberNoCheck(tid);

    if (!opentde_pagestore_fetch_latest(RelationGetRelid(scan->rel),
                                        row_blockno,
                                        &tuple))
        return false;

    ExecStoreHeapTuple(tuple, slot, true);
    opentde_page_fixup_slot_tid(slot, &tuple->t_self);

    if (call_again)
        *call_again = false;
    if (all_dead)
        *all_dead = false;

    return true;
}

static double
opentde_page_index_build_range_scan(Relation table_rel,
                                    Relation index_rel,
                                    struct IndexInfo *index_info,
                                    bool allow_sync,
                                    bool anyvisible,
                                    bool progress,
                                    BlockNumber start_blockno,
                                    BlockNumber numblocks,
                                    IndexBuildCallback callback,
                                    void *callback_state,
                                    TableScanDesc scan)
{
    EState         *estate;
    TupleTableSlot *slot;
    Snapshot        snapshot;
    bool            need_unregister_snapshot;
    Datum           values[INDEX_MAX_KEYS];
    bool            isnull[INDEX_MAX_KEYS];
    double          reltuples;

    (void) allow_sync;
    (void) anyvisible;
    (void) progress;
    (void) start_blockno;
    (void) numblocks;

    need_unregister_snapshot = false;
    if (index_info->ii_Concurrent)
    {
        snapshot = RegisterSnapshot(GetTransactionSnapshot());
        need_unregister_snapshot = true;
    }
    else
        snapshot = SnapshotAny;

    estate = CreateExecutorState();
    slot = table_slot_create(table_rel, NULL);

    scan = table_beginscan_strat(table_rel,
                                 snapshot,
                                 0,
                                 NULL,
                                 true,
                                 true);

    reltuples = 0;
    while (opentde_page_scan_getnextslot(scan, ForwardScanDirection, slot))
    {
        CHECK_FOR_INTERRUPTS();

        FormIndexDatum(index_info,
                       slot,
                       estate,
                       values,
                       isnull);
        callback(index_rel,
                 &slot->tts_tid,
                 values,
                 isnull,
                 true,
                 callback_state);
        reltuples += 1;
    }

    table_endscan(scan);
    if (need_unregister_snapshot)
        UnregisterSnapshot(snapshot);

    ExecDropSingleTupleTableSlot(slot);
    FreeExecutorState(estate);

    return reltuples;
}

static TM_Result
opentde_page_tuple_lock(Relation relation,
                        ItemPointer tid,
                        Snapshot snapshot,
                        TupleTableSlot *slot,
                        CommandId cid,
                        LockTupleMode mode,
                        LockWaitPolicy wait_policy,
                        uint8 flags,
                        TM_FailureData *tmfd)
{
    HeapTuple tuple;
    BlockNumber row_blockno;

    (void) snapshot;
    (void) cid;
    (void) mode;
    (void) wait_policy;
    (void) flags;

    if (!slot)
        return TM_Invisible;

    if (!tid)
        return TM_Deleted;

    row_blockno = ItemPointerGetBlockNumberNoCheck(tid);

    if (!opentde_pagestore_fetch_latest(RelationGetRelid(relation),
                                        row_blockno,
                                        &tuple))
        return TM_Deleted;

    ExecStoreHeapTuple(tuple, slot, true);
    opentde_page_fixup_slot_tid(slot, &tuple->t_self);
    if (tmfd)
        memset(tmfd, 0, sizeof(*tmfd));

    return TM_Ok;
}

static bool
opentde_page_tuple_fetch_row_version(Relation relation,
                                     ItemPointer tid,
                                     Snapshot snapshot,
                                     TupleTableSlot *slot)
{
    HeapTuple tuple;
    BlockNumber row_blockno;

    (void) snapshot;

    if (!tid)
        return false;

    row_blockno = ItemPointerGetBlockNumberNoCheck(tid);

    if (!opentde_pagestore_fetch_latest(RelationGetRelid(relation),
                                        row_blockno,
                                        &tuple))
        return false;

    ExecStoreHeapTuple(tuple, slot, true);
    opentde_page_fixup_slot_tid(slot, &tuple->t_self);
    return true;
}

static Oid
opentde_page_relation_toast_am(Relation rel)
{
    (void) rel;
    return HEAP_TABLE_AM_OID;
}

static const TupleTableSlotOps *
opentde_page_slot_callbacks(Relation rel)
{
    (void) rel;
    return &TTSOpsHeapTuple;
}

static const TableAmRoutine *
opentde_get_pageam_methods(void)
{
    const TableAmRoutine *heap_am;

    heap_am = GetHeapamTableAmRoutine();
    memcpy(&opentde_pageam_methods, heap_am, sizeof(TableAmRoutine));

    opentde_pageam_methods.tuple_insert = opentde_page_tuple_insert;
    opentde_pageam_methods.tuple_delete = opentde_page_tuple_delete;
    opentde_pageam_methods.tuple_update = opentde_page_tuple_update;
    opentde_pageam_methods.multi_insert = opentde_page_multi_insert;
    opentde_pageam_methods.scan_getnextslot = opentde_page_scan_getnextslot;
    opentde_pageam_methods.index_build_range_scan = opentde_page_index_build_range_scan;
    opentde_pageam_methods.index_fetch_tuple = opentde_page_index_fetch_tuple;
    opentde_pageam_methods.tuple_lock = opentde_page_tuple_lock;
    opentde_pageam_methods.tuple_fetch_row_version = opentde_page_tuple_fetch_row_version;
    opentde_pageam_methods.relation_toast_am = opentde_page_relation_toast_am;
    opentde_pageam_methods.slot_callbacks = opentde_page_slot_callbacks;

    return &opentde_pageam_methods;
}

Datum
opentde_pageam_handler(PG_FUNCTION_ARGS)
{
    PG_RETURN_POINTER(opentde_get_pageam_methods());
}

/* Compatibility symbol for old databases that still reference opentde_tableam_handler. */
Datum
opentde_tableam_handler(PG_FUNCTION_ARGS)
{
    PG_RETURN_POINTER(opentde_get_pageam_methods());
}
