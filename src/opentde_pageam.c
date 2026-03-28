#include "postgres.h"
#include "fmgr.h"
#include "opentde_pagestore.h" // for opentde_pagestore_header, helpers, magic/version
#include "executor/tuptable.h" // for TTSOpsVirtual
#include "access/transam.h"    // for InvalidTransactionId
#include "access/multixact.h"  // for InvalidMultiXactId

#include "access/tableam.h"  // for Relation, TableScanDesc, TableAmRoutine, etc.

PG_FUNCTION_INFO_V1(opentde_pageam_handler);


/* --- Minimal stub implementations for all required TableAmRoutine callbacks --- */

typedef struct opentde_tableam_scan {
    Relation rel;
    opentde_pagestore_scan pagestore_scan;
    bool pagestore_opened;
} opentde_tableam_scan;
static const TupleTableSlotOps *opentde_slot_callbacks(Relation rel) {
    return &TTSOpsHeapTuple;
}

static TableScanDesc opentde_scan_begin(Relation rel, Snapshot snapshot, int nkeys, ScanKey key, ParallelTableScanDesc pscan, uint32 flags) {
    opentde_tableam_scan *scan = palloc0(sizeof(opentde_tableam_scan));
    scan->rel = rel;
    scan->pagestore_opened = opentde_pagestore_scan_open(RelationGetRelid(rel), &scan->pagestore_scan);
    return (TableScanDesc)scan;
}

static void opentde_scan_end(TableScanDesc scan) {
    opentde_tableam_scan *s = (opentde_tableam_scan *)scan;
    if (s->pagestore_opened) {
        opentde_pagestore_scan_close(&s->pagestore_scan);
        s->pagestore_opened = false;
    }
    pfree(scan);
}

static bool opentde_scan_getnextslot(TableScanDesc scan, ScanDirection direction, TupleTableSlot *slot) {
    opentde_tableam_scan *s = (opentde_tableam_scan *)scan;
    HeapTuple tuple = NULL;
    if (!s->pagestore_opened)
        return false;
    if (!opentde_pagestore_scan_next(&s->pagestore_scan, &tuple))
        return false;
    /* elog(LOG, "OpenTDE: TableAM scan_getnextslot returning tuple with t_len=%d", (int)tuple->t_len); */
    ExecClearTuple(slot);
    slot->tts_tupleDescriptor = s->rel->rd_att;
    ExecStoreHeapTuple(tuple, slot, false);
    return true;
}

static void opentde_scan_rescan(TableScanDesc scan, ScanKey key, bool set_params, bool allow_strat, bool allow_sync, bool allow_pagemode) {
    elog(ERROR, "OpenTDE: scan_rescan not implemented");
}

static void opentde_scan_set_tidrange(TableScanDesc scan, ItemPointer mintid, ItemPointer maxtid) { elog(ERROR, "OpenTDE: scan_set_tidrange not implemented"); }
static bool opentde_scan_getnextslot_tidrange(TableScanDesc scan, ScanDirection direction, TupleTableSlot *slot) { elog(ERROR, "OpenTDE: scan_getnextslot_tidrange not implemented"); return false; }
static Size opentde_parallelscan_estimate(Relation rel) { elog(ERROR, "OpenTDE: parallelscan_estimate not implemented"); return 0; }
static Size opentde_parallelscan_initialize(Relation rel, ParallelTableScanDesc pscan) { elog(ERROR, "OpenTDE: parallelscan_initialize not implemented"); return 0; }
static void opentde_parallelscan_reinitialize(Relation rel, ParallelTableScanDesc pscan) { elog(ERROR, "OpenTDE: parallelscan_reinitialize not implemented"); }
static struct IndexFetchTableData *opentde_index_fetch_begin(Relation rel) { elog(ERROR, "OpenTDE: index_fetch_begin not implemented"); return NULL; }
static void opentde_index_fetch_reset(struct IndexFetchTableData *data) { elog(ERROR, "OpenTDE: index_fetch_reset not implemented"); }
static void opentde_index_fetch_end(struct IndexFetchTableData *data) { elog(ERROR, "OpenTDE: index_fetch_end not implemented"); }
static bool opentde_index_fetch_tuple(struct IndexFetchTableData *scan, ItemPointer tid, Snapshot snapshot, TupleTableSlot *slot, bool *call_again, bool *all_dead) { elog(ERROR, "OpenTDE: index_fetch_tuple not implemented"); return false; }
static bool opentde_tuple_fetch_row_version(Relation rel, ItemPointer tid, Snapshot snapshot, TupleTableSlot *slot) {
    /* Minimal implementation: scan all tuples, compare t_self with tid, store in slot if found */
    opentde_pagestore_scan scan;
    HeapTuple tuple = NULL;
    bool found = false;
    if (!opentde_pagestore_scan_open(RelationGetRelid(rel), &scan))
        return false;
    while (opentde_pagestore_scan_next(&scan, &tuple)) {
        if (ItemPointerEquals(&tuple->t_self, tid)) {
            ExecClearTuple(slot);
            slot->tts_tupleDescriptor = rel->rd_att;
            ExecStoreHeapTuple(tuple, slot, false);
            found = true;
            break;
        }
        heap_freetuple(tuple);
    }
    opentde_pagestore_scan_close(&scan);
    return found;
}
static bool opentde_tuple_tid_valid(TableScanDesc scan, ItemPointer tid) { elog(ERROR, "OpenTDE: tuple_tid_valid not implemented"); return false; }
static void opentde_tuple_get_latest_tid(TableScanDesc scan, ItemPointer tid) { elog(ERROR, "OpenTDE: tuple_get_latest_tid not implemented"); }
static bool opentde_tuple_satisfies_snapshot(Relation rel, TupleTableSlot *slot, Snapshot snapshot) { elog(ERROR, "OpenTDE: tuple_satisfies_snapshot not implemented"); return false; }
static TransactionId opentde_index_delete_tuples(Relation rel, TM_IndexDeleteOp *delstate) { elog(ERROR, "OpenTDE: index_delete_tuples not implemented"); return InvalidTransactionId; }
static void opentde_tuple_insert(Relation rel, TupleTableSlot *slot, CommandId cid, int options, BulkInsertStateData *bistate) {
    /* Insert tuple using pagestore. */
    if (!TTS_EMPTY(slot)) {
        /* Get HeapTuple from slot */
        HeapTuple tuple = ExecCopySlotHeapTuple(slot);
        /* Инициализируем t_self валидным значением (blockno=0, offset=1) */
        ItemPointerSet(&tuple->t_self, 0, 1);
        ItemPointerData tid;
        opentde_pagestore_append_tuple(RelationGetRelid(rel), tuple, &tid);
        heap_freetuple(tuple);
    }
}
static void opentde_tuple_insert_speculative(Relation rel, TupleTableSlot *slot, CommandId cid, int options, BulkInsertStateData *bistate, uint32 specToken) { elog(ERROR, "OpenTDE: tuple_insert_speculative not implemented"); }
static void opentde_tuple_complete_speculative(Relation rel, TupleTableSlot *slot, uint32 specToken, bool succeeded) { elog(ERROR, "OpenTDE: tuple_complete_speculative not implemented"); }
static void opentde_multi_insert(Relation rel, TupleTableSlot **slots, int nslots, CommandId cid, int options, BulkInsertStateData *bistate) { elog(ERROR, "OpenTDE: multi_insert not implemented"); }
static TM_Result opentde_tuple_delete(Relation rel, ItemPointer tid, CommandId cid, Snapshot snapshot, Snapshot crosscheck, bool wait, TM_FailureData *tmfd, bool changingPart) { elog(ERROR, "OpenTDE: tuple_delete not implemented"); return TM_Ok; }
static TM_Result opentde_tuple_update(Relation rel, ItemPointer otid, TupleTableSlot *slot, CommandId cid, Snapshot snapshot, Snapshot crosscheck, bool wait, TM_FailureData *tmfd, LockTupleMode *lockmode, TU_UpdateIndexes *update_indexes) { elog(ERROR, "OpenTDE: tuple_update not implemented"); return TM_Ok; }
static TM_Result opentde_tuple_lock(Relation rel, ItemPointer tid, Snapshot snapshot, TupleTableSlot *slot, CommandId cid, LockTupleMode mode, LockWaitPolicy wait_policy, uint8 flags, TM_FailureData *tmfd) { elog(ERROR, "OpenTDE: tuple_lock not implemented"); return TM_Ok; }
static void opentde_finish_bulk_insert(Relation rel, int options) { elog(ERROR, "OpenTDE: finish_bulk_insert not implemented"); }
static void opentde_relation_set_new_filelocator(Relation rel, const RelFileLocator *newrlocator, char persistence, TransactionId *freezeXid, MultiXactId *minmulti) {
    /* Create a new pagestore file for the relation. */
    Oid table_oid = RelationGetRelid(rel);
    opentde_pagestore_ensure_dir();
    char *path = opentde_pagestore_get_file_path(table_oid);
    int fd = open(path, O_RDWR | O_CREAT | O_EXCL | PG_BINARY, 0600);
    if (fd >= 0) {
        opentde_pagestore_header hdr;
        memset(&hdr, 0, sizeof(hdr));
        hdr.magic = OPENTDE_PAGESTORE_MAGIC;
        hdr.version = OPENTDE_PAGESTORE_VERSION;
        hdr.record_count = 0;
        pwrite(fd, &hdr, sizeof(hdr), 0);
        close(fd);
    }
    pfree(path);
    if (freezeXid) *freezeXid = InvalidTransactionId;
    if (minmulti) *minmulti = InvalidMultiXactId;
}
static void opentde_relation_nontransactional_truncate(Relation rel) { elog(ERROR, "OpenTDE: relation_nontransactional_truncate not implemented"); }
static void opentde_relation_copy_data(Relation rel, const RelFileLocator *newrlocator) { elog(ERROR, "OpenTDE: relation_copy_data not implemented"); }
static void opentde_relation_copy_for_cluster(Relation OldTable, Relation NewTable, Relation OldIndex, bool use_sort, TransactionId OldestXmin, TransactionId *xid_cutoff, MultiXactId *multi_cutoff, double *num_tuples, double *tups_vacuumed, double *tups_recently_dead) { elog(ERROR, "OpenTDE: relation_copy_for_cluster not implemented"); }
static void opentde_relation_vacuum(Relation rel, const VacuumParams params, BufferAccessStrategy bstrategy) { elog(ERROR, "OpenTDE: relation_vacuum not implemented"); }
static bool opentde_scan_analyze_next_block(TableScanDesc scan, ReadStream *stream) { elog(ERROR, "OpenTDE: scan_analyze_next_block not implemented"); return false; }
static bool opentde_scan_analyze_next_tuple(TableScanDesc scan, TransactionId OldestXmin, double *liverows, double *deadrows, TupleTableSlot *slot) { elog(ERROR, "OpenTDE: scan_analyze_next_tuple not implemented"); return false; }
static double opentde_index_build_range_scan(Relation table_rel, Relation index_rel, IndexInfo *index_info, bool allow_sync, bool anyvisible, bool progress, BlockNumber start_blockno, BlockNumber numblocks, IndexBuildCallback callback, void *callback_state, TableScanDesc scan) { elog(ERROR, "OpenTDE: index_build_range_scan not implemented"); return 0; }
static void opentde_index_validate_scan(Relation table_rel, Relation index_rel, IndexInfo *index_info, Snapshot snapshot, ValidateIndexState *state) { elog(ERROR, "OpenTDE: index_validate_scan not implemented"); }
static uint64 opentde_relation_size(Relation rel, ForkNumber forkNumber) { elog(ERROR, "OpenTDE: relation_size not implemented"); return 0; }
static bool opentde_relation_needs_toast_table(Relation rel) { return false; }
static Oid opentde_relation_toast_am(Relation rel) { elog(ERROR, "OpenTDE: relation_toast_am not implemented"); return InvalidOid; }
static void opentde_relation_fetch_toast_slice(Relation toastrel, Oid valueid, int32 attrsize, int32 sliceoffset, int32 slicelength, struct varlena *result) { elog(ERROR, "OpenTDE: relation_fetch_toast_slice not implemented"); }
static void opentde_relation_estimate_size(Relation rel, int32 *attr_widths, BlockNumber *pages, double *tuples, double *allvisfrac) {
    /* Minimal stub: just return 1 page, 1 tuple, 100% visibility */
    if (pages) *pages = 1;
    if (tuples) *tuples = 1.0;
    if (allvisfrac) *allvisfrac = 1.0;
}
static bool opentde_scan_bitmap_next_tuple(TableScanDesc scan, TupleTableSlot *slot, bool *recheck, uint64 *lossy_pages, uint64 *exact_pages) { elog(ERROR, "OpenTDE: scan_bitmap_next_tuple not implemented"); return false; }
static bool opentde_scan_sample_next_block(TableScanDesc scan, SampleScanState *scanstate) { elog(ERROR, "OpenTDE: scan_sample_next_block not implemented"); return false; }
static bool opentde_scan_sample_next_tuple(TableScanDesc scan, SampleScanState *scanstate, TupleTableSlot *slot) { elog(ERROR, "OpenTDE: scan_sample_next_tuple not implemented"); return false; }

static const TableAmRoutine opentde_minimal_tableam = {
    .type = T_TableAmRoutine,
    .slot_callbacks = opentde_slot_callbacks,
    .scan_begin = opentde_scan_begin,
    .scan_end = opentde_scan_end,
    .scan_rescan = opentde_scan_rescan,
    .scan_getnextslot = opentde_scan_getnextslot,
    .scan_set_tidrange = opentde_scan_set_tidrange,
    .scan_getnextslot_tidrange = opentde_scan_getnextslot_tidrange,
    .parallelscan_estimate = opentde_parallelscan_estimate,
    .parallelscan_initialize = opentde_parallelscan_initialize,
    .parallelscan_reinitialize = opentde_parallelscan_reinitialize,
    .index_fetch_begin = opentde_index_fetch_begin,
    .index_fetch_reset = opentde_index_fetch_reset,
    .index_fetch_end = opentde_index_fetch_end,
    .index_fetch_tuple = opentde_index_fetch_tuple,
    .tuple_fetch_row_version = opentde_tuple_fetch_row_version,
    .tuple_tid_valid = opentde_tuple_tid_valid,
    .tuple_get_latest_tid = opentde_tuple_get_latest_tid,
    .tuple_satisfies_snapshot = opentde_tuple_satisfies_snapshot,
    .index_delete_tuples = opentde_index_delete_tuples,
    .tuple_insert = opentde_tuple_insert,
    .tuple_insert_speculative = opentde_tuple_insert_speculative,
    .tuple_complete_speculative = opentde_tuple_complete_speculative,
    .multi_insert = opentde_multi_insert,
    .tuple_delete = opentde_tuple_delete,
    .tuple_update = opentde_tuple_update,
    .tuple_lock = opentde_tuple_lock,
    .finish_bulk_insert = opentde_finish_bulk_insert,
    .relation_set_new_filelocator = opentde_relation_set_new_filelocator,
    .relation_nontransactional_truncate = opentde_relation_nontransactional_truncate,
    .relation_copy_data = opentde_relation_copy_data,
    .relation_copy_for_cluster = opentde_relation_copy_for_cluster,
    .relation_vacuum = opentde_relation_vacuum,
    .scan_analyze_next_block = opentde_scan_analyze_next_block,
    .scan_analyze_next_tuple = opentde_scan_analyze_next_tuple,
    .index_build_range_scan = opentde_index_build_range_scan,
    .index_validate_scan = opentde_index_validate_scan,
    .relation_size = opentde_relation_size,
    .relation_needs_toast_table = opentde_relation_needs_toast_table,
    .relation_toast_am = opentde_relation_toast_am,
    .relation_fetch_toast_slice = opentde_relation_fetch_toast_slice,
    .relation_estimate_size = opentde_relation_estimate_size,
    .scan_bitmap_next_tuple = opentde_scan_bitmap_next_tuple,
    .scan_sample_next_block = opentde_scan_sample_next_block,
    .scan_sample_next_tuple = opentde_scan_sample_next_tuple,
};

Datum
opentde_pageam_handler(PG_FUNCTION_ARGS)
{
    /* elog(LOG, "OpenTDE: opentde_pageam_handler called"); */
    PG_RETURN_POINTER(&opentde_minimal_tableam);
}
