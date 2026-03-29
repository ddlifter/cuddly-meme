
#include "postgres.h"
#include "fmgr.h"

#include "access/tableam.h"
#include "executor/tuptable.h"
#include "access/transam.h"
#include "access/multixact.h"

PG_FUNCTION_INFO_V1(opentde_pageam_handler);

typedef struct opentde_tableam_scan {
    Relation rel;
    bool done;
} opentde_tableam_scan;

static const TupleTableSlotOps *opentde_slot_callbacks(Relation rel) {
    return &TTSOpsHeapTuple;
}

static TableScanDesc opentde_scan_begin(Relation rel, Snapshot snapshot, int nkeys, ScanKey key, ParallelTableScanDesc pscan, uint32_t flags) {
    opentde_tableam_scan *scan = palloc0(sizeof(opentde_tableam_scan));
    scan->rel = rel;
    scan->done = false;
    return (TableScanDesc)scan;
}

static void opentde_scan_end(TableScanDesc scan) {
    pfree(scan);
}

static bool opentde_scan_getnextslot(TableScanDesc scan, ScanDirection direction, TupleTableSlot *slot) {
    opentde_tableam_scan *s = (opentde_tableam_scan *)scan;
    if (s->done) return false;
    s->done = true;
    ExecClearTuple(slot);
    slot->tts_tupleDescriptor = s->rel->rd_att;
    // Minimal stub: always return empty slot
    return false;
}

static const TableAmRoutine opentde_minimal_tableam = {
    .type = T_TableAmRoutine,
    .slot_callbacks = opentde_slot_callbacks,
    .scan_begin = opentde_scan_begin,
    .scan_end = opentde_scan_end,
    .scan_rescan = NULL,
    .scan_getnextslot = opentde_scan_getnextslot,
    .scan_set_tidrange = NULL,
    .scan_getnextslot_tidrange = NULL,
    .parallelscan_estimate = NULL,
    .parallelscan_initialize = NULL,
    .parallelscan_reinitialize = NULL,
    .index_fetch_begin = NULL,
    .index_fetch_reset = NULL,
    .index_fetch_end = NULL,
    .index_fetch_tuple = NULL,
    .tuple_fetch_row_version = NULL,
    .tuple_tid_valid = NULL,
    .tuple_get_latest_tid = NULL,
    .tuple_satisfies_snapshot = NULL,
    .index_delete_tuples = NULL,
    .tuple_insert = NULL,
    .tuple_insert_speculative = NULL,
    .tuple_complete_speculative = NULL,
    .multi_insert = NULL,
    .tuple_delete = NULL,
    .tuple_update = NULL,
    .tuple_lock = NULL,
    .finish_bulk_insert = NULL,
    .relation_set_new_filelocator = NULL,
    .relation_nontransactional_truncate = NULL,
    .relation_copy_data = NULL,
    .relation_copy_for_cluster = NULL,
    .relation_vacuum = NULL,
    .scan_analyze_next_block = NULL,
    .scan_analyze_next_tuple = NULL,
    .index_build_range_scan = NULL,
    .index_validate_scan = NULL,
    .relation_size = NULL,
    .relation_needs_toast_table = NULL,
    .relation_toast_am = NULL,
    .relation_fetch_toast_slice = NULL,
    .relation_estimate_size = NULL,
    .scan_bitmap_next_tuple = NULL,
    .scan_sample_next_block = NULL,
    .scan_sample_next_tuple = NULL,
};

Datum
opentde_pageam_handler(PG_FUNCTION_ARGS)
{
    PG_RETURN_POINTER(&opentde_minimal_tableam);
}
