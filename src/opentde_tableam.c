/*
 * opentde_tableam.c — Реализация Table Access Method (AM) для OpenTDE.
 *
 * Это главный файл расширения: содержит PG_MODULE_MAGIC, _PG_init
 * и все callback-функции Table AM API PostgreSQL.
 *
 * Стратегия: копируем все методы из стандартного heap AM (memcpy),
 * затем подменяем те, которым нужна криптография:
 *
 *   tuple_insert          — вставка с шифрованием payload
 *   tuple_update          — обновление с шифрованием нового кортежа
 *   multi_insert          — массовая вставка (COPY) с шифрованием
 *   scan_getnextslot      — последовательное чтение с дешифрованием
 *   relation_toast_am     — TOAST-таблица создаётся как обычная heap
 *   index_build_range_scan — построение индекса с дешифрованием
 *   index_fetch_tuple     — извлечение по индексу с дешифрованием
 *
 * Все остальные методы (tuple_delete, vacuum, analyze и т.д.) делегируются
 * стандартному heap AM без изменений.
 */
#include "opentde.h"

#include "catalog/pg_am_d.h"   /* HEAP_TABLE_AM_OID */
#include "catalog/index.h"     /* IndexInfo, FormIndexDatum */
#include "utils/snapmgr.h"    /* RegisterSnapshot, UnregisterSnapshot */
#include "miscadmin.h"         /* CHECK_FOR_INTERRUPTS */

#include <string.h>

PG_MODULE_MAGIC;

/* =====================================================================
 * Статическая таблица методов AM — инициализируется в _PG_init()
 * ===================================================================== */
static TableAmRoutine opentde_tableam_methods;

/* =====================================================================
 * Прототипы внутренних callback-функций
 * ===================================================================== */
static void opentde_tuple_insert(Relation relation, TupleTableSlot *slot,
                                 CommandId cid, int options,
                                 BulkInsertState bistate);
static TM_Result opentde_tuple_update(Relation relation, ItemPointer otid,
                                      TupleTableSlot *slot, CommandId cid,
                                      Snapshot snapshot, Snapshot crosscheck,
                                      bool wait, TM_FailureData *tmfd,
                                      LockTupleMode *lockmode,
                                      TU_UpdateIndexes *update_indexes);
static void opentde_multi_insert(Relation relation, TupleTableSlot **slots,
                                 int nslots, CommandId cid, int options,
                                 BulkInsertState bistate);
static bool opentde_scan_getnextslot(TableScanDesc sscan,
                                     ScanDirection direction,
                                     TupleTableSlot *slot);
static Oid  opentde_relation_toast_am(Relation rel);
static double opentde_index_build_range_scan(Relation heapRelation,
                                             Relation indexRelation,
                                             struct IndexInfo *indexInfo,
                                             bool allow_sync,
                                             bool anyvisible,
                                             bool progress,
                                             BlockNumber start_blockno,
                                             BlockNumber numblocks,
                                             IndexBuildCallback callback,
                                             void *callback_state,
                                             TableScanDesc scan);
static bool opentde_index_fetch_tuple(struct IndexFetchTableData *scan,
                                      ItemPointer tid,
                                      Snapshot snapshot,
                                      TupleTableSlot *slot,
                                      bool *call_again, bool *all_dead);

/* =====================================================================
 * INSERT — вставка одного кортежа
 *
 * Алгоритм:
 *   1. Материализуем кортеж из слота (ExecFetchSlotHeapTuple)
 *   2. Вызываем стандартный heap_insert (handles TOAST, xmin, WAL)
 *   3. Шифруем payload прямо в буферной странице
 *   4. Регистрируем IV для нового TID
 * ===================================================================== */
static void
opentde_tuple_insert(Relation relation,
                     TupleTableSlot *slot,
                     CommandId cid,
                     int options,
                     BulkInsertState bistate)
{
    bool      should_free;
    HeapTuple tuple;
    Oid       table_oid;
    uint8_t   row_iv[DATA_IV_SIZE];
    int       payload_len;

    table_oid = RelationGetRelid(relation);
    elog(DEBUG1, "[OpenTDE] Encrypting INSERT for table %u", table_oid);

    tuple = ExecFetchSlotHeapTuple(slot, true, &should_free);
    if (!tuple)
        return;

    /*
     * Сначала вставляем открытый кортеж — heap обрабатывает TOAST,
     * проставляет xmin/cmin, пишет WAL и т.д.
     * Затем шифруем payload на буферной странице до того,
     * как другой бэкенд сможет увидеть закоммиченные данные.
     */
    heap_insert(relation, tuple, cid, options, bistate);

    if (!ItemPointerIsValid(&tuple->t_self))
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("heap insert did not produce a valid tuple TID")));

    /* Шифрование payload в буферной странице */
    payload_len = opentde_encrypt_in_buffer(relation, table_oid,
                                            &tuple->t_self, row_iv);
    if (payload_len > 0)
        opentde_register_tuple_iv(table_oid, &tuple->t_self, row_iv);

    slot->tts_tid = tuple->t_self;

    if (should_free)
        heap_freetuple(tuple);
}

/* =====================================================================
 * UPDATE — обновление кортежа
 *
 * Аналогично INSERT: heap_update создаёт новую версию кортежа,
 * затем мы шифруем payload новой версии и регистрируем для неё IV.
 * Старая версия остаётся зашифрованной (со своим IV).
 * ===================================================================== */
static TM_Result
opentde_tuple_update(Relation relation,
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
    Oid        table_oid;
    uint8_t    row_iv[DATA_IV_SIZE];
    TM_Result  result;
    int        payload_len;

    table_oid = RelationGetRelid(relation);
    elog(DEBUG1, "[OpenTDE] Encrypting UPDATE for table %u", table_oid);

    tuple = ExecFetchSlotHeapTuple(slot, true, &should_free);
    if (!tuple)
        return TM_Invisible;

    /* Проставляем OID таблицы на новой версии (как это делает heapam) */
    slot->tts_tableOid = RelationGetRelid(relation);
    tuple->t_tableOid  = slot->tts_tableOid;

    elog(LOG, "[OpenTDE] tuple_update NEW hoff=%u tlen=%u id_bytes=[%02x %02x %02x %02x]",
        (unsigned) tuple->t_data->t_hoff, (unsigned) tuple->t_len,
        (unsigned char) ((char*)tuple->t_data)[tuple->t_data->t_hoff + 0],
        (unsigned char) ((char*)tuple->t_data)[tuple->t_data->t_hoff + 1],
        (unsigned char) ((char*)tuple->t_data)[tuple->t_data->t_hoff + 2],
        (unsigned char) ((char*)tuple->t_data)[tuple->t_data->t_hoff + 3]);

    /*
     * Вызываем heap_update: создаём новую версию, помечаем старую мёртвой,
     * обрабатываем TOAST, HOT, WAL и т.д.
     */
    result = heap_update(relation, otid, tuple, cid, crosscheck, wait,
                         tmfd, lockmode, update_indexes);

    elog(LOG, "[OpenTDE] heap_update result=%d otid=(%u,%u) new_tid=(%u,%u)",
        (int) result,
        (unsigned) ItemPointerGetBlockNumber(otid),
        (unsigned) ItemPointerGetOffsetNumber(otid),
        (unsigned) ItemPointerGetBlockNumber(&tuple->t_self),
        (unsigned) ItemPointerGetOffsetNumber(&tuple->t_self));

    ItemPointerCopy(&tuple->t_self, &slot->tts_tid);

    if (result == TM_Ok)
    {
        /* Шифруем payload новой версии кортежа */
        payload_len = opentde_encrypt_in_buffer(relation, table_oid,
                                                &tuple->t_self, row_iv);
        if (payload_len > 0)
            opentde_register_tuple_iv(table_oid, &tuple->t_self, row_iv);
    }

    if (should_free)
        heap_freetuple(tuple);

    return result;
}

/* =====================================================================
 * MULTI INSERT — массовая вставка (используется в COPY)
 *
 * Все кортежи сначала вставляются через heap_multi_insert,
 * затем каждый шифруется на своей буферной странице.
 * ===================================================================== */
static void
opentde_multi_insert(Relation relation,
                     TupleTableSlot **slots,
                     int nslots,
                     CommandId cid,
                     int options,
                     BulkInsertState bistate)
{
    Oid table_oid;
    int i;

    table_oid = RelationGetRelid(relation);
    elog(DEBUG1, "[OpenTDE] Encrypting MULTI_INSERT (%d rows) for table %u",
         nslots, table_oid);

    /*
     * Массовая вставка открытых кортежей.
     * После вызова каждый slot->tts_tid содержит TID на диске.
     */
    heap_multi_insert(relation, slots, nslots, cid, options, bistate);

    /* Шифрование каждого кортежа в его буферной странице */
    for (i = 0; i < nslots; i++)
    {
        uint8_t row_iv[DATA_IV_SIZE];
        int     payload_len;

        if (!ItemPointerIsValid(&slots[i]->tts_tid))
            ereport(ERROR,
                    (errcode(ERRCODE_INTERNAL_ERROR),
                     errmsg("heap multi_insert did not set a valid TID for slot %d", i)));

        payload_len = opentde_encrypt_in_buffer(relation, table_oid,
                                                &slots[i]->tts_tid, row_iv);
        if (payload_len > 0)
            opentde_register_tuple_iv(table_oid, &slots[i]->tts_tid, row_iv);
    }
}

/* =====================================================================
 * SEQUENTIAL SCAN — последовательное чтение с дешифрованием
 *
 * Делегирует чтение heap AM, затем:
 *   1. Копирует полученный кортеж (чтобы не менять данные в буфере)
 *   2. Ищет IV по TID
 *   3. Расшифровывает payload копии
 *   4. Возвращает расшифрованный кортеж через слот
 * ===================================================================== */
static bool
opentde_scan_getnextslot(TableScanDesc sscan,
                         ScanDirection direction,
                         TupleTableSlot *slot)
{
    const TableAmRoutine *heap_am;
    bool        found;
    bool        should_free;
    HeapTuple   tuple;
    HeapTuple   decrypted_tuple;
    char       *dec_payload;
    int         dec_len;
    ItemPointerData tid;
    Relation    relation;
    Oid         table_oid;
    uint8_t     row_iv[DATA_IV_SIZE];

    heap_am   = GetHeapamTableAmRoutine();
    relation  = sscan->rs_rd;
    table_oid = RelationGetRelid(relation);

    /* Чтение следующего кортежа стандартным heap-сканом */
    found = heap_am->scan_getnextslot(sscan, direction, slot);
    if (!found)
        return false;

    tuple = ExecFetchSlotHeapTuple(slot, true, &should_free);
    if (!tuple)
        return true;

    /* Создаём рабочую копию для дешифрования (не трогаем буферную страницу) */
    decrypted_tuple = heap_copytuple(tuple);
    decrypted_tuple->t_self = tuple->t_self;
    tid = tuple->t_self;

    dec_payload = (char *) decrypted_tuple->t_data + decrypted_tuple->t_data->t_hoff;
    dec_len = decrypted_tuple->t_len - decrypted_tuple->t_data->t_hoff;

    if (dec_len > 0)
    {
        /* Поиск IV для данного кортежа */
        if (!opentde_lookup_tuple_iv(table_oid, &tid, row_iv))
            ereport(ERROR,
                    (errcode(ERRCODE_INTERNAL_ERROR),
                     errmsg("missing tuple IV for table %u block %u offset %u",
                            table_oid,
                            ItemPointerGetBlockNumber(&tid),
                            ItemPointerGetOffsetNumber(&tid)),
                     errhint("Rows inserted before this fix may need re-encryption.")));

        elog(LOG, "[OpenTDE] scan_decrypt tid=(%u,%u) CIPH first4=[%02x %02x %02x %02x]",
             (unsigned) ItemPointerGetBlockNumber(&tid),
             (unsigned) ItemPointerGetOffsetNumber(&tid),
             (unsigned char) dec_payload[0], (unsigned char) dec_payload[1],
             (unsigned char) dec_payload[2], (unsigned char) dec_payload[3]);

        /* Дешифрование payload (CTR-режим: повторное применение = расшифровка) */
        opentde_gost_encrypt_decrypt(dec_payload, dec_len, table_oid, row_iv);

        elog(LOG, "[OpenTDE] scan_decrypt tid=(%u,%u) PLAIN first4=[%02x %02x %02x %02x]",
             (unsigned) ItemPointerGetBlockNumber(&tid),
             (unsigned) ItemPointerGetOffsetNumber(&tid),
             (unsigned char) dec_payload[0], (unsigned char) dec_payload[1],
             (unsigned char) dec_payload[2], (unsigned char) dec_payload[3]);
    }

    /* Помещаем расшифрованный кортеж обратно в слот */
    ExecForceStoreHeapTuple(decrypted_tuple, slot, true);
    slot->tts_tid = tid;

    if (should_free)
        heap_freetuple(tuple);

    return true;
}

/* =====================================================================
 * TOAST AM — тип метода доступа для TOAST-таблицы
 *
 * Возвращаем HEAP_TABLE_AM_OID (=2), чтобы TOAST-таблица создавалась
 * как обычная heap-таблица. Это необходимо, потому что PG при создании
 * TOAST-таблицы использует AM родительской таблицы, а мы не хотим
 * шифровать TOAST-данные (и heap_getnext проверяет тип AM).
 * ===================================================================== */
static Oid
opentde_relation_toast_am(Relation rel)
{
    return HEAP_TABLE_AM_OID;
}

/* =====================================================================
 * INDEX FETCH — извлечение кортежа по индексу (Index Scan / Bitmap Scan)
 *
 * При Index Scan PostgreSQL вызывает index_fetch_tuple для получения
 * кортежа по TID из индексной записи. Стандартный heap возвращает
 * зашифрованные данные — мы дешифруем их перед возвратом.
 * ===================================================================== */
static bool
opentde_index_fetch_tuple(struct IndexFetchTableData *scan,
                          ItemPointer tid,
                          Snapshot snapshot,
                          TupleTableSlot *slot,
                          bool *call_again, bool *all_dead)
{
    const TableAmRoutine *heap_am;
    bool        found;
    bool        should_free;
    HeapTuple   tuple;
    HeapTuple   decrypted;
    Oid         table_oid;
    char       *payload;
    int         payload_len;
    uint8_t     row_iv[DATA_IV_SIZE];
    ItemPointerData saved_tid;

    /* Делегируем чтение heap AM */
    heap_am = GetHeapamTableAmRoutine();
    found = heap_am->index_fetch_tuple(scan, tid, snapshot, slot,
                                       call_again, all_dead);
    if (!found)
        return false;

    table_oid = RelationGetRelid(scan->rel);
    saved_tid = slot->tts_tid;

    tuple = ExecFetchSlotHeapTuple(slot, true, &should_free);
    if (!tuple)
        return true;

    /* Рабочая копия для дешифрования */
    decrypted = heap_copytuple(tuple);
    decrypted->t_self = tuple->t_self;

    payload     = (char *) decrypted->t_data + decrypted->t_data->t_hoff;
    payload_len = decrypted->t_len - decrypted->t_data->t_hoff;

    if (payload_len > 0)
    {
        if (!opentde_lookup_tuple_iv(table_oid, &decrypted->t_self, row_iv))
            ereport(ERROR,
                    (errcode(ERRCODE_INTERNAL_ERROR),
                     errmsg("missing tuple IV for table %u block %u offset %u",
                            table_oid,
                            ItemPointerGetBlockNumber(&decrypted->t_self),
                            ItemPointerGetOffsetNumber(&decrypted->t_self))));

        opentde_gost_encrypt_decrypt(payload, payload_len, table_oid, row_iv);
    }

    ExecForceStoreHeapTuple(decrypted, slot, true);
    slot->tts_tid = saved_tid;

    if (should_free)
        heap_freetuple(tuple);

    return true;
}

/* =====================================================================
 * INDEX BUILD — сканирование таблицы при построении индекса (CREATE INDEX)
 *
 * Стандартный heap AM при CREATE INDEX вызывает heap_getnext напрямую
 * (минуя Table AM API), поэтому мы не можем использовать heap-реализацию.
 * Вместо этого открываем свой скан и используем opentde_scan_getnextslot,
 * который расшифровывает кортежи — чтобы индексные выражения
 * вычислялись на открытых данных.
 * ===================================================================== */
static double
opentde_index_build_range_scan(Relation heapRelation,
                               Relation indexRelation,
                               struct IndexInfo *indexInfo,
                               bool allow_sync,
                               bool anyvisible,
                               bool progress,
                               BlockNumber start_blockno,
                               BlockNumber numblocks,
                               IndexBuildCallback callback,
                               void *callback_state,
                               TableScanDesc scan)
{
    Snapshot        snapshot;
    bool            need_unregister_snapshot = false;
    double          reltuples = 0;
    EState         *estate;
    ExprContext    *econtext;
    ExprState      *predicate;
    TupleTableSlot *slot;
    Datum           values[INDEX_MAX_KEYS];
    bool            isnull[INDEX_MAX_KEYS];

    /*
     * Параллельное построение индекса передаёт готовый scan-дескриптор.
     * Пока не поддерживаем — делегируем heap AM с временной подменой AM.
     */
    if (scan != NULL)
    {
        const TableAmRoutine *heap_am = GetHeapamTableAmRoutine();
        const TableAmRoutine *saved = heapRelation->rd_tableam;
        double result;

        heapRelation->rd_tableam = heap_am;
        result = heap_am->index_build_range_scan(heapRelation, indexRelation,
                    indexInfo, allow_sync, anyvisible, progress,
                    start_blockno, numblocks, callback, callback_state, scan);
        heapRelation->rd_tableam = saved;
        return result;
    }

    /* Подготовка состояния для вычисления индексных выражений */
    estate    = CreateExecutorState();
    econtext  = GetPerTupleExprContext(estate);
    slot      = table_slot_create(heapRelation, NULL);
    econtext->ecxt_scantuple = slot;
    predicate = ExecPrepareQual(indexInfo->ii_Predicate, estate);

    /* Создаём snapshot и начинаем последовательный скан */
    snapshot = RegisterSnapshot(GetTransactionSnapshot());
    need_unregister_snapshot = true;

    scan = table_beginscan_strat(heapRelation, snapshot, 0, NULL,
                                 true, allow_sync);

    /*
     * Основной цикл: читаем расшифрованные кортежи через наш scan,
     * вычисляем индексные атрибуты, передаём callback-у для вставки
     * в индекс.
     */
    while (opentde_scan_getnextslot(scan, ForwardScanDirection, slot))
    {
        CHECK_FOR_INTERRUPTS();
        MemoryContextReset(econtext->ecxt_per_tuple_memory);

        /* Проверка предиката частичного индекса */
        if (predicate != NULL && !ExecQual(predicate, econtext))
            continue;

        /* Формирование значений индексных столбцов и вставка в индекс */
        FormIndexDatum(indexInfo, slot, estate, values, isnull);
        callback(indexRelation, &slot->tts_tid, values, isnull, true,
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

/* =====================================================================
 * Table AM Handler — точка входа PostgreSQL
 *
 * Возвращает указатель на таблицу методов (TableAmRoutine).
 * Вызывается при CREATE ACCESS METHOD ... HANDLER opentde_tableam_handler.
 * ===================================================================== */
PG_FUNCTION_INFO_V1(opentde_tableam_handler);

Datum
opentde_tableam_handler(PG_FUNCTION_ARGS)
{
    PG_RETURN_POINTER(&opentde_tableam_methods);
}

/* =====================================================================
 * _PG_init — инициализация расширения при загрузке
 *
 * Выполняется один раз при старте каждого бэкенда PostgreSQL.
 *
 * Алгоритм:
 *   1. Получаем указатель на стандартный heap AM
 *   2. Копируем все его методы в нашу таблицу (memcpy)
 *   3. Подменяем нужные callback-и на свои реализации
 *   4. Инициализируем менеджер ключей
 *   5. Пытаемся автоматически загрузить мастер-ключ из файла
 *   6. Если ключ загружен — загружаем DEK и IV
 * ===================================================================== */
void
_PG_init(void)
{
    const TableAmRoutine *heap_am;

    /* Копируем все методы heap AM как базу */
    heap_am = GetHeapamTableAmRoutine();
    memcpy(&opentde_tableam_methods, heap_am, sizeof(TableAmRoutine));

    opentde_tableam_methods.type = T_TableAmRoutine;

    /* Подмена callback-ов шифрующими версиями */
    opentde_tableam_methods.tuple_insert          = opentde_tuple_insert;
    opentde_tableam_methods.tuple_update          = opentde_tuple_update;
    opentde_tableam_methods.multi_insert          = opentde_multi_insert;
    opentde_tableam_methods.scan_getnextslot      = opentde_scan_getnextslot;
    opentde_tableam_methods.relation_toast_am     = opentde_relation_toast_am;
    opentde_tableam_methods.index_build_range_scan = opentde_index_build_range_scan;
    opentde_tableam_methods.index_fetch_tuple     = opentde_index_fetch_tuple;

    /* Инициализация менеджера ключей */
    opentde_init_key_manager();
    elog(LOG, "[OpenTDE] Extension loaded");

    /* Автозагрузка мастер-ключа, DEK и IV из файлов */
    if (opentde_load_master_key_from_file())
    {
        opentde_load_key_file();
        elog(LOG, "[OpenTDE] Auto-loaded %d keys", global_key_mgr->key_count);
    }

    opentde_load_iv_file();
}
