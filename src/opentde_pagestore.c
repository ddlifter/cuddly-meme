#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "postgres.h"
#include "opentde_pagestore.h"
#include "access/htup_details.h"
#include "utils/elog.h"
#include "utils/memutils.h"
#include "storage/fd.h"
#include "storage/lwlock.h"
#include "catalog/pg_type.h"
#include "miscadmin.h"
#include "opentde.h"

#define OPENTDE_PAGE_MAXSIZE 8192

#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "postgres.h"
#include "opentde_pagestore.h"
#include "access/htup_details.h"
#include "utils/elog.h"
#include "utils/memutils.h"
#include "storage/fd.h"
#include "storage/lwlock.h"
#include "catalog/pg_type.h"
#include "miscadmin.h"
#include "opentde.h"

/* --- Static helper stubs (implementations to be filled in as needed) --- */

static char *opentde_pagestore_get_dir(void)
{
    char *pgdata = opentde_get_pgdata_path();
    return psprintf("%s/pg_encryption/pages", pgdata);
}

char *opentde_pagestore_get_file_path(Oid table_oid)
{
    char *dir = opentde_pagestore_get_dir();
    return psprintf("%s/%u.ps", dir, table_oid);
}

static char *opentde_pagestore_get_journal_path(Oid table_oid)
{
    char *dir = opentde_pagestore_get_dir();
    return psprintf("%s/%u.psj", dir, table_oid);
}

void opentde_pagestore_ensure_dir(void)
{
    char *dir = opentde_pagestore_get_dir();
    struct stat st;
    if (stat(dir, &st) != 0)
    {
        mkdir(dir, 0700);
    }
    pfree(dir);
}

static void opentde_pagestore_lock_fd(int fd, int locktype) { /* stub */ }
static void opentde_pagestore_unlock_fd(int fd) { /* stub */ }
static void opentde_pagestore_write_journal(Oid table_oid, uint32_t blockno, uint8_t *blob, uint32_t blob_len) { /* stub */ }
static void opentde_pagestore_append_raw_record(int fd, uint32_t blockno, uint8_t *blob, uint32_t blob_len)
{
    // Write record header
    opentde_pagestore_record_header rec_hdr;
    rec_hdr.blockno = blockno;
    rec_hdr.blob_len = blob_len;
    ssize_t written = write(fd, &rec_hdr, sizeof(rec_hdr));
    if (written != sizeof(rec_hdr)) {
        elog(WARNING, "OpenTDE: failed to write record header");
        return;
    }
    // Write blob if present
    if (blob_len > 0 && blob != NULL) {
        written = write(fd, blob, blob_len);
        if (written != (ssize_t)blob_len) {
            elog(WARNING, "OpenTDE: failed to write blob");
            return;
        }
    }
}
static void opentde_pagestore_fsync_fd(int fd, const char *desc) { /* stub */ }
static void opentde_pagestore_clear_journal(Oid table_oid) { /* stub */ }
static void opentde_pagestore_replay_journal_if_needed(int fd, Oid table_oid, opentde_pagestore_header *hdr) { /* stub */ }
static int opentde_page_blob_encrypt(Oid table_oid, BlockNumber blockno, uint8_t *plain, uint32_t plain_len, uint8_t **blob_out, uint32_t *blob_len_out)
{
    /* elog(LOG, "OpenTDE: page_blob_encrypt (real): table_oid=%u blockno=%u plain_len=%u", table_oid, blockno, plain_len); */
    if (!plain || plain_len == 0 || !blob_out || !blob_len_out) {
        /* elog(LOG, "OpenTDE: page_blob_encrypt: invalid input, returning 0"); */
        return 0;
    }
    /* Получаем DEK и IV для страницы (offset=0) */
    uint8_t *dek = opentde_get_table_dek(table_oid);
    uint8_t iv[DATA_IV_SIZE];
    uint32_t key_version = DEFAULT_DEK_VERSION;
    memset(iv, 0, DATA_IV_SIZE);
    memcpy(iv, &blockno, sizeof(blockno));
    *blob_out = (uint8_t *) palloc(plain_len);
    memcpy(*blob_out, plain, plain_len);
    opentde_gost_encrypt_decrypt((char *)*blob_out, plain_len, table_oid, key_version, iv);
    *blob_len_out = plain_len;
    /* elog(LOG, "OpenTDE: page_blob_encrypt: encrypted %u bytes (page-level)", plain_len); */
    return 1;
}
static int opentde_page_blob_decrypt(Oid table_oid, BlockNumber blockno, uint8_t *blob, uint32_t blob_len, uint8_t **plain_out, uint32_t *plain_len_out, void *unused)
{
    if (!blob || blob_len == 0 || !plain_out || !plain_len_out)
        return 0;
    *plain_out = (uint8_t *) palloc(blob_len);
    memcpy(*plain_out, blob, blob_len);
    /* Получаем DEK и IV для страницы (offset=0) */
    uint8_t *dek = opentde_get_table_dek(table_oid);
    uint8_t iv[DATA_IV_SIZE];
    uint32_t key_version = DEFAULT_DEK_VERSION;
    memset(iv, 0, DATA_IV_SIZE);
    memcpy(iv, &blockno, sizeof(blockno));
    opentde_gost_encrypt_decrypt((char *)*plain_out, blob_len, table_oid, key_version, iv);
    *plain_len_out = blob_len;
    return 1;
}

/* --- End static helpers --- */

static void
opentde_pagestore_write_header(int fd, const opentde_pagestore_header *hdr)
{
    if (pwrite(fd, hdr, sizeof(*hdr), 0) != sizeof(*hdr))
        ereport(ERROR,
                (errcode_for_file_access(),
                 errmsg("cannot write page store header")));
}

static void
opentde_pagestore_read_or_init_header(int fd, opentde_pagestore_header *hdr)
{
    struct stat st;

    if (fstat(fd, &st) != 0)
        ereport(ERROR,
                (errcode_for_file_access(),
                 errmsg("cannot stat page store file")));

    if ((size_t) st.st_size < sizeof(*hdr))
    {
        memset(hdr, 0, sizeof(*hdr));
        hdr->magic = OPENTDE_PAGESTORE_MAGIC;
        hdr->version = OPENTDE_PAGESTORE_VERSION;
        hdr->record_count = 0;
        opentde_pagestore_write_header(fd, hdr);
        return;
    }

    if (pread(fd, hdr, sizeof(*hdr), 0) != sizeof(*hdr))
        ereport(ERROR,
                (errcode_for_file_access(),
                 errmsg("cannot read page store header")));

    if (hdr->magic != OPENTDE_PAGESTORE_MAGIC ||
        hdr->version != OPENTDE_PAGESTORE_VERSION)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_CORRUPTED),
                 errmsg("invalid page store header")));
}

static bool
opentde_pagestore_append_tuple_internal(Oid table_oid,
                                        HeapTuple tuple,
                                        BlockNumber blockno,
                                        bool use_explicit_blockno,
                                        bool delete_marker,
                                        ItemPointerData *tid_out)
{
    char                        *path;
    int                          fd;
    opentde_pagestore_header     hdr;
    uint8_t                     *blob = NULL;
    uint8_t                     *plain_copy = NULL;
    uint32_t                     blob_len = 0;
    uint32_t                     stored_blockno;

    /* elog(LOG, "OpenTDE: append_tuple_internal: table_oid=%u use_explicit_blockno=%d blockno=%u delete_marker=%d", table_oid, use_explicit_blockno, blockno, delete_marker); */

    if (!delete_marker && (!tuple || tuple->t_len <= 0))
        return false;

    opentde_pagestore_ensure_dir();
    path = opentde_pagestore_get_file_path(table_oid);

    /* Try to open file, create if missing, and initialize header if new */
    fd = open(path, O_RDWR | O_CREAT | PG_BINARY, 0600);
    if (fd < 0)
    {
        pfree(path);
        ereport(ERROR,
                (errcode_for_file_access(),
                 errmsg("cannot open page store file %s", path)));
    }

    opentde_pagestore_lock_fd(fd, F_WRLCK);

    /* Check if file is new (size == 0), and initialize header if so */
    struct stat st;
    if (fstat(fd, &st) == 0 && st.st_size == 0) {
        memset(&hdr, 0, sizeof(hdr));
        hdr.magic = OPENTDE_PAGESTORE_MAGIC;
        hdr.version = OPENTDE_PAGESTORE_VERSION;
        hdr.record_count = 0;
        pwrite(fd, &hdr, sizeof(hdr), 0);
        /* elog(LOG, "OpenTDE: pagestore file created and header initialized for table_oid=%u", table_oid); */
    }

    opentde_pagestore_read_or_init_header(fd, &hdr);
    opentde_pagestore_replay_journal_if_needed(fd, table_oid, &hdr);

    /* elog(LOG, "OpenTDE: append_tuple_internal: before write, record_count=%u", hdr.record_count); */

    /* Гарантируем валидный stored_blockno */
    if (use_explicit_blockno && blockno != InvalidBlockNumber)
        stored_blockno = (uint32_t) blockno;
    else
        stored_blockno = hdr.record_count;

    if (stored_blockno == InvalidBlockNumber) {
        elog(ERROR, "OpenTDE: append_tuple_internal: stored_blockno is InvalidBlockNumber! blockno=%u use_explicit_blockno=%d hdr.record_count=%u", blockno, use_explicit_blockno, hdr.record_count);
        opentde_pagestore_unlock_fd(fd);
        close(fd);
        pfree(path);
        return false;
    }

    if (!delete_marker)
    {
        plain_copy = (uint8_t *) palloc((Size) tuple->t_len);
        memcpy(plain_copy, tuple->t_data, (Size) tuple->t_len);
        ItemPointerSet(&((HeapTupleHeader) plain_copy)->t_ctid,
                   stored_blockno,
                   FirstOffsetNumber);

        /* elog(LOG, "OpenTDE: about to call page_blob_encrypt: t_len=%u", (uint32_t)tuple->t_len); */
        /* page-level TDE: передаём корректный page_tid (offset=0) */
        int enc_ret = opentde_page_blob_encrypt(table_oid,
                                       (BlockNumber) stored_blockno,
                                       plain_copy,
                                       (uint32_t) tuple->t_len,
                                       &blob,
                                       &blob_len);
        /* elog(LOG, "OpenTDE: page_blob_encrypt returned %d, blob_len=%u", enc_ret, blob_len); */
        if (!enc_ret)
        {
            pfree(plain_copy);
            opentde_pagestore_unlock_fd(fd);
            close(fd);
            pfree(path);
            return false;
        }

        pfree(plain_copy);
        plain_copy = NULL;
    }

    if (delete_marker)
        blob_len = 0;

    opentde_pagestore_write_journal(table_oid, stored_blockno, blob, blob_len);
    opentde_pagestore_append_raw_record(fd, stored_blockno, blob, blob_len);
    /* Immediate write: no batch buffer, flush after each record */
    opentde_pagestore_fsync_fd(fd, "page store file");

    if (stored_blockno >= hdr.record_count) {
        hdr.record_count = stored_blockno + 1;
        /* elog(LOG, "OpenTDE: append_tuple_internal: updated record_count=%u", hdr.record_count); */
    }
    opentde_pagestore_write_header(fd, &hdr);
    opentde_pagestore_fsync_fd(fd, "page store file header");
    opentde_pagestore_clear_journal(table_oid);

    if (tid_out)
        ItemPointerSet(tid_out, stored_blockno, FirstOffsetNumber);

    if (blob)
        pfree(blob);
    if (plain_copy)
        pfree(plain_copy);
    opentde_pagestore_unlock_fd(fd);
    close(fd);
    pfree(path);
    return true;
}

void
opentde_pagestore_append_tuple(Oid table_oid,
                               HeapTuple tuple,
                               ItemPointer tid_out)
{
    /* Batch append: (disabled, immediate write for correctness) */
    /* elog(LOG, "OpenTDE: append_tuple table_oid=%u tuple=%p t_len=%d", table_oid, tuple, tuple ? (int)tuple->t_len : -1); */
    ItemPointerData tmp_tid;
    if (tid_out == NULL)
        tid_out = &tmp_tid;
    (void)opentde_pagestore_append_tuple_internal(table_oid,
                                                 tuple,
                                                 InvalidBlockNumber,
                                                 false,
                                                 false,
                                                 tid_out);
}

bool
opentde_pagestore_update_tuple(Oid table_oid,
                               BlockNumber blockno,
                               HeapTuple tuple,
                               ItemPointerData *tid_out)
{
    return opentde_pagestore_append_tuple_internal(table_oid,
                                                   tuple,
                                                   blockno,
                                                   true,
                                                   false,
                                                   tid_out);
}

bool
opentde_pagestore_delete_tuple(Oid table_oid,
                               BlockNumber blockno)
{
    return opentde_pagestore_append_tuple_internal(table_oid,
                                                   NULL,
                                                   blockno,
                                                   true,
                                                   true,
                                                   NULL);
}

static bool
opentde_pagestore_find_latest_record(int fd,
                                     uint32_t target_blockno,
                                     uint64_t *blob_offset_out,
                                     uint32_t *blob_len_out,
                                     bool *deleted_out)
{
    uint64_t                       off;
    struct stat                    st;
    opentde_pagestore_record_header rec_hdr;
    bool                           found;
    uint64_t                       latest_blob_off;
    uint32_t                       latest_blob_len;
    bool                           latest_deleted;

    if (fstat(fd, &st) != 0)
        return false;

    off = sizeof(opentde_pagestore_header);
    found = false;
    latest_blob_off = 0;
    latest_blob_len = 0;
    latest_deleted = false;

    while (off + sizeof(rec_hdr) <= (uint64_t) st.st_size)
    {
        if (pread(fd, &rec_hdr, sizeof(rec_hdr), (off_t) off) != sizeof(rec_hdr))
            return false;

        off += sizeof(rec_hdr);
        if (off + rec_hdr.blob_len > (uint64_t) st.st_size)
            return false;

        if (rec_hdr.blockno == target_blockno)
        {
            found = true;
            latest_blob_off = off;
            latest_blob_len = rec_hdr.blob_len;
            latest_deleted = (rec_hdr.blob_len == 0);
        }

        off += rec_hdr.blob_len;
    }

    if (!found)
        return false;

    if (blob_offset_out)
        *blob_offset_out = latest_blob_off;
    if (blob_len_out)
        *blob_len_out = latest_blob_len;
    if (deleted_out)
        *deleted_out = latest_deleted;

    return true;
}

bool
opentde_pagestore_fetch_latest(Oid table_oid,
                               BlockNumber blockno,
                               HeapTuple *tuple_out)
{
    char     *path;
    int       fd;
    uint64_t  blob_off;
    uint32_t  blob_len;
    bool      deleted;
    uint8_t  *blob;
    uint8_t  *plain = NULL;
    uint32_t  plain_len = 0;
    HeapTuple tuple;
    opentde_pagestore_header hdr;

    if (!tuple_out)
        return false;

    path = opentde_pagestore_get_file_path(table_oid);
    fd = open(path, O_RDWR | PG_BINARY, 0600);
    pfree(path);

    if (fd < 0)
        return false;

    opentde_pagestore_lock_fd(fd, F_WRLCK);

    opentde_pagestore_read_or_init_header(fd, &hdr);
    opentde_pagestore_replay_journal_if_needed(fd, table_oid, &hdr);

    if (!opentde_pagestore_find_latest_record(fd, (uint32_t) blockno,
                                              &blob_off, &blob_len, &deleted))
    {
        opentde_pagestore_unlock_fd(fd);
        close(fd);
        return false;
    }

    if (deleted)
    {
        opentde_pagestore_unlock_fd(fd);
        close(fd);
        return false;
    }

    blob = (uint8_t *) palloc(blob_len);
    if (pread(fd, blob, blob_len, (off_t) blob_off) != (ssize_t) blob_len)
    {
        pfree(blob);
        opentde_pagestore_unlock_fd(fd);
        close(fd);
        return false;
    }

    if (!opentde_page_blob_decrypt(table_oid,
                                   blockno,
                                   blob,
                                   blob_len,
                                   &plain,
                                   &plain_len,
                                   NULL))
    {
        pfree(blob);
        opentde_pagestore_unlock_fd(fd);
        close(fd);
        return false;
    }

    tuple = (HeapTuple) palloc0(sizeof(HeapTupleData));
    tuple->t_data = (HeapTupleHeader) plain;
    tuple->t_len = plain_len;
    tuple->t_tableOid = table_oid;
    ItemPointerSet(&tuple->t_data->t_ctid, blockno, FirstOffsetNumber);
    ItemPointerSet(&tuple->t_self, blockno, FirstOffsetNumber);

    *tuple_out = tuple;

    pfree(blob);
    opentde_pagestore_unlock_fd(fd);
    close(fd);
    return true;
}

bool
opentde_pagestore_scan_open(Oid table_oid, opentde_pagestore_scan *scan)
{
    char                    *path;
    int                      fd;
    opentde_pagestore_header hdr;
    struct stat              st;
    uint64_t                 off;
    uint32_t                 max_blockno;
    opentde_pagestore_row_state *rows;
    opentde_pagestore_record_header rec_hdr;

    /* elog(LOG, "OpenTDE: scan_open: table_oid=%u", table_oid); */

    if (!scan)
        return false;

    memset(scan, 0, sizeof(*scan));

    path = opentde_pagestore_get_file_path(table_oid);
    fd = open(path, O_RDWR | PG_BINARY, 0600);
    pfree(path);

    if (fd < 0)
        return false;

    opentde_pagestore_lock_fd(fd, F_WRLCK);

    opentde_pagestore_read_or_init_header(fd, &hdr);
    opentde_pagestore_replay_journal_if_needed(fd, table_oid, &hdr);

    if (fstat(fd, &st) != 0)
    {
        close(fd);
        return false;
    }

    max_blockno = 0;
    off = sizeof(opentde_pagestore_header);
    uint32_t record_counter = 0;
    while (off + sizeof(rec_hdr) <= (uint64_t) st.st_size)
    {
        /* elog(LOG, "OpenTDE: scan_open: reading header at offset=%lu", (unsigned long)off); */
        if (pread(fd, &rec_hdr, sizeof(rec_hdr), (off_t) off) != sizeof(rec_hdr))
        {
            elog(WARNING, "OpenTDE: scan_open: failed to read record header at offset=%lu", (unsigned long)off);
            close(fd);
            return false;
        }
        /* elog(LOG, "OpenTDE: scan_open: got header blockno=%u blob_len=%u", rec_hdr.blockno, rec_hdr.blob_len); */

        off += sizeof(rec_hdr);
        if (off + rec_hdr.blob_len > (uint64_t) st.st_size)
        {
            elog(WARNING, "OpenTDE: scan_open: blob_len out of bounds at offset=%lu", (unsigned long)off);
            close(fd);
            return false;
        }

        if (rec_hdr.blockno > max_blockno)
            max_blockno = rec_hdr.blockno;
        record_counter++;
        off += rec_hdr.blob_len;
    }
    /* elog(LOG, "OpenTDE: scan_open: found %u records, max_blockno=%u", record_counter, max_blockno); */

    rows = NULL;
    if (off > sizeof(opentde_pagestore_header))
        rows = (opentde_pagestore_row_state *) palloc0(((size_t) max_blockno + 1) * sizeof(*rows));

    off = sizeof(opentde_pagestore_header);
    while (off + sizeof(rec_hdr) <= (uint64_t) st.st_size)
    {
        if (pread(fd, &rec_hdr, sizeof(rec_hdr), (off_t) off) != sizeof(rec_hdr))
        {
            if (rows)
                pfree(rows);
            close(fd);
            return false;
        }

        off += sizeof(rec_hdr);
        if (off + rec_hdr.blob_len > (uint64_t) st.st_size)
        {
            if (rows)
                pfree(rows);
            close(fd);
            return false;
        }

        if (rows)
        {
            opentde_pagestore_row_state *state = &rows[rec_hdr.blockno];
            state->seen = true;
            state->deleted = (rec_hdr.blob_len == 0);
            state->blob_offset = off;
            state->blob_len = rec_hdr.blob_len;
        }

        off += rec_hdr.blob_len;
    }

    scan->fd = fd;
    scan->table_oid = table_oid;
    scan->total_records = hdr.record_count;
    scan->current_record = 0;
    scan->next_offset = sizeof(opentde_pagestore_header);
    scan->max_blockno = max_blockno;
    scan->row_states = rows;
    scan->is_open = true;

    opentde_pagestore_unlock_fd(fd);

    return true;
}

bool opentde_pagestore_scan_next(opentde_pagestore_scan *scan, HeapTuple *tuple)
{
    opentde_pagestore_row_state    *rows;
    uint8_t                        *blob;
    uint8_t                        *plain = NULL;
    uint32_t                        plain_len = 0;
    HeapTuple                       tuple_local;
    uint32_t                        blockno;
    uint32_t                        emitted;

    /* elog(LOG, "OpenTDE: scan_next table_oid=%u is_open=%d current_record=%u max_blockno=%u", scan ? scan->table_oid : 0, scan ? scan->is_open : 0, scan ? scan->current_record : 0, scan ? scan->max_blockno : 0); */
    if (!scan || !scan->is_open || !tuple)
        return false;

    rows = (opentde_pagestore_row_state *) scan->row_states;
    if (!rows)
        return false;

    emitted = 0;
    for (blockno = scan->current_record; blockno <= scan->max_blockno; blockno++)
    {
        opentde_pagestore_row_state *state = &rows[blockno];

        if (!state->seen || state->deleted)
            continue;

        blob = (uint8_t *) palloc(state->blob_len);
        if (pread(scan->fd, blob, state->blob_len, (off_t) state->blob_offset) != (ssize_t) state->blob_len)
        {
            pfree(blob);
            return false;
        }

        if (!opentde_page_blob_decrypt(scan->table_oid,
                                       (BlockNumber) blockno,
                                       blob,
                                       state->blob_len,
                                       &plain,
                                       &plain_len,
                                       NULL))
        {
            pfree(blob);
            return false;
        }

        tuple_local = (HeapTuple) palloc0(sizeof(HeapTupleData));
        tuple_local->t_data = (HeapTupleHeader) plain;
        tuple_local->t_len = plain_len;
        tuple_local->t_tableOid = scan->table_oid;
        ItemPointerSet(&tuple_local->t_data->t_ctid, blockno, FirstOffsetNumber);
        ItemPointerSet(&tuple_local->t_self, blockno, FirstOffsetNumber);

        /* Set tuple header fields for visibility */
        HeapTupleHeaderSetXmin(tuple_local->t_data, 1); /* always visible */
        HeapTupleHeaderSetCmin(tuple_local->t_data, 0);
        HeapTupleHeaderSetXmax(tuple_local->t_data, 0);
        tuple_local->t_data->t_infomask |= HEAP_XMIN_COMMITTED | HEAP_XMAX_INVALID;

        *tuple = tuple_local;

        scan->current_record = blockno + 1;
        emitted = 1;
        pfree(blob);
        break;
    }

    return emitted == 1;
}

void
opentde_pagestore_scan_close(opentde_pagestore_scan *scan)
{
    if (!scan || !scan->is_open)
        return;

    if (scan->row_states)
        pfree(scan->row_states);

    close(scan->fd);
    scan->row_states = NULL;
    scan->is_open = false;
}
