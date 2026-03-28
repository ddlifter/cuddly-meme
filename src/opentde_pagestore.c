#include "postgres.h"
#include "access/htup_details.h"
#include "access/heapam.h"
#include "utils/rel.h"
#include "utils/builtins.h"
#include "utils/memutils.h"
#include "fmgr.h"
#include "storage/bufmgr.h"
#include "storage/bufpage.h"
#include "storage/itemid.h"
#include <stdbool.h>
#include <stddef.h>
#include <utils/guc.h>
#include "opentde.h"
#include "port.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

// GUC variables
bool opentde_pagestore_fsync = true;

#define OPENTDE_PAGESTORE_MAGIC   0x4F545053U /* ASCII "OTPS" */
#define OPENTDE_PAGESTORE_VERSION 1
#define OPENTDE_PAGESTORE_JOURNAL_MAGIC   0x4F544A52U /* ASCII "OTJR" */
#define OPENTDE_PAGESTORE_JOURNAL_VERSION 1

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t record_count;
    uint32_t reserved;
} opentde_pagestore_header;

typedef struct {
    uint32_t blockno;
    uint32_t blob_len;
} opentde_pagestore_record_header;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t blockno;
    uint32_t blob_len;
} opentde_pagestore_journal_header;

bool opentde_pagestore_journal = true;

void _PG_init(void);

void _PG_init(void)
{
    DefineCustomBoolVariable(
        "opentde.pagestore_fsync",
        "Enable fsync for page store (disable for performance testing only)",
        NULL,
        &opentde_pagestore_fsync,
        true,
        PGC_SUSET,
        0,
        NULL,
        NULL,
        NULL
    );
    DefineCustomBoolVariable(
        "opentde.pagestore_journal",
        "Enable journaling for page store (disable for performance testing only)",
        NULL,
        &opentde_pagestore_journal,
        true,
        PGC_SUSET,
        0,
        NULL,
        NULL,
        NULL
    );
}

static void opentde_pagestore_write_header(int fd,
                                           const opentde_pagestore_header *hdr);
static bool opentde_pagestore_append_tuple_internal(Oid table_oid,
                                                    HeapTuple tuple,
                                                    BlockNumber blockno,
                                                    bool use_explicit_blockno,
                                                    bool delete_marker,
                                                    ItemPointerData *tid_out);

typedef struct {
    bool     seen;
    bool     deleted;
    uint64_t blob_offset;
    uint32_t blob_len;
} opentde_pagestore_row_state;

static char *
opentde_pagestore_get_dir(void)
{
    char *pgdata = opentde_get_pgdata_path();
    return psprintf("%s/pg_encryption/pages", pgdata);
}

static void
opentde_pagestore_ensure_dir(void)
{
    char *dir;

    opentde_ensure_key_directory();
    dir = opentde_pagestore_get_dir();

    if (mkdir(dir, 0700) != 0 && errno != EEXIST)
        ereport(ERROR,
                (errcode_for_file_access(),
                 errmsg("cannot create page store directory %s", dir)));

    pfree(dir);
}

static char *
opentde_pagestore_get_file_path(Oid table_oid)
{
    char *dir = opentde_pagestore_get_dir();
    char *path = psprintf("%s/%u.ps", dir, table_oid);
    pfree(dir);
    return path;
}

static char *
opentde_pagestore_get_journal_path(Oid table_oid)
{
    char *dir = opentde_pagestore_get_dir();
    char *path = psprintf("%s/%u.psj", dir, table_oid);
    pfree(dir);
    return path;
}

static void
opentde_pagestore_fsync_fd(int fd, const char *what)
{
    if (opentde_pagestore_fsync)
    {
        if (fsync(fd) != 0)
            ereport(ERROR,
                    (errcode_for_file_access(),
                     errmsg("cannot fsync %s", what)));
    }
}

static void
opentde_pagestore_lock_fd(int fd, int lock_type)
{
    struct flock fl;

    MemSet(&fl, 0, sizeof(fl));
    fl.l_type = lock_type;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;

    if (fcntl(fd, F_SETLKW, &fl) != 0)
        ereport(ERROR,
                (errcode_for_file_access(),
                 errmsg("cannot acquire pagestore file lock")));
}

static void
opentde_pagestore_unlock_fd(int fd)
{
    struct flock fl;

    MemSet(&fl, 0, sizeof(fl));
    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;

    if (fcntl(fd, F_SETLK, &fl) != 0)
        ereport(ERROR,
                (errcode_for_file_access(),
                 errmsg("cannot release pagestore file lock")));
}

static void
opentde_pagestore_append_raw_record(int fd,
                                    uint32_t blockno,
                                    const uint8_t *blob,
                                    uint32_t blob_len)
{
    opentde_pagestore_record_header rec_hdr;

    rec_hdr.blockno = blockno;
    rec_hdr.blob_len = blob_len;

    if (lseek(fd, 0, SEEK_END) < 0 ||
        write(fd, &rec_hdr, sizeof(rec_hdr)) != sizeof(rec_hdr))
        ereport(ERROR,
                (errcode_for_file_access(),
                 errmsg("cannot append page store record")));

    if (blob_len > 0 &&
        write(fd, blob, blob_len) != (ssize_t) blob_len)
        ereport(ERROR,
                (errcode_for_file_access(),
                 errmsg("cannot append page store record payload")));
}

static void
opentde_pagestore_write_journal(Oid table_oid,
                                uint32_t blockno,
                                const uint8_t *blob,
                                uint32_t blob_len)
{
    if (!opentde_pagestore_journal)
        return;
    char *jpath;
    int jfd;
    opentde_pagestore_journal_header jhdr;
    jpath = opentde_pagestore_get_journal_path(table_oid);
    jfd = open(jpath, O_WRONLY | O_CREAT | O_TRUNC | PG_BINARY, 0600);
    if (jfd < 0)
    {
        pfree(jpath);
        ereport(ERROR,
                (errcode_for_file_access(),
                 errmsg("cannot open page store journal %s", jpath)));
    }
    jhdr.magic = OPENTDE_PAGESTORE_JOURNAL_MAGIC;
    jhdr.version = OPENTDE_PAGESTORE_JOURNAL_VERSION;
    jhdr.blockno = blockno;
    jhdr.blob_len = blob_len;
    if (write(jfd, &jhdr, sizeof(jhdr)) != sizeof(jhdr))
    {
        close(jfd);
        pfree(jpath);
        ereport(ERROR,
                (errcode_for_file_access(),
                 errmsg("cannot write page store journal")));
    }
    if (blob_len > 0 && write(jfd, blob, blob_len) != (ssize_t) blob_len)
    {
        close(jfd);
        pfree(jpath);
        ereport(ERROR,
                (errcode_for_file_access(),
                 errmsg("cannot write page store journal payload")));
    }
    opentde_pagestore_fsync_fd(jfd, "page store journal");
    close(jfd);
    pfree(jpath);
}

static void
opentde_pagestore_clear_journal(Oid table_oid)
{
    char *jpath;

    jpath = opentde_pagestore_get_journal_path(table_oid);
    if (unlink(jpath) != 0 && errno != ENOENT)
    {
        pfree(jpath);
        ereport(ERROR,
                (errcode_for_file_access(),
                 errmsg("cannot remove page store journal")));
    }
    pfree(jpath);
}

static void
opentde_pagestore_replay_journal_if_needed(int fd,
                                           Oid table_oid,
                                           opentde_pagestore_header *hdr)
{
    char                           *jpath;
    int                             jfd;
    opentde_pagestore_journal_header jhdr;
    uint8_t                        *blob;

    jpath = opentde_pagestore_get_journal_path(table_oid);
    jfd = open(jpath, O_RDONLY | PG_BINARY, 0600);
    if (jfd < 0)
    {
        pfree(jpath);
        return;
    }

    if (read(jfd, &jhdr, sizeof(jhdr)) != sizeof(jhdr) ||
        jhdr.magic != OPENTDE_PAGESTORE_JOURNAL_MAGIC ||
        jhdr.version != OPENTDE_PAGESTORE_JOURNAL_VERSION)
    {
        close(jfd);
        pfree(jpath);
        ereport(ERROR,
                (errcode(ERRCODE_DATA_CORRUPTED),
                 errmsg("invalid page store journal for table %u", table_oid)));
    }

    blob = NULL;
    if (jhdr.blob_len > 0)
    {
        blob = (uint8_t *) palloc(jhdr.blob_len);
        if (read(jfd, blob, jhdr.blob_len) != (ssize_t) jhdr.blob_len)
        {
            pfree(blob);
            close(jfd);
            pfree(jpath);
            ereport(ERROR,
                    (errcode_for_file_access(),
                     errmsg("cannot read page store journal payload")));
        }
    }

    close(jfd);

    /*
     * Replay journal unconditionally.
     * Journal can represent insert/update/delete append records.
     * Re-applying an already persisted record is idempotent for logical state
     * because latest record per block wins during reads/scans.
     */
    opentde_pagestore_append_raw_record(fd, jhdr.blockno, blob, jhdr.blob_len);
    if (jhdr.blockno >= hdr->record_count)
        hdr->record_count = jhdr.blockno + 1;
    opentde_pagestore_write_header(fd, hdr);
    opentde_pagestore_fsync_fd(fd, "page store file");

    if (blob)
        pfree(blob);
    if (unlink(jpath) != 0 && errno != ENOENT)
    {
        pfree(jpath);
        ereport(ERROR,
                (errcode_for_file_access(),
                 errmsg("cannot remove page store journal after replay")));
    }

    pfree(jpath);
}

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

    if (!delete_marker && (!tuple || tuple->t_len <= 0))
        return false;

    opentde_pagestore_ensure_dir();
    path = opentde_pagestore_get_file_path(table_oid);

    fd = open(path, O_RDWR | O_CREAT | PG_BINARY, 0600);
    if (fd < 0)
    {
        pfree(path);
        ereport(ERROR,
                (errcode_for_file_access(),
                 errmsg("cannot open page store file %s", path)));
    }

    opentde_pagestore_lock_fd(fd, F_WRLCK);

    opentde_pagestore_read_or_init_header(fd, &hdr);
    opentde_pagestore_replay_journal_if_needed(fd, table_oid, &hdr);

    stored_blockno = use_explicit_blockno ? (uint32_t) blockno : hdr.record_count;

    if (!delete_marker)
    {
        plain_copy = (uint8_t *) palloc((Size) tuple->t_len);
        memcpy(plain_copy, tuple->t_data, (Size) tuple->t_len);
        ItemPointerSet(&((HeapTupleHeader) plain_copy)->t_ctid,
                   stored_blockno,
                   FirstOffsetNumber);

        if (!opentde_page_blob_encrypt(table_oid,
                                       (BlockNumber) stored_blockno,
                                       plain_copy,
                                       (uint32_t) tuple->t_len,
                                       &blob,
                                       &blob_len))
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
    opentde_pagestore_fsync_fd(fd, "page store file");

    if (stored_blockno >= hdr.record_count)
        hdr.record_count = stored_blockno + 1;
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

bool
opentde_pagestore_append_tuple(Oid table_oid,
                               HeapTuple tuple,
                               ItemPointerData *tid_out)
{
    /* Batch append: открывает файл, lock, вставляет все кортежи, fsync один раз */
    return opentde_pagestore_append_tuple_internal(table_oid,
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
    while (off + sizeof(rec_hdr) <= (uint64_t) st.st_size)
    {
        if (pread(fd, &rec_hdr, sizeof(rec_hdr), (off_t) off) != sizeof(rec_hdr))
        {
            close(fd);
            return false;
        }

        off += sizeof(rec_hdr);
        if (off + rec_hdr.blob_len > (uint64_t) st.st_size)
        {
            close(fd);
            return false;
        }

        if (rec_hdr.blockno > max_blockno)
            max_blockno = rec_hdr.blockno;

        off += rec_hdr.blob_len;
    }

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

bool
opentde_pagestore_scan_next(opentde_pagestore_scan *scan,
                            HeapTuple *tuple_out)
{
    opentde_pagestore_row_state    *rows;
    uint8_t                        *blob;
    uint8_t                        *plain = NULL;
    uint32_t                        plain_len = 0;
    HeapTuple                       tuple;
    uint32_t                        blockno;
    uint32_t                        emitted;

    if (!scan || !scan->is_open || !tuple_out)
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

        tuple = (HeapTuple) palloc0(sizeof(HeapTupleData));
        tuple->t_data = (HeapTupleHeader) plain;
        tuple->t_len = plain_len;
        tuple->t_tableOid = scan->table_oid;
        ItemPointerSet(&tuple->t_data->t_ctid, blockno, FirstOffsetNumber);
        ItemPointerSet(&tuple->t_self, blockno, FirstOffsetNumber);

        *tuple_out = tuple;

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
