#include "opentde.h"

#include "postgres.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "storage/aio.h"
#include "storage/backendid.h"
#include "access/table.h"
#include "storage/bufpage.h"
#include "storage/smgr.h"
#include "storage/md.h"
#include "storage/itemid.h"
#include "access/htup_details.h"
#include "access/transam.h"
#include "utils/guc.h"
#include "utils/lsyscache.h"
#include <fcntl.h>
#include <unistd.h>

PG_MODULE_MAGIC;

static f_smgr original_md_smgr;
static bool md_smgr_hooked = false;
static bool md_smgr_installing = false;
extern Oid opentde_pending_index_parent_storage_oid;
extern Oid opentde_pending_index_child_storage_oid;

static Oid
relation_key_owner_oid(SMgrRelation reln)
{
    Oid storage_oid;

    storage_oid = reln->smgr_rlocator.locator.relNumber;
    if (storage_oid == opentde_pending_index_child_storage_oid &&
        opentde_pending_index_parent_storage_oid != InvalidOid)
        return opentde_pending_index_parent_storage_oid;

    return storage_oid;
}

static bool
storage_oid_present_in_key_file(Oid storage_oid)
{
    char            *pgdata;
    char            *key_path;
    int              fd;
    key_file_header  header;
    bool             found;

    if (!OidIsValid(storage_oid))
        return false;

    pgdata = opentde_get_pgdata_path();
    key_path = psprintf("%s/%s", pgdata, KEY_FILE_PATH);
    pfree(pgdata);

    fd = open(key_path, O_RDONLY | PG_BINARY, 0600);
    pfree(key_path);
    if (fd < 0)
        return false;

    if (read(fd, &header, sizeof(header)) != sizeof(header) ||
        header.magic != KEY_FILE_MAGIC)
    {
        close(fd);
        return false;
    }

    found = false;
    for (uint32_t i = 0; i < header.key_count; i++)
    {
        key_file_entry entry;

        if (read(fd, &entry, sizeof(entry)) != sizeof(entry))
            break;

        if (entry.table_oid == storage_oid)
        {
            found = true;
            break;
        }
    }

    close(fd);
    return found;
}

static bool
get_storage_key(Oid storage_oid, uint8_t *key_out)
{
    int      selected_idx;
    uint32_t selected_active_version;
    uint32_t selected_fallback_version;
    int      attempt;
    uint32_t i;

    if (!OidIsValid(storage_oid))
        return false;

    for (attempt = 0; attempt < 3; attempt++)
    {
        opentde_ensure_keys_loaded();

        if (!master_key_set)
            (void) opentde_load_master_key_from_file();

        if (!global_key_mgr)
            opentde_init_key_manager();

        if (master_key_set && global_key_mgr && global_key_mgr->key_count == 0)
            (void) opentde_reload_key_file();

        if (!global_key_mgr)
            continue;

        selected_idx = -1;
        selected_active_version = 0;
        selected_fallback_version = 0;

        for (i = 0; i < (uint32_t) global_key_mgr->key_count; i++)
        {
            opentde_key_entry *entry = &global_key_mgr->keys[i];

            if (entry->table_oid != storage_oid)
                continue;

            if (entry->is_active && entry->key_version >= selected_active_version)
            {
                selected_active_version = entry->key_version;
                selected_idx = (int) i;
                continue;
            }

            if (selected_idx < 0 && entry->key_version >= selected_fallback_version)
            {
                selected_fallback_version = entry->key_version;
                selected_idx = (int) i;
            }
        }

        if (selected_idx >= 0)
        {
            memcpy(key_out, global_key_mgr->keys[selected_idx].dek, DEK_SIZE);
            return true;
        }

        (void) opentde_reload_key_file();
    }

    return false;
}

static void
make_iv(Oid relfilenode, ForkNumber forknum, BlockNumber blocknum, uint8_t *iv)
{
    memset(iv, 0, DATA_IV_SIZE);
    memcpy(iv, &relfilenode, sizeof(Oid));
    memcpy(iv + sizeof(Oid), &forknum, sizeof(ForkNumber));
    memcpy(iv + sizeof(Oid) + sizeof(ForkNumber), &blocknum, sizeof(BlockNumber));
}

static void
crypt_page_body_ctx(void *page_ptr, Oid relfilenode, const kuz_key_t *ctx, ForkNumber forknum, BlockNumber blocknum)
{
    PageHeader page_header;
    uint16     body_offset;
    uint16     body_end;
    uint8_t    iv[DATA_IV_SIZE];

    page_header = (PageHeader) page_ptr;
    body_offset = page_header->pd_upper;
    body_end = page_header->pd_special;

    if (body_offset <= SizeOfPageHeaderData || body_offset > BLCKSZ)
        return;
    if (body_end < body_offset || body_end > BLCKSZ)
        return;

    make_iv(relfilenode, forknum, blocknum, iv);
    kuz_ctr_crypt_ctx(ctx, iv, (uint8_t *) page_ptr + body_offset, body_end - body_offset);
}

static bool
get_cached_table_crypto(SMgrRelation reln, uint8_t *key_out, const kuz_key_t **ctx_out)
{
    static bool      cache_valid = false;
    static Oid       cached_storage_oid = InvalidOid;
    static uint8_t   cached_raw_key[DEK_SIZE];
    static kuz_key_t cached_ctx;
    Oid              storage_oid;

    storage_oid = relation_key_owner_oid(reln);
    if (!get_storage_key(storage_oid, key_out))
        return false;

    if (cache_valid &&
        cached_storage_oid == storage_oid &&
        memcmp(cached_raw_key, key_out, DEK_SIZE) == 0)
    {
        *ctx_out = &cached_ctx;
        return true;
    }

    kuz_set_key(&cached_ctx, key_out);
    memcpy(cached_raw_key, key_out, DEK_SIZE);
    cached_storage_oid = storage_oid;
    cache_valid = true;
    *ctx_out = &cached_ctx;
    return true;
}

/*
 * Detect obviously wrong heap tuples after decryption (typically plaintext
 * pages that were mistakenly passed through decrypt path).
 */
static bool
heap_page_has_impossible_xids(Page page)
{
    PageHeader   phdr;
    OffsetNumber maxoff;
    OffsetNumber offnum;
    TransactionId next_xid;
    int          checked;
    int          bad;

    phdr = (PageHeader) page;

    /* Heuristic is only for heap main-fork pages. */
    if (phdr->pd_special != BLCKSZ)
        return false;

    next_xid = ReadNextTransactionId();
    maxoff = PageGetMaxOffsetNumber(page);
    checked = 0;
    bad = 0;

    for (offnum = FirstOffsetNumber; offnum <= maxoff && checked < 64; offnum++)
    {
        ItemId         iid;
        OffsetNumber   lp_off;
        Size           lp_len;
        HeapTupleHeader tup;
        TransactionId  xmin;

        iid = PageGetItemId(page, offnum);
        if (!ItemIdIsNormal(iid))
            continue;

        lp_off = ItemIdGetOffset(iid);
        lp_len = ItemIdGetLength(iid);
        checked++;

        if (lp_len < SizeofHeapTupleHeader ||
            lp_off < phdr->pd_upper ||
            lp_off + lp_len > phdr->pd_special)
        {
            bad += 2;
            continue;
        }

        tup = (HeapTupleHeader) ((char *) page + lp_off);
        xmin = HeapTupleHeaderGetRawXmin(tup);

        if (TransactionIdIsNormal(xmin) && TransactionIdFollows(xmin, next_xid))
            bad++;
    }

    if (maxoff > 0 && checked == 0)
        return true;

    return (checked > 0 && bad > 0);
}

static void
decrypt_read_buffers(SMgrRelation reln, ForkNumber forknum, BlockNumber blocknum,
                     void **buffers, BlockNumber nblocks)
{
    uint8_t key[DEK_SIZE];
    const kuz_key_t *kuz_ctx;
    Oid relfilenode_oid;

    if (forknum != MAIN_FORKNUM)
        return;

    if (!get_cached_table_crypto(reln, key, &kuz_ctx))
        return;

    relfilenode_oid = reln->smgr_rlocator.locator.relNumber;

    for (BlockNumber i = 0; i < nblocks; i++)
    {
        char original_page[BLCKSZ];

        if (buffers[i] == NULL)
            continue;

        memcpy(original_page, buffers[i], BLCKSZ);
        crypt_page_body_ctx(buffers[i], relfilenode_oid, kuz_ctx, forknum, blocknum + i);

        if (heap_page_has_impossible_xids((Page) buffers[i]))
            memcpy(buffers[i], original_page, BLCKSZ);
    }
}

static void
encrypted_smgr_startreadv(PgAioHandle *ioh, SMgrRelation reln, ForkNumber forknum,
                          BlockNumber blocknum, void **buffers, BlockNumber nblocks,
                          SmgrChainIndex chain_index)
{
    const char *io_method;

    smgr_startreadv_next(ioh, reln, forknum, blocknum, buffers, nblocks, chain_index + 1);

    io_method = GetConfigOption("io_method", true, false);
    if (io_method != NULL && strcmp(io_method, "sync") == 0)
        decrypt_read_buffers(reln, forknum, blocknum, buffers, nblocks);
}

static void
encrypted_smgr_readv(SMgrRelation reln, ForkNumber forknum, BlockNumber blocknum,
                     void **buffers, BlockNumber nblocks, SmgrChainIndex chain_index)
{
    original_md_smgr.smgr_readv(reln, forknum, blocknum, buffers, nblocks, chain_index + 1);
    decrypt_read_buffers(reln, forknum, blocknum, buffers, nblocks);
}

static void
encrypted_smgr_writev(SMgrRelation reln, ForkNumber forknum, BlockNumber blocknum,
                      const void **buffers, BlockNumber nblocks, bool skipFsync,
                      SmgrChainIndex chain_index)
{
    void **enc_bufs;
    void **enc_raw_bufs;
    uint8_t key[DEK_SIZE];
    const kuz_key_t *kuz_ctx;

    enc_bufs = (void **) palloc(sizeof(void *) * nblocks);
    enc_raw_bufs = (void **) palloc(sizeof(void *) * nblocks);

    if (forknum != MAIN_FORKNUM || !get_cached_table_crypto(reln, key, &kuz_ctx))
    {
        Oid storage_oid = relation_key_owner_oid(reln);

        if (forknum == MAIN_FORKNUM && storage_oid_present_in_key_file(storage_oid))
            ereport(ERROR,
                    (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                     errmsg("OpenTDE key is unavailable for encrypted storage %u", storage_oid)));

        original_md_smgr.smgr_writev(reln, forknum, blocknum, buffers,
                                     nblocks, skipFsync, chain_index + 1);
        pfree(enc_raw_bufs);
        pfree(enc_bufs);
        return;
    }

    for (BlockNumber i = 0; i < nblocks; i++)
    {
        enc_raw_bufs[i] = palloc(BLCKSZ + PG_IO_ALIGN_SIZE);
        enc_bufs[i] = (void *) TYPEALIGN(PG_IO_ALIGN_SIZE, enc_raw_bufs[i]);
        memcpy(enc_bufs[i], buffers[i], BLCKSZ);
        crypt_page_body_ctx(enc_bufs[i], reln->smgr_rlocator.locator.relNumber, kuz_ctx, forknum, blocknum + i);
        PageSetChecksumInplace((Page) enc_bufs[i], blocknum + i);
    }

    original_md_smgr.smgr_writev(reln, forknum, blocknum, (const void **) enc_bufs,
                                 nblocks, skipFsync, chain_index + 1);

    for (BlockNumber i = 0; i < nblocks; i++)
    {
        if (enc_raw_bufs[i] != NULL)
            pfree(enc_raw_bufs[i]);
    }

    pfree(enc_raw_bufs);
    pfree(enc_bufs);
}

static void
encrypted_smgr_extend(SMgrRelation reln, ForkNumber forknum, BlockNumber blocknum,
                      const void *buffer, bool skipFsync, SmgrChainIndex chain_index)
{
    uint8_t key[DEK_SIZE];
    const kuz_key_t *kuz_ctx;

    if (forknum != MAIN_FORKNUM || !get_cached_table_crypto(reln, key, &kuz_ctx))
    {
        Oid storage_oid = relation_key_owner_oid(reln);

        if (forknum == MAIN_FORKNUM && storage_oid_present_in_key_file(storage_oid))
            ereport(ERROR,
                    (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                     errmsg("OpenTDE key is unavailable for encrypted storage %u", storage_oid)));

        original_md_smgr.smgr_extend(reln, forknum, blocknum, buffer, skipFsync, chain_index + 1);
        return;
    }

    {
        char   *enc_raw_buf;
        uint8_t *enc_buf;

        enc_raw_buf = palloc(BLCKSZ + PG_IO_ALIGN_SIZE);
        enc_buf = (uint8_t *) TYPEALIGN(PG_IO_ALIGN_SIZE, enc_raw_buf);

        memcpy(enc_buf, buffer, BLCKSZ);
        crypt_page_body_ctx(enc_buf, reln->smgr_rlocator.locator.relNumber, kuz_ctx, forknum, blocknum);
        PageSetChecksumInplace((Page) enc_buf, blocknum);
        original_md_smgr.smgr_extend(reln, forknum, blocknum, enc_buf, skipFsync, chain_index + 1);
        pfree(enc_raw_buf);
    }
}

static void
encrypted_smgr_zeroextend(SMgrRelation reln, ForkNumber forknum, BlockNumber blocknum,
                          int nblocks, bool skipFsync, SmgrChainIndex chain_index)
{
    original_md_smgr.smgr_zeroextend(reln, forknum, blocknum, nblocks, skipFsync, chain_index + 1);
}

static bool
encrypted_smgr_prefetch(SMgrRelation reln, ForkNumber forknum, BlockNumber blocknum,
                        int nblocks, SmgrChainIndex chain_index)
{
    return original_md_smgr.smgr_prefetch(reln, forknum, blocknum, nblocks, chain_index + 1);
}

static void
encrypted_smgr_writeback(SMgrRelation reln, ForkNumber forknum, BlockNumber blocknum,
                         BlockNumber nblocks, SmgrChainIndex chain_index)
{
    original_md_smgr.smgr_writeback(reln, forknum, blocknum, nblocks, chain_index + 1);
}

static BlockNumber
encrypted_smgr_nblocks(SMgrRelation reln, ForkNumber forknum, SmgrChainIndex chain_index)
{
    return original_md_smgr.smgr_nblocks(reln, forknum, chain_index + 1);
}

static void
encrypted_smgr_truncate(SMgrRelation reln, ForkNumber forknum, BlockNumber old_blocks,
                        BlockNumber nblocks, SmgrChainIndex chain_index)
{
    original_md_smgr.smgr_truncate(reln, forknum, old_blocks, nblocks, chain_index + 1);
}

static void
encrypted_smgr_immedsync(SMgrRelation reln, ForkNumber forknum, SmgrChainIndex chain_index)
{
    original_md_smgr.smgr_immedsync(reln, forknum, chain_index + 1);
}

static void
encrypted_smgr_open(SMgrRelation reln, SmgrChainIndex chain_index)
{
    original_md_smgr.smgr_open(reln, chain_index + 1);
}

static void
encrypted_smgr_close(SMgrRelation reln, ForkNumber forknum, SmgrChainIndex chain_index)
{
    original_md_smgr.smgr_close(reln, forknum, chain_index + 1);
}

static void
encrypted_smgr_create(RelFileLocator relold, SMgrRelation reln, ForkNumber forknum,
                      bool isRedo, SmgrChainIndex chain_index)
{
    if (opentde_pending_index_parent_storage_oid != InvalidOid &&
        opentde_pending_index_child_storage_oid == InvalidOid &&
        forknum == MAIN_FORKNUM &&
        !isRedo &&
        reln->smgr_rlocator.backend == InvalidBackendId)
    {
        opentde_pending_index_child_storage_oid = reln->smgr_rlocator.locator.relNumber;

        if (opentde_storage_key_exists(opentde_pending_index_child_storage_oid))
            opentde_forget_table_keys(opentde_pending_index_child_storage_oid);

        opentde_copy_active_storage_key(opentde_pending_index_parent_storage_oid,
                                        opentde_pending_index_child_storage_oid);
    }

    original_md_smgr.smgr_create(relold, reln, forknum, isRedo, chain_index + 1);
}

static bool
encrypted_smgr_exists(SMgrRelation reln, ForkNumber forknum, SmgrChainIndex chain_index)
{
    return original_md_smgr.smgr_exists(reln, forknum, chain_index + 1);
}

static void
encrypted_smgr_unlink(RelFileLocatorBackend rlocator, ForkNumber forknum, bool isRedo,
                      SmgrChainIndex chain_index)
{
    original_md_smgr.smgr_unlink(rlocator, forknum, isRedo, chain_index + 1);
}

static void
encrypted_smgr_init(void)
{
}

static int
encrypted_smgr_fd(SMgrRelation reln, ForkNumber forknum, BlockNumber blocknum, uint32 *off, SmgrChainIndex chain_index)
{
    if (off != NULL)
        *off = 0;

    return -1;
}
void
opentde_reencrypt_relation_storage(Oid relation_oid)
{
    char relkind;
    Relation rel;
    SMgrRelation smgr;
    Oid relfilenode_oid;
    ForkNumber forknum = MAIN_FORKNUM;
    BlockNumber nblocks;
    BlockNumber blocknum;
    uint8_t key[DEK_SIZE];
    const kuz_key_t *kuz_ctx = NULL;
    bool have_crypto = false;
    char   *raw_buffer;
    void   *buffers[1];

    relkind = get_rel_relkind(relation_oid);
    if (relkind == RELKIND_INDEX)
        rel = index_open(relation_oid, AccessExclusiveLock);
    else
        rel = table_open(relation_oid, AccessExclusiveLock);

    smgr = smgropen(rel->rd_locator, rel->rd_backend);
    relfilenode_oid = smgr->smgr_rlocator.locator.relNumber;

    if (relkind != RELKIND_INDEX)
    {
        have_crypto = get_cached_table_crypto(smgr, key, &kuz_ctx);
        if (!have_crypto)
            ereport(ERROR,
                    (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                     errmsg("OpenTDE key is unavailable for relation %u", relation_oid)));
    }

    nblocks = original_md_smgr.smgr_nblocks(smgr, forknum, 0);

    for (blocknum = 0; blocknum < nblocks; blocknum++)
    {
        raw_buffer = palloc(BLCKSZ + PG_IO_ALIGN_SIZE);
        buffers[0] = (void *) TYPEALIGN(PG_IO_ALIGN_SIZE, raw_buffer);

        original_md_smgr.smgr_readv(smgr, forknum, blocknum, buffers, 1, 0);

        if (relkind != RELKIND_INDEX)
        {
            bool raw_bad;

            raw_bad = heap_page_has_impossible_xids((Page) buffers[0]);
            if (raw_bad)
            {
                char *candidate_plain;
                bool  dec_bad;

                candidate_plain = palloc(BLCKSZ);
                memcpy(candidate_plain, buffers[0], BLCKSZ);
                crypt_page_body_ctx(candidate_plain, relfilenode_oid, kuz_ctx, forknum, blocknum);
                dec_bad = heap_page_has_impossible_xids((Page) candidate_plain);

                if (!dec_bad)
                    memcpy(buffers[0], candidate_plain, BLCKSZ);

                pfree(candidate_plain);
            }
        }

        smgrwritev(smgr, forknum, blocknum, (const void **) buffers, 1, false);

        pfree(raw_buffer);
    }

    smgrclose(smgr);
    if (relkind == RELKIND_INDEX)
        index_close(rel, AccessExclusiveLock);
    else
        table_close(rel, AccessExclusiveLock);
}

static const f_smgr encrypted_smgr = {
    .name = "encrypted",
    .chain_position = SMGR_CHAIN_MODIFIER,
    .smgr_init = encrypted_smgr_init,
    .smgr_shutdown = NULL,
    .smgr_open = encrypted_smgr_open,
    .smgr_close = encrypted_smgr_close,
    .smgr_create = encrypted_smgr_create,
    .smgr_exists = encrypted_smgr_exists,
    .smgr_unlink = encrypted_smgr_unlink,
    .smgr_extend = encrypted_smgr_extend,
    .smgr_zeroextend = encrypted_smgr_zeroextend,
    .smgr_prefetch = encrypted_smgr_prefetch,
    .smgr_maxcombine = NULL,
    .smgr_readv = encrypted_smgr_readv,
    .smgr_startreadv = encrypted_smgr_startreadv,
    .smgr_writev = encrypted_smgr_writev,
    .smgr_writeback = encrypted_smgr_writeback,
    .smgr_nblocks = encrypted_smgr_nblocks,
    .smgr_truncate = encrypted_smgr_truncate,
    .smgr_immedsync = encrypted_smgr_immedsync,
    .smgr_registersync = NULL,
    .smgr_fd = encrypted_smgr_fd
};

void
opentde_install_md_hooks(void)
{
    const char *current_chain;

    if (md_smgr_hooked || md_smgr_installing)
        return;

    md_smgr_installing = true;

    elog(DEBUG1, "[OpenTDE] installing smgr hooks");
    opentde_ensure_keys_loaded();
    elog(DEBUG1, "[OpenTDE] loaded keys, registering encrypted smgr");
    original_md_smgr = smgrsw[smgr_lookup("md")];

    smgr_register(&encrypted_smgr, sizeof(SMgrRelationData));
    elog(DEBUG1, "[OpenTDE] encrypted smgr registered");

    current_chain = smgr_chain_string;
    if (current_chain == NULL || current_chain[0] == '\0')
        smgr_chain_string = psprintf("encrypted,md");
    else if (strstr(current_chain, "encrypted") == NULL)
        smgr_chain_string = psprintf("encrypted,%s", current_chain);

    process_smgr_chain();
    elog(DEBUG1, "[OpenTDE] smgr chain configured as '%s'", smgr_chain_string);

    md_smgr_hooked = true;
    md_smgr_installing = false;
}

void
_PG_init(void)
{
    if (process_shared_preload_libraries_in_progress && !IsUnderPostmaster)
    {
        opentde_install_md_hooks();
        opentde_init_utility_hooks();
    }
}
