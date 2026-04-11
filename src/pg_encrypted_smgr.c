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
#include "utils/guc.h"
#include "utils/lsyscache.h"

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
get_storage_key(Oid storage_oid, uint8_t *key_out)
{
    if (!OidIsValid(storage_oid))
        return false;

    opentde_ensure_keys_loaded();

    if (!global_key_mgr)
        return false;

    if (global_key_mgr->key_count == 0)
        (void) opentde_reload_key_file();

    for (uint32_t i = 0; i < global_key_mgr->key_count; i++)
    {
        if (global_key_mgr->keys[i].table_oid == storage_oid)
        {
            memcpy(key_out, global_key_mgr->keys[i].dek, DEK_SIZE);
            return true;
        }
    }

    if (opentde_reload_key_file())
    {
        for (uint32_t i = 0; i < global_key_mgr->key_count; i++)
        {
            if (global_key_mgr->keys[i].table_oid == storage_oid)
            {
                memcpy(key_out, global_key_mgr->keys[i].dek, DEK_SIZE);
                return true;
            }
        }
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
    uint8_t    iv[DATA_IV_SIZE];

    page_header = (PageHeader) page_ptr;
    body_offset = page_header->pd_upper;
    if (body_offset <= SizeOfPageHeaderData || body_offset > BLCKSZ)
        return;

    make_iv(relfilenode, forknum, blocknum, iv);
    kuz_ctr_crypt_ctx(ctx, iv, (uint8_t *) page_ptr + body_offset, BLCKSZ - body_offset);
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

static void
encrypted_smgr_startreadv(PgAioHandle *ioh, SMgrRelation reln, ForkNumber forknum,
                          BlockNumber blocknum, void **buffers, BlockNumber nblocks,
                          SmgrChainIndex chain_index)
{
    const char *io_method;

    smgr_startreadv_next(ioh, reln, forknum, blocknum, buffers, nblocks, chain_index + 1);

    io_method = GetConfigOption("io_method", true, false);
    if (io_method != NULL && strcmp(io_method, "sync") == 0)
    {
        Oid relfilenode_oid = reln->smgr_rlocator.locator.relNumber;
        uint8_t key[DEK_SIZE];
        const kuz_key_t *kuz_ctx;

        if (!get_cached_table_crypto(reln, key, &kuz_ctx))
            return;

        for (BlockNumber i = 0; i < nblocks; i++)
        {
            if (buffers[i] == NULL)
                continue;

            crypt_page_body_ctx(buffers[i], relfilenode_oid, kuz_ctx, forknum, blocknum + i);
        }
    }
}

static void
encrypted_smgr_readv(SMgrRelation reln, ForkNumber forknum, BlockNumber blocknum,
                     void **buffers, BlockNumber nblocks, SmgrChainIndex chain_index)
{
    original_md_smgr.smgr_readv(reln, forknum, blocknum, buffers, nblocks, chain_index + 1);

    {
        uint8_t key[DEK_SIZE];
        const kuz_key_t *kuz_ctx;
        Oid relfilenode_oid;

        if (!get_cached_table_crypto(reln, key, &kuz_ctx))
            return;

        relfilenode_oid = reln->smgr_rlocator.locator.relNumber;

        for (BlockNumber i = 0; i < nblocks; i++)
        {
            crypt_page_body_ctx(buffers[i], relfilenode_oid, kuz_ctx, forknum, blocknum + i);
        }
    }
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

    if (!get_cached_table_crypto(reln, key, &kuz_ctx))
    {
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

    if (!get_cached_table_crypto(reln, key, &kuz_ctx))
    {
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
    return original_md_smgr.smgr_fd(reln, forknum, blocknum, off, chain_index + 1);
}
void
opentde_reencrypt_relation_storage(Oid relation_oid)
{
    char relkind;
    Relation rel;
    SMgrRelation smgr;
    ForkNumber forknum = MAIN_FORKNUM;
    BlockNumber nblocks;
    BlockNumber blocknum;
    char   *raw_buffer;
    void   *buffers[1];

    relkind = get_rel_relkind(relation_oid);
    if (relkind == RELKIND_INDEX)
        rel = index_open(relation_oid, AccessExclusiveLock);
    else
        rel = table_open(relation_oid, AccessExclusiveLock);

    smgr = smgropen(rel->rd_locator, rel->rd_backend);
    nblocks = original_md_smgr.smgr_nblocks(smgr, forknum, 0);

    for (blocknum = 0; blocknum < nblocks; blocknum++)
    {
        raw_buffer = palloc(BLCKSZ + PG_IO_ALIGN_SIZE);
        buffers[0] = (void *) TYPEALIGN(PG_IO_ALIGN_SIZE, raw_buffer);

        original_md_smgr.smgr_readv(smgr, forknum, blocknum, buffers, 1, 0);
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
