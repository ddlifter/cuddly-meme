#include "opentde.h"

#include "postgres.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "storage/smgr.h"
#include "storage/md.h"
#include "utils/guc.h"

PG_MODULE_MAGIC;

static f_smgr original_md_smgr;
static bool md_smgr_hooked = false;
static bool md_smgr_installing = false;

static bool
get_table_key(Oid table_oid, uint8_t *key_out)
{
    opentde_ensure_keys_loaded();

    elog(WARNING, "[OpenTDE] key lookup rel=%u key_count=%d master_key_set=%s",
         table_oid,
         global_key_mgr ? global_key_mgr->key_count : -1,
         master_key_set ? "true" : "false");

    if (!global_key_mgr || global_key_mgr->key_count == 0)
        return false;

    for (uint32_t i = 0; i < global_key_mgr->key_count; i++)
    {
        if (global_key_mgr->keys[i].table_oid == table_oid)
        {
            elog(WARNING, "[OpenTDE] key lookup hit rel=%u version=%u",
                 table_oid,
                 global_key_mgr->keys[i].key_version);
            memcpy(key_out, global_key_mgr->keys[i].dek, DEK_SIZE);
            return true;
        }
    }

    if (opentde_reload_key_file())
    {
        for (uint32_t i = 0; i < global_key_mgr->key_count; i++)
        {
            if (global_key_mgr->keys[i].table_oid == table_oid)
            {
                elog(WARNING, "[OpenTDE] key lookup hit after reload rel=%u version=%u",
                     table_oid,
                     global_key_mgr->keys[i].key_version);
                memcpy(key_out, global_key_mgr->keys[i].dek, DEK_SIZE);
                return true;
            }
        }
    }

    elog(WARNING, "[OpenTDE] key lookup miss rel=%u", table_oid);

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
encrypted_smgr_readv(SMgrRelation reln, ForkNumber forknum, BlockNumber blocknum,
                     void **buffers, BlockNumber nblocks, SmgrChainIndex chain_index)
{
    elog(WARNING, "[OpenTDE] encrypted_smgr_readv rel=%u fork=%d blocks=%u chain=%u",
         reln->smgr_rlocator.locator.relNumber,
         (int) forknum,
         (unsigned int) nblocks,
         (unsigned int) chain_index);
    original_md_smgr.smgr_readv(reln, forknum, blocknum, buffers, nblocks, chain_index + 1);

    for (BlockNumber i = 0; i < nblocks; i++)
    {
        uint8_t key[DEK_SIZE];
        uint8_t iv[DATA_IV_SIZE];
        kuz_key_t ctx;

        if (!get_table_key(reln->smgr_rlocator.locator.relNumber, key))
            continue;

        make_iv(reln->smgr_rlocator.locator.relNumber, forknum, blocknum + i, iv);
        kuz_set_key(&ctx, key);
        kuz_ctr_crypt_ctx(&ctx, iv, (uint8_t *) buffers[i], BLCKSZ);
    }
}

static void
encrypted_smgr_writev(SMgrRelation reln, ForkNumber forknum, BlockNumber blocknum,
                      const void **buffers, BlockNumber nblocks, bool skipFsync,
                      SmgrChainIndex chain_index)
{
    elog(WARNING, "[OpenTDE] encrypted_smgr_writev rel=%u fork=%d blocks=%u chain=%u",
         reln->smgr_rlocator.locator.relNumber,
         (int) forknum,
         (unsigned int) nblocks,
         (unsigned int) chain_index);
    void **enc_bufs;
    void **enc_raw_bufs;

    enc_bufs = (void **) palloc(sizeof(void *) * nblocks);
    enc_raw_bufs = (void **) palloc(sizeof(void *) * nblocks);

    for (BlockNumber i = 0; i < nblocks; i++)
    {
        uint8_t key[DEK_SIZE];
        uint8_t iv[DATA_IV_SIZE];
        kuz_key_t ctx;

        if (!get_table_key(reln->smgr_rlocator.locator.relNumber, key))
        {
            enc_bufs[i] = (void *) buffers[i];
            enc_raw_bufs[i] = NULL;
            continue;
        }

        make_iv(reln->smgr_rlocator.locator.relNumber, forknum, blocknum + i, iv);
        kuz_set_key(&ctx, key);
        enc_raw_bufs[i] = palloc(BLCKSZ + PG_IO_ALIGN_SIZE);
        enc_bufs[i] = (void *) TYPEALIGN(PG_IO_ALIGN_SIZE, enc_raw_bufs[i]);
        memcpy(enc_bufs[i], buffers[i], BLCKSZ);
        kuz_ctr_crypt_ctx(&ctx, iv, enc_bufs[i], BLCKSZ);
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
    elog(WARNING, "[OpenTDE] encrypted_smgr_extend rel=%u fork=%d block=%u chain=%u",
         reln->smgr_rlocator.locator.relNumber,
         (int) forknum,
         (unsigned int) blocknum,
         (unsigned int) chain_index);
    uint8_t key[DEK_SIZE];
    uint8_t iv[DATA_IV_SIZE];

    if (!get_table_key(reln->smgr_rlocator.locator.relNumber, key))
    {
        original_md_smgr.smgr_extend(reln, forknum, blocknum, buffer, skipFsync, chain_index + 1);
        return;
    }

    make_iv(reln->smgr_rlocator.locator.relNumber, forknum, blocknum, iv);

    {
        char   *enc_raw_buf;
        uint8_t *enc_buf;
        kuz_key_t ctx;

        enc_raw_buf = palloc(BLCKSZ + PG_IO_ALIGN_SIZE);
        enc_buf = (uint8_t *) TYPEALIGN(PG_IO_ALIGN_SIZE, enc_raw_buf);

        memcpy(enc_buf, buffer, BLCKSZ);
        kuz_set_key(&ctx, key);
        kuz_ctr_crypt_ctx(&ctx, iv, enc_buf, BLCKSZ);
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
    .smgr_startreadv = NULL,
    .smgr_writev = encrypted_smgr_writev,
    .smgr_writeback = encrypted_smgr_writeback,
    .smgr_nblocks = encrypted_smgr_nblocks,
    .smgr_truncate = encrypted_smgr_truncate,
    .smgr_immedsync = encrypted_smgr_immedsync,
    .smgr_registersync = NULL,
    .smgr_fd = NULL
};

void
opentde_install_md_hooks(void)
{
    const char *current_chain;

    if (md_smgr_hooked || md_smgr_installing)
        return;

    md_smgr_installing = true;

    elog(WARNING, "[OpenTDE] installing smgr hooks");
    opentde_ensure_keys_loaded();
    elog(WARNING, "[OpenTDE] loaded keys, registering encrypted smgr");
    original_md_smgr = smgrsw[smgr_lookup("md")];
    smgr_register(&encrypted_smgr, sizeof(SMgrRelationData));
    elog(WARNING, "[OpenTDE] encrypted smgr registered");

    current_chain = smgr_chain_string;
    if (current_chain == NULL || current_chain[0] == '\0')
        smgr_chain_string = psprintf("encrypted,md");
    else if (strstr(current_chain, "encrypted") == NULL)
        smgr_chain_string = psprintf("encrypted,%s", current_chain);

    process_smgr_chain();
    elog(WARNING, "[OpenTDE] smgr chain configured as '%s'", smgr_chain_string);

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
