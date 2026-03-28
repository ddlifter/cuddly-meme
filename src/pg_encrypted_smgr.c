#include "opentde.h"
#include "postgres.h"
#include "fmgr.h"
#include "storage/smgr.h"
#include "storage/md.h"
#include "kuznechik.h"
#include "utils/guc.h"

extern PGDLLIMPORT bool process_shared_preload_libraries_in_progress;

PG_MODULE_MAGIC;


// Получить ключ для table_oid (relfilenode)
static bool get_table_key(Oid table_oid, uint8_t *key_out) {
    extern void opentde_ensure_keys_loaded(void);
    opentde_ensure_keys_loaded();
    if (!global_key_mgr || !global_key_mgr->key_count)
        return false;
    for (uint32_t i = 0; i < global_key_mgr->key_count; i++) {
        if (global_key_mgr->keys[i].table_oid == table_oid) {
            memcpy(key_out, global_key_mgr->keys[i].dek, KEY_SIZE);
            return true;
        }
    }
    return false;
}

static void make_iv(Oid relfilenode, ForkNumber forknum, BlockNumber blocknum, uint8_t *iv) {
    memset(iv, 0, 16);
    memcpy(iv, &relfilenode, sizeof(Oid));
    memcpy(iv + sizeof(Oid), &forknum, sizeof(ForkNumber));
    memcpy(iv + sizeof(Oid) + sizeof(ForkNumber), &blocknum, sizeof(BlockNumber));
}

// Реализация smgr_readv: дешифрует каждый блок после mdreadv
static void encrypted_smgr_readv(SMgrRelation reln, ForkNumber forknum, BlockNumber blocknum,
                                 void **buffers, BlockNumber nblocks, SmgrChainIndex chain_index) {
    mdsmgr_register(); // ensure mdsmgr is registered
    smgrsw[MdSMgrId].smgr_readv(reln, forknum, blocknum, buffers, nblocks, chain_index + 1);
    for (BlockNumber i = 0; i < nblocks; i++) {
        uint8_t key[KEY_SIZE];
        uint8_t iv[16];
        if (!get_table_key(reln->smgr_rlocator.locator.relNumber, key))
            continue;
        make_iv(reln->smgr_rlocator.locator.relNumber, forknum, blocknum + i, iv);
        kuz_key_t ctx;
        kuz_set_key(&ctx, key);
        kuz_ctr_crypt_ctx(&ctx, iv, (uint8_t *)buffers[i], BLCKSZ);
    }
}

// Реализация smgr_writev: шифрует каждый блок перед mdwritev
static void encrypted_smgr_writev(SMgrRelation reln, ForkNumber forknum, BlockNumber blocknum,
                                  const void **buffers, BlockNumber nblocks, bool skipFsync, SmgrChainIndex chain_index) {
    void **enc_bufs;
    BlockNumber i;
    enc_bufs = (void **)palloc(sizeof(void *) * nblocks);
    for (i = 0; i < nblocks; i++) {
        uint8_t key[KEY_SIZE];
        uint8_t iv[16];
        int need_free = 0;
        if (!get_table_key(reln->smgr_rlocator.locator.relNumber, key)) {
            enc_bufs[i] = (void *)buffers[i];
            continue;
        }
        make_iv(reln->smgr_rlocator.locator.relNumber, forknum, blocknum + i, iv);
        kuz_key_t ctx;
        kuz_set_key(&ctx, key);
        enc_bufs[i] = palloc(BLCKSZ);
        memcpy(enc_bufs[i], buffers[i], BLCKSZ);
        kuz_ctr_crypt_ctx(&ctx, iv, enc_bufs[i], BLCKSZ);
    }
    mdsmgr_register();
    smgrsw[MdSMgrId].smgr_writev(reln, forknum, blocknum, (const void **)enc_bufs, nblocks, skipFsync, chain_index + 1);
    for (i = 0; i < nblocks; i++) {
        uint8_t key[KEY_SIZE];
        if (get_table_key(reln->smgr_rlocator.locator.relNumber, key))
            pfree(enc_bufs[i]);
    }
    pfree(enc_bufs);
}

static void encrypted_smgr_extend(SMgrRelation reln, ForkNumber forknum, BlockNumber blocknum, const void *buffer, bool skipFsync, SmgrChainIndex chain_index) {
    uint8_t key[KEY_SIZE];
    uint8_t iv[16];
    if (!get_table_key(reln->smgr_rlocator.locator.relNumber, key)) {
        mdsmgr_register();
        smgrsw[MdSMgrId].smgr_extend(reln, forknum, blocknum, buffer, skipFsync, chain_index + 1);
        return;
    }
    make_iv(reln->smgr_rlocator.locator.relNumber, forknum, blocknum, iv);
    kuz_key_t ctx;
    kuz_set_key(&ctx, key);
    uint8_t enc_buf[BLCKSZ];
    memcpy(enc_buf, buffer, BLCKSZ);
    kuz_ctr_crypt_ctx(&ctx, iv, enc_buf, BLCKSZ);
    mdsmgr_register();
    smgrsw[MdSMgrId].smgr_extend(reln, forknum, blocknum, enc_buf, skipFsync, chain_index + 1);
}

static bool encrypted_smgr_prefetch(SMgrRelation reln, ForkNumber forknum, BlockNumber blocknum, int nblocks, SmgrChainIndex chain_index) {
    mdsmgr_register();
    return smgrsw[MdSMgrId].smgr_prefetch(reln, forknum, blocknum, nblocks, chain_index + 1);
}

static void encrypted_smgr_unlink(RelFileLocatorBackend rlocator, ForkNumber forknum, bool isRedo, SmgrChainIndex chain_index) {
    mdsmgr_register();
    smgrsw[MdSMgrId].smgr_unlink(rlocator, forknum, isRedo, chain_index + 1);
}

static void encrypted_smgr_truncate(SMgrRelation reln, ForkNumber forknum, BlockNumber old_blocks, BlockNumber nblocks, SmgrChainIndex chain_index) {
    mdsmgr_register();
    smgrsw[MdSMgrId].smgr_truncate(reln, forknum, old_blocks, nblocks, chain_index + 1);
}

static void encrypted_smgr_immedsync(SMgrRelation reln, ForkNumber forknum, SmgrChainIndex chain_index) {
    mdsmgr_register();
    smgrsw[MdSMgrId].smgr_immedsync(reln, forknum, chain_index + 1);
}

static void encrypted_smgr_open(SMgrRelation reln, SmgrChainIndex chain_index) {
    mdsmgr_register();
    smgrsw[MdSMgrId].smgr_open(reln, chain_index + 1);
}

static void encrypted_smgr_close(SMgrRelation reln, ForkNumber forknum, SmgrChainIndex chain_index) {
    mdsmgr_register();
    smgrsw[MdSMgrId].smgr_close(reln, forknum, chain_index + 1);
}

static void encrypted_smgr_init(void) { mdsmgr_register(); }

// Вместо регистрации SMGR — lookup кастомного SMGR по имени
#include "storage/smgr.h"

static SMgrId encrypted_smgr_id = 0;

void _PG_init(void)
{
    /* Ensure master key is loaded from Vault at backend startup */
    opentde_ensure_keys_loaded();
    encrypted_smgr_id = smgr_lookup("encrypted");
}
