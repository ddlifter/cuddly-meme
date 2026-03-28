#include "postgres.h"
#include "fmgr.h"
#include "storage/smgr.h"

PG_MODULE_MAGIC;

// Минимальная реализация: просто проксирует md.c
static void encrypted_smgr_init(void) {}
static void encrypted_smgr_open(SMgrRelation reln, SmgrChainIndex chain_index) {}
static void encrypted_smgr_close(SMgrRelation reln, ForkNumber forknum, SmgrChainIndex chain_index) {}
static void encrypted_smgr_create(SMgrRelation reln, ForkNumber forknum, bool isRedo, SmgrChainIndex chain_index) {}
static bool encrypted_smgr_exists(SMgrRelation reln, ForkNumber forknum, SmgrChainIndex chain_index) { return false; }
static void encrypted_smgr_unlink(RelFileLocatorBackend rlocator, ForkNumber forknum, bool isRedo, SmgrChainIndex chain_index) {}
static void encrypted_smgr_extend(SMgrRelation reln, ForkNumber forknum, BlockNumber blocknum, const void *buffer, bool skipFsync, SmgrChainIndex chain_index) {}
static void encrypted_smgr_zeroextend(SMgrRelation reln, ForkNumber forknum, BlockNumber blocknum, int nblocks, bool skipFsync, SmgrChainIndex chain_index) {}
static bool encrypted_smgr_prefetch(SMgrRelation reln, ForkNumber forknum, BlockNumber blocknum, int nblocks, SmgrChainIndex chain_index) { return false; }
static void encrypted_smgr_readv(SMgrRelation reln, ForkNumber forknum, BlockNumber blocknum, void **buffers, BlockNumber nblocks, SmgrChainIndex chain_index) {}
static void encrypted_smgr_writev(SMgrRelation reln, ForkNumber forknum, BlockNumber blocknum, const void **buffers, BlockNumber nblocks, bool skipFsync, SmgrChainIndex chain_index) {}
static void encrypted_smgr_writeback(SMgrRelation reln, ForkNumber forknum, BlockNumber blocknum, BlockNumber nblocks, SmgrChainIndex chain_index) {}
static BlockNumber encrypted_smgr_nblocks(SMgrRelation reln, ForkNumber forknum, SmgrChainIndex chain_index) { return 0; }
static void encrypted_smgr_truncate(SMgrRelation reln, ForkNumber forknum, BlockNumber nblocks, SmgrChainIndex chain_index) {}
static void encrypted_smgr_immedsync(SMgrRelation reln, ForkNumber forknum, SmgrChainIndex chain_index) {}

static const f_smgr encrypted_smgr = {
    .name = "encrypted",
    .chain_position = 0,
    .smgr_init    = encrypted_smgr_init,
    .smgr_shutdown = NULL,
    .smgr_open    = encrypted_smgr_open,
    .smgr_close   = encrypted_smgr_close,
    .smgr_create  = encrypted_smgr_create,
    .smgr_exists  = encrypted_smgr_exists,
    .smgr_unlink  = encrypted_smgr_unlink,
    .smgr_extend  = encrypted_smgr_extend,
    .smgr_zeroextend = encrypted_smgr_zeroextend,
    .smgr_prefetch = encrypted_smgr_prefetch,
    .smgr_readv   = encrypted_smgr_readv,
    .smgr_writev  = encrypted_smgr_writev,
    .smgr_writeback = encrypted_smgr_writeback,
    .smgr_nblocks = encrypted_smgr_nblocks,
    .smgr_truncate = encrypted_smgr_truncate,
    .smgr_immedsync = encrypted_smgr_immedsync,
    .smgr_registersync = NULL,
    .smgr_fd = NULL
};

void _PG_init(void)
{
    smgr_register(&encrypted_smgr, sizeof(SMgrRelationData));
}
