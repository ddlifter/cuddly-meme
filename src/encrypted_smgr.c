#include "postgres.h"
#include "fmgr.h"
#include "storage/smgr.h"

PG_MODULE_MAGIC;


#include "pg_encrypted_smgr.c"

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
