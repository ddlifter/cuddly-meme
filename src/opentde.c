#include "postgres.h"
#include "fmgr.h"
#include "access/tableam.h"
#include "utils/guc.h"

PG_MODULE_MAGIC;

// void _PG_init(void);
void _PG_fini(void);

/* Функция вызывается при загрузке библиотеки в память процесса */
// void
// _PG_init(void)
// {
//     /* 
//      * Custom WAL Resource Manager 
//      */
//     elog(INFO, "OpenTDE: Extension loaded successfully.");
// }

void
_PG_fini(void)
{
    elog(INFO, "OpenTDE: Extension unloaded.");
}
