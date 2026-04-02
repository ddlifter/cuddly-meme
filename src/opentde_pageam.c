#include "opentde.h"
#include "postgres.h"
#include "fmgr.h"
#include "access/tableam.h"

PG_FUNCTION_INFO_V1(opentde_pageam_handler);

Datum
opentde_pageam_handler(PG_FUNCTION_ARGS)
{
    elog(WARNING, "[OpenTDE] opentde_pageam_handler invoked");
    PG_RETURN_POINTER((void *) GetHeapamTableAmRoutine());
}
