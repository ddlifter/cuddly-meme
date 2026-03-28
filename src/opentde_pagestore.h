#ifndef OPENTDE_PAGESTORE_H
#define OPENTDE_PAGESTORE_H

#include "postgres.h"
#include "access/htup_details.h"
#include <stdbool.h>
#include <stdint.h>

#define OPENTDE_PAGESTORE_MAGIC 0x50414745 /* 'PAGE' */
#define OPENTDE_PAGESTORE_VERSION 1

typedef struct {
	uint32_t magic;
	uint8_t version;
	uint8_t pad[3];
	uint32_t record_count;
	uint32_t reserved[13];
} opentde_pagestore_header;

typedef struct {
	uint32_t blockno;
	uint32_t blob_len;
} opentde_pagestore_record_header;

typedef struct {
	bool seen;
	bool deleted;
	uint64_t blob_offset;
	uint32_t blob_len;
} opentde_pagestore_row_state;

typedef struct {
	int fd;
	Oid table_oid;
	uint32_t total_records;
	uint32_t current_record;
	uint64_t next_offset;
	uint32_t max_blockno;
	void *row_states;
	bool is_open;
} opentde_pagestore_scan;

void opentde_pagestore_ensure_dir(void);
bool opentde_pagestore_scan_open(Oid table_oid, opentde_pagestore_scan *scan);
void opentde_pagestore_scan_close(opentde_pagestore_scan *scan);
bool opentde_pagestore_scan_next(opentde_pagestore_scan *scan, HeapTuple *tuple);
void opentde_pagestore_append_tuple(Oid table_oid, HeapTuple tuple, ItemPointer tid);
char *opentde_pagestore_get_file_path(Oid table_oid);

#endif // OPENTDE_PAGESTORE_H
