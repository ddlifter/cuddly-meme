#include "opentde.h"

#include <string.h>

PG_FUNCTION_INFO_V1(opentde_page_crypto_selftest);

static uint32_t
opentde_fnv1a32_start(void)
{
    return 2166136261U;
}

static uint32_t
opentde_fnv1a32_update(uint32_t state, const uint8_t *buf, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
    {
        state ^= (uint32_t) buf[i];
        state *= 16777619U;
    }

    return state;
}

static uint32_t
opentde_page_blob_checksum(const opentde_page_blob_header *hdr,
                           const uint8_t *ciphertext)
{
    uint32_t state;

    state = opentde_fnv1a32_start();
    state = opentde_fnv1a32_update(state, (const uint8_t *) &hdr->magic, sizeof(hdr->magic));
    state = opentde_fnv1a32_update(state, (const uint8_t *) &hdr->version, sizeof(hdr->version));
    state = opentde_fnv1a32_update(state, (const uint8_t *) &hdr->header_len, sizeof(hdr->header_len));
    state = opentde_fnv1a32_update(state, (const uint8_t *) &hdr->table_oid, sizeof(hdr->table_oid));
    state = opentde_fnv1a32_update(state, (const uint8_t *) &hdr->blockno, sizeof(hdr->blockno));
    state = opentde_fnv1a32_update(state, (const uint8_t *) &hdr->key_version, sizeof(hdr->key_version));
    state = opentde_fnv1a32_update(state, hdr->iv, DATA_IV_SIZE);
    state = opentde_fnv1a32_update(state, (const uint8_t *) &hdr->payload_len, sizeof(hdr->payload_len));

    if (hdr->payload_len > 0)
        state = opentde_fnv1a32_update(state, ciphertext, hdr->payload_len);

    return state;
}

bool
opentde_page_blob_encrypt(Oid table_oid,
                          BlockNumber blockno,
                          const uint8_t *plain,
                          uint32_t plain_len,
                          uint8_t **blob_out,
                          uint32_t *blob_len_out)
{
    opentde_page_blob_header hdr;
    uint8_t                 *blob;
    uint8_t                 *payload;
    uint32_t                 blob_len;

    if (!blob_out || !blob_len_out)
        return false;

    if (plain_len > 0 && plain == NULL)
        return false;

    hdr.magic = OPENTDE_PAGE_BLOB_MAGIC;
    hdr.version = OPENTDE_PAGE_BLOB_VERSION;
    hdr.header_len = (uint16_t) sizeof(opentde_page_blob_header);
    hdr.table_oid = table_oid;
    hdr.blockno = (uint32_t) blockno;
    hdr.key_version = opentde_get_active_table_key_version(table_oid);
    hdr.payload_len = plain_len;
    hdr.checksum = 0;

    opentde_fill_random_bytes(hdr.iv, DATA_IV_SIZE, "page blob IV");

    blob_len = (uint32_t) sizeof(opentde_page_blob_header) + plain_len;
    blob = (uint8_t *) palloc(blob_len);

    memcpy(blob, &hdr, sizeof(opentde_page_blob_header));
    payload = blob + sizeof(opentde_page_blob_header);

    if (plain_len > 0)
    {
        memcpy(payload, plain, plain_len);
        opentde_gost_encrypt_decrypt((char *) payload,
                                     (int) plain_len,
                                     table_oid,
                                     hdr.key_version,
                                     hdr.iv);
    }

    hdr.checksum = opentde_page_blob_checksum(&hdr, payload);
    memcpy(blob, &hdr, sizeof(opentde_page_blob_header));

    *blob_out = blob;
    *blob_len_out = blob_len;
    return true;
}

bool
opentde_page_blob_decrypt(Oid expected_table_oid,
                          BlockNumber expected_blockno,
                          const uint8_t *blob,
                          uint32_t blob_len,
                          uint8_t **plain_out,
                          uint32_t *plain_len_out,
                          uint32_t *key_version_out)
{
    opentde_page_blob_header hdr;
    const uint8_t           *ciphertext;
    uint8_t                 *plain;
    uint32_t                 expected_sum;

    if (!blob || blob_len < sizeof(opentde_page_blob_header))
        return false;

    if (!plain_out || !plain_len_out)
        return false;

    memcpy(&hdr, blob, sizeof(opentde_page_blob_header));

    if (hdr.magic != OPENTDE_PAGE_BLOB_MAGIC ||
        hdr.version != OPENTDE_PAGE_BLOB_VERSION)
        return false;

    if (hdr.header_len != sizeof(opentde_page_blob_header))
        return false;

    if (hdr.table_oid != expected_table_oid)
        return false;

    if (hdr.blockno != (uint32_t) expected_blockno)
        return false;

    if (hdr.payload_len + sizeof(opentde_page_blob_header) != blob_len)
        return false;

    ciphertext = blob + sizeof(opentde_page_blob_header);
    expected_sum = opentde_page_blob_checksum(&hdr, ciphertext);

    if (expected_sum != hdr.checksum)
        return false;

    plain = (uint8_t *) palloc(hdr.payload_len);
    if (hdr.payload_len > 0)
    {
        memcpy(plain, ciphertext, hdr.payload_len);
        opentde_gost_encrypt_decrypt((char *) plain,
                                     (int) hdr.payload_len,
                                     hdr.table_oid,
                                     hdr.key_version,
                                     hdr.iv);
    }

    *plain_out = plain;
    *plain_len_out = hdr.payload_len;
    if (key_version_out)
        *key_version_out = hdr.key_version;

    return true;
}

Datum
opentde_page_crypto_selftest(PG_FUNCTION_ARGS)
{
    Oid      table_oid;
    int32    blockno;
    bytea   *input;
    uint8_t *blob = NULL;
    uint8_t *plain = NULL;
    uint32_t blob_len = 0;
    uint32_t plain_len = 0;
    uint32_t key_version = 0;
    int32    input_len;
    bool     ok;

    table_oid = PG_GETARG_OID(0);
    blockno = PG_GETARG_INT32(1);
    input = PG_GETARG_BYTEA_PP(2);
    input_len = VARSIZE_ANY_EXHDR(input);

    ok = opentde_page_blob_encrypt(table_oid,
                                   (BlockNumber) blockno,
                                   (const uint8_t *) VARDATA_ANY(input),
                                   (uint32_t) input_len,
                                   &blob,
                                   &blob_len);

    if (!ok)
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("page blob encrypt selftest failed")));

    ok = opentde_page_blob_decrypt(table_oid,
                                   (BlockNumber) blockno,
                                   blob,
                                   blob_len,
                                   &plain,
                                   &plain_len,
                                   &key_version);

    if (!ok)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_CORRUPTED),
                 errmsg("page blob decrypt selftest failed")));

    if (plain_len != (uint32_t) input_len ||
        (plain_len > 0 && memcmp(plain, VARDATA_ANY(input), plain_len) != 0))
        ereport(ERROR,
                (errcode(ERRCODE_DATA_CORRUPTED),
                 errmsg("page blob selftest roundtrip mismatch")));

    pfree(blob);
    pfree(plain);

    PG_RETURN_BOOL(key_version > 0);
}
