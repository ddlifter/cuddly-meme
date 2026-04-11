#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kuznechik.h"

static int
hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static int
hex_to_bytes(const char *hex, size_t expected_len, uint8_t *out)
{
    size_t hex_len = strlen(hex);
    size_t i;

    if (hex_len != expected_len * 2)
        return -1;

    for (i = 0; i < expected_len; i++)
    {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);

        if (hi < 0 || lo < 0)
            return -1;

        out[i] = (uint8_t) ((hi << 4) | lo);
    }

    return 0;
}

static int
load_file(const char *path, uint8_t **buf_out, size_t *len_out)
{
    FILE *f;
    long size;
    uint8_t *buf;

    f = fopen(path, "rb");
    if (f == NULL)
        return -1;

    if (fseek(f, 0, SEEK_END) != 0)
    {
        fclose(f);
        return -1;
    }

    size = ftell(f);
    if (size < 0)
    {
        fclose(f);
        return -1;
    }

    if (fseek(f, 0, SEEK_SET) != 0)
    {
        fclose(f);
        return -1;
    }

    buf = (uint8_t *) malloc((size_t) size);
    if (buf == NULL)
    {
        fclose(f);
        return -1;
    }

    if (size > 0)
    {
        size_t nread = fread(buf, 1, (size_t) size, f);
        if (nread != (size_t) size)
        {
            free(buf);
            fclose(f);
            return -1;
        }
    }

    fclose(f);
    *buf_out = buf;
    *len_out = (size_t) size;
    return 0;
}

static int
save_file(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");

    if (f == NULL)
        return -1;

    if (len > 0)
    {
        size_t nwritten = fwrite(buf, 1, len, f);
        if (nwritten != len)
        {
            fclose(f);
            return -1;
        }
    }

    if (fclose(f) != 0)
        return -1;

    return 0;
}

int
main(int argc, char **argv)
{
    const char *mode;
    const char *key_hex;
    const char *iv_hex;
    const char *src_path;
    const char *dst_path;
    uint8_t key[32];
    uint8_t iv[16];
    uint8_t *data = NULL;
    size_t len = 0;

    if (argc != 6)
    {
        fprintf(stderr,
                "Usage: %s <enc|dec> <key_hex_64> <iv_hex_32> <src_path> <dst_path>\n",
                argv[0]);
        return 2;
    }

    mode = argv[1];
    key_hex = argv[2];
    iv_hex = argv[3];
    src_path = argv[4];
    dst_path = argv[5];

    if (strcmp(mode, "enc") != 0 && strcmp(mode, "dec") != 0)
    {
        fprintf(stderr, "Invalid mode: %s\n", mode);
        return 2;
    }

    if (hex_to_bytes(key_hex, sizeof(key), key) != 0)
    {
        fprintf(stderr, "Invalid key hex, expected 64 hex chars\n");
        return 2;
    }

    if (hex_to_bytes(iv_hex, sizeof(iv), iv) != 0)
    {
        fprintf(stderr, "Invalid IV hex, expected 32 hex chars\n");
        return 2;
    }

    if (load_file(src_path, &data, &len) != 0)
    {
        fprintf(stderr, "Failed to read file %s: %s\n", src_path, strerror(errno));
        return 1;
    }

    kuz_ctr_crypt(key, iv, data, len);

    if (save_file(dst_path, data, len) != 0)
    {
        fprintf(stderr, "Failed to write file %s: %s\n", dst_path, strerror(errno));
        free(data);
        return 1;
    }

    free(data);
    return 0;
}
