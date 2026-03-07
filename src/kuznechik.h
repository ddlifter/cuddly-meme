#ifndef KUZNECHIK_H
#define KUZNECHIK_H

#include <stdint.h>
#include <stddef.h>

#define BLOCK_SIZE 16
#define KEY_SIZE 32

typedef struct {
    uint8_t keys[10][16];
} kuz_key_t;

// Инициализация ключа
void kuz_set_key(kuz_key_t *ctx, const uint8_t *key);

// Шифрование одного блока (16 байт)
// out = Encrypt(in)
void kuz_encrypt_block(kuz_key_t *ctx, const uint8_t *in, uint8_t *out);

void kuz_ctr_crypt(const uint8_t *key, const uint8_t *iv, uint8_t *data, size_t len);

#endif
