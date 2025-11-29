#ifndef KUZNECHIK_H
#define KUZNECHIK_H

#include <stdint.h>
#include <stddef.h>

// Размер блока у Кузнечика = 128 бит (16 байт)
#define BLOCK_SIZE 16
// Размер ключа = 256 бит (32 байта)
#define KEY_SIZE 32

// Контекст (развернутые ключи)
typedef struct {
    uint8_t keys[10][16]; // 10 раундовых ключей
} kuz_key_t;

// Инициализация ключа
void kuz_set_key(kuz_key_t *ctx, const uint8_t *key);

// Шифрование одного блока (16 байт)
// out = Encrypt(in)
void kuz_encrypt_block(kuz_key_t *ctx, const uint8_t *in, uint8_t *out);

// Наша главная функция: Режим CTR (Гаммирование)
// Позволяет шифровать данные любой длины
// key - мастер-ключ (32 байта)
// iv - вектор инициализации (16 байт, должен быть уникальным для строки)
// data - данные (шифруются на месте)
// len - длина данных
void kuz_ctr_crypt(const uint8_t *key, const uint8_t *iv, uint8_t *data, size_t len);

#endif
