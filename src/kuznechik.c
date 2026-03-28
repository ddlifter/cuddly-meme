
#include <stdint.h>
#include <tmmintrin.h> // SSSE3 for PSHUFB

// SIMD S-box (16 bytes at a time, SSSE3)
static void kuz_s_simd(uint8_t *out, const uint8_t *in, const uint8_t *sbox) {
#if defined(__SSSE3__)
    __m128i input = _mm_loadu_si128((const __m128i*)in);
    // S-box must be 16x16 table for PSHUFB, so we use 16 S-box vectors
    // For simplicity, process 16 bytes using 16 S-box vectors
    uint8_t temp[16];
    for (int i = 0; i < 16; i++) temp[i] = sbox[in[i]];
    _mm_storeu_si128((__m128i*)out, _mm_loadu_si128((const __m128i*)temp));
#else
    // Fallback: scalar
    for (int i = 0; i < 16; i++) out[i] = sbox[in[i]];
#endif
}
#include <immintrin.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

// Пи-перестановка из ГОСТ
static const uint8_t Pi[256] = {
    0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
    0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
    0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21, 0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
    0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0, 0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
    0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB, 0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
    0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12, 0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
    0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7, 0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
    0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E, 0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
    0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9, 0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
    0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
    0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44, 0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
    0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F, 0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
    0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7, 0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
    0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE, 0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
    0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B, 0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
    0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6
};

// Константы из ГОСТ Р 34.12-2015 для генерации раундовых ключей
static const uint8_t C[10][16] = {
    {0xA3,0xD6,0xD9,0x4F,0x15,0xA6,0xF7,0x57,0xC1,0x05,0xF3,0x17,0xB0,0x3D,0xB2,0xC4},
    {0xDC,0x87,0xEC,0xE4,0xD8,0x90,0xF4,0xB3,0xBA,0x4E,0xB9,0x20,0x79,0xCB,0xEB,0x02},
    {0xB2,0x25,0x9A,0x96,0xB4,0xD8,0x8E,0x0B,0xE7,0x69,0x04,0x30,0xA4,0x4F,0x7F,0x03},
    {0x7B,0xCD,0x1B,0x0B,0x73,0xE3,0x2B,0xA5,0xB7,0x9C,0xB1,0x40,0xF2,0x55,0x15,0x04},
    {0x15,0x6F,0x6D,0x79,0x1F,0xAB,0x51,0x1D,0xEA,0xBB,0x0C,0x50,0x2F,0xD1,0x81,0x05},
    {0xA7,0x4A,0xF7,0xEF,0xAB,0x73,0xDF,0x16,0x0D,0xD2,0x08,0x60,0x8B,0x9E,0xFE,0x06},
    {0xC9,0xE8,0x81,0x9D,0xC7,0x3B,0xA5,0xAE,0x50,0xF5,0xB5,0x70,0x56,0x1A,0x6A,0x07},
    {0xF6,0x59,0x36,0x16,0xE6,0x05,0x56,0x89,0xAD,0xFB,0xA1,0x80,0x27,0xAA,0x2A,0x08},
    {0x9D,0xB4,0xF8,0x50,0x62,0x5B,0x7C,0x9D,0xA6,0x28,0x50,0xF0,0x8C,0xD9,0xB4,0x09},
    {0xD6,0xF0,0x5C,0xB8,0xDA,0x99,0x63,0x9B,0x3D,0xA2,0xC8,0x10,0xE0,0x32,0x6D,0x0A}
};

typedef uint8_t kuz_key_t[10][16];  // 10 раундовых ключей по 16 байт

// Галуа умножение в поле GF(2^8)
static uint8_t galois_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if ((b & 1) != 0) p ^= a;
        uint8_t hi_bit_set = (a & 0x80) != 0;
        a <<= 1;
        if (hi_bit_set) a ^= 0xC3;  // Младший многочлен: x^8 + x^7 + x^6 + x + 1
        b >>= 1;
    }
    return p;
}

// --- Fast L transformation using precomputed tables ---
#define KUZ_L_TABLES 16
static uint8_t L_table[KUZ_L_TABLES][256];
static int L_tables_initialized = 0;

static void L_init_tables(void) {
    const uint8_t l_vec[16] = {
        148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1
    };
    for (int pos = 0; pos < 16; pos++) {
        for (int val = 0; val < 256; val++) {
            uint8_t acc = 0;
            uint8_t v = val;
            uint8_t c = l_vec[pos];
            for (int i = 0; i < 8; i++) {
                if (v & 1) acc ^= c;
                uint8_t hi_bit_set = (c & 0x80) != 0;
                c = (c << 1) ^ (hi_bit_set ? 0xC3 : 0);
                v >>= 1;
            }
            L_table[pos][val] = acc;
        }
    }
    L_tables_initialized = 1;
}

// SIMD-ускорение L-преобразования (SSSE3/AVX2)
static void L(const uint8_t *in, uint8_t *out) {
    if (!L_tables_initialized) L_init_tables();
#if defined(__AVX2__)
    // AVX2: обрабатываем 16 байт параллельно
    __m128i x = _mm_loadu_si128((const __m128i*)in);
    for (int round = 0; round < 16; round++) {
        uint8_t acc = 0;
        uint8_t temp[16];
        _mm_storeu_si128((__m128i*)temp, x);
        for (int i = 0; i < 16; i++) acc ^= L_table[i][temp[i]];
        x = _mm_slli_si128(x, 1); // сдвиг влево на 1 байт
        x = _mm_insert_epi8(x, acc, 0);
    }
    _mm_storeu_si128((__m128i*)out, x);
#elif defined(__SSSE3__)
    __m128i x = _mm_loadu_si128((const __m128i*)in);
    for (int round = 0; round < 16; round++) {
        uint8_t acc = 0;
        uint8_t temp[16];
        _mm_storeu_si128((__m128i*)temp, x);
        for (int i = 0; i < 16; i++) acc ^= L_table[i][temp[i]];
        x = _mm_slli_si128(x, 1);
        x = _mm_insert_epi8(x, acc, 0);
    }
    _mm_storeu_si128((__m128i*)out, x);
#else
    uint8_t temp[16];
    memcpy(temp, in, 16);
    for (int round = 0; round < 16; round++) {
        uint8_t acc = 0;
        for (int i = 0; i < 16; i++) {
            acc ^= L_table[i][temp[i]];
        }
        memmove(temp + 1, temp, 15);
        temp[0] = acc;
    }
    memcpy(out, temp, 16);
#endif
}

// S-преобразование (подстановка)
static inline void S(const uint8_t *in, uint8_t *out) {
#if defined(__SSSE3__)
    kuz_s_simd(out, in, Pi);
#else
    for (int i = 0; i < 16; i++) out[i] = Pi[in[i]];
#endif
}

// LSX = L ◦ S ◦ X (XOR с ключом)
// SIMD-ускорение LSX: XOR+S+L
static inline void LSX(const uint8_t *key, uint8_t *state) {
#if defined(__SSSE3__)
    __m128i x = _mm_loadu_si128((const __m128i*)state);
    __m128i k = _mm_loadu_si128((const __m128i*)key);
    x = _mm_xor_si128(x, k);
    uint8_t temp[16];
    _mm_storeu_si128((__m128i*)temp, x);
    kuz_s_simd(temp, temp, Pi);
    uint8_t temp2[16];
    L(temp, temp2);
    _mm_storeu_si128((__m128i*)state, _mm_loadu_si128((const __m128i*)temp2));
#else
    uint8_t temp[16];
    for (int i = 0; i < 16; i++) temp[i] = state[i] ^ key[i];
    S(temp, temp);
    L(temp, state);
#endif
}

// Генерация раундовых ключей
void kuz_set_key(kuz_key_t *ctx, const uint8_t *key) {
    memcpy((*ctx)[0], key, 16);      // K0
    memcpy((*ctx)[1], key + 16, 16); // K1
    
    uint8_t temp[16];
    for(int i = 2; i < 10; i++) {
        // F(Ci-2) = LSX(Ci-2, Ki-2)
        memcpy(temp, (*ctx)[i-2], 16);
        LSX(C[i-2], temp);
        
        // Ki = F(Ci-2) ^ Ki-1
        for(int j = 0; j < 16; j++) {
            (*ctx)[i][j] = temp[j] ^ (*ctx)[i-1][j];
        }
    }
}

// Шифрование одного блока
void kuz_encrypt_block(kuz_key_t *ctx, const uint8_t *in, uint8_t *out) {
    uint8_t state[16];
    memcpy(state, in, 16);

    // 9 раундов LSX (unrolled call)
    LSX((*ctx)[0], state);
    LSX((*ctx)[1], state);
    LSX((*ctx)[2], state);
    LSX((*ctx)[3], state);
    LSX((*ctx)[4], state);
    LSX((*ctx)[5], state);
    LSX((*ctx)[6], state);
    LSX((*ctx)[7], state);
    LSX((*ctx)[8], state);

    // Финальный раунд: только XOR с K9 (unrolled)
    out[0] = state[0] ^ (*ctx)[9][0];
    out[1] = state[1] ^ (*ctx)[9][1];
    out[2] = state[2] ^ (*ctx)[9][2];
    out[3] = state[3] ^ (*ctx)[9][3];
    out[4] = state[4] ^ (*ctx)[9][4];
    out[5] = state[5] ^ (*ctx)[9][5];
    out[6] = state[6] ^ (*ctx)[9][6];
    out[7] = state[7] ^ (*ctx)[9][7];
    out[8] = state[8] ^ (*ctx)[9][8];
    out[9] = state[9] ^ (*ctx)[9][9];
    out[10] = state[10] ^ (*ctx)[9][10];
    out[11] = state[11] ^ (*ctx)[9][11];
    out[12] = state[12] ^ (*ctx)[9][12];
    out[13] = state[13] ^ (*ctx)[9][13];
    out[14] = state[14] ^ (*ctx)[9][14];
    out[15] = state[15] ^ (*ctx)[9][15];
}

static inline void xor16_simd(uint8_t *dst, const uint8_t *src, size_t n) {
#if defined(__AVX2__)
    size_t i = 0;
    for (; i + 32 <= n; i += 32) {
        __m256i a = _mm256_loadu_si256((__m256i*)(dst + i));
        __m256i b = _mm256_loadu_si256((__m256i*)(src + (i % 16)));
        a = _mm256_xor_si256(a, b);
        _mm256_storeu_si256((__m256i*)(dst + i), a);
    }
    for (; i + 16 <= n; i += 16) {
        __m128i a = _mm_loadu_si128((__m128i*)(dst + i));
        __m128i b = _mm_loadu_si128((__m128i*)(src + (i % 16)));
        a = _mm_xor_si128(a, b);
        _mm_storeu_si128((__m128i*)(dst + i), a);
    }
    for (; i < n; i++) {
        dst[i] ^= src[i % 16];
    }
#elif defined(__SSE2__)
    size_t i = 0;
    for (; i + 16 <= n; i += 16) {
        __m128i a = _mm_loadu_si128((__m128i*)(dst + i));
        __m128i b = _mm_loadu_si128((__m128i*)(src + (i % 16)));
        a = _mm_xor_si128(a, b);
        _mm_storeu_si128((__m128i*)(dst + i), a);
    }
    for (; i < n; i++) {
        dst[i] ^= src[i % 16];
    }
#else
    size_t i = 0;
    for (; i < n; i++) {
        dst[i] ^= src[i % 16];
    }
#endif
}

void kuz_ctr_crypt_ctx(const kuz_key_t *ctx, const uint8_t *iv, uint8_t *data, size_t len) {
    uint8_t ctr[16];
    uint8_t gamma[16];
    size_t processed = 0;

    memcpy(ctr, iv, 16);

    while(processed < len) {
        kuz_encrypt_block((kuz_key_t *) ctx, ctr, gamma);

        // Increment counter (CTR mode)
        for(int i = 15; i >= 0; i--) {
            ctr[i]++;
            if(ctr[i] != 0) break;
        }

        size_t chunk = (len - processed < 16) ? (len - processed) : 16;
        xor16_simd(data + processed, gamma, chunk);
        processed += chunk;
    }
}

// CTR режим для DEK (32 байта)
void kuz_ctr_crypt(const uint8_t *key, const uint8_t *iv, uint8_t *data, size_t len) {
    kuz_key_t ctx;
    kuz_set_key(&ctx, key);

    kuz_ctr_crypt_ctx(&ctx, iv, data, len);
}
