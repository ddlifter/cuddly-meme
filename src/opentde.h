#include <stdbool.h>

// Глобальный флаг: использовать column-level encryption (альтернатива)
extern bool use_column_level_encryption;
/*
 * opentde.h — Общий заголовочный файл расширения OpenTDE.
 *
 * Содержит:
 *   - Константы (размеры ключей, пути к файлам, magic-значения)
 *   - Определения структур данных (менеджер ключей, записи ключей и IV)
 *   - Прототипы функций, общие для всех модулей
 *
 * Архитектура расширения:
 *   opentde_keymanager.c  — управление мастер-ключом, DEK и IV (файловое хранилище)
 *   opentde_crypto.c      — криптографические операции (wrap/unwrap DEK, шифрование кортежей)
 *   opentde_tableam.c     — реализация Table AM (insert, update, scan, index)
 *   opentde_sql.c         — SQL-функции, вызываемые пользователем
 *   kuznechik.c / .h      — реализация шифра «Кузнечик» (ГОСТ Р 34.12-2015) в режиме CTR
 */
#ifndef OPENTDE_H
#define OPENTDE_H

#include "postgres.h"
#include "access/heapam.h"
#include "access/htup_details.h"
#include "access/tableam.h"
#include "executor/executor.h"
#include "executor/tuptable.h"
#include "fmgr.h"
#include "storage/bufmgr.h"
#include "storage/bufpage.h"
#include "storage/itemid.h"
#include "utils/builtins.h"
#include "utils/memutils.h"
#include "utils/rel.h"

#include "kuznechik.h"

/* =====================================================================
 * Константы
 * ===================================================================== */

/* Пути к файлам хранения ключей внутри PGDATA */
#define KEY_FILE_PATH   "pg_encryption/keys"
#define IV_FILE_PATH    "pg_encryption/ivs"
#define MASTER_KEY_PATH "pg_encryption/master.key"

/* Magic-значения для проверки целостности файлов */
#define KEY_FILE_MAGIC  0x4F50454E   /* ASCII "OPEN" */
#define IV_FILE_MAGIC   0x4F544956   /* ASCII "OTIV" */

/* Версии форматов файлов */
#define KEY_VERSION     3
#define IV_VERSION      2

/* Начальная версия DEK для таблицы */
#define DEFAULT_DEK_VERSION 1

/* Размеры криптографических параметров (в байтах) */
#define MASTER_KEY_SIZE   32                           /* Мастер-ключ: 256 бит */
#define DEK_SIZE          32                           /* Ключ шифрования данных (DEK): 256 бит */
#define DATA_IV_SIZE      16                           /* Вектор инициализации: 128 бит */
#define WRAPPED_DEK_SIZE  (DATA_IV_SIZE + DEK_SIZE)    /* Обёрнутый DEK = IV + зашифрованный DEK */

/* Начальные размеры динамических массивов */
#define INITIAL_KEY_CAPACITY  64
#define INITIAL_IV_CAPACITY   1024

/* =====================================================================
 * Структуры данных — формат файлов на диске
 * ===================================================================== */

/*
 * Заголовок файла ключей (pg_encryption/keys).
 * Формат: [заголовок][запись_1][запись_2]...[запись_N]
 */
typedef struct {
    uint32_t magic;         /* Должно быть KEY_FILE_MAGIC */
    uint8_t  version;       /* Версия формата */
    uint8_t  pad[3];        /* Выравнивание */
    uint32_t key_count;     /* Количество записей */
    uint32_t reserved[13];  /* Резерв для будущих полей */
} key_file_header;

/*
 * Одна запись в файле ключей.
 * Хранит обёрнутый (зашифрованный мастер-ключом) DEK для конкретной таблицы.
 */
typedef struct {
    Oid      table_oid;                      /* OID таблицы */
    uint32_t key_version;                    /* Версия DEK таблицы */
    uint8_t  is_active;                      /* 1 = активная версия для новых записей */
    uint8_t  pad[3];                         /* Выравнивание */
    uint8_t  wrapped_dek[WRAPPED_DEK_SIZE];  /* IV (16 байт) + зашифрованный DEK (32 байта) */
    uint64_t created_at;                     /* Время создания (UNIX timestamp) */
} key_file_entry;

/*
 * Заголовок файла IV (pg_encryption/ivs).
 * Хранит векторы инициализации для каждого кортежа.
 */
typedef struct {
    uint32_t magic;         /* Должно быть IV_FILE_MAGIC */
    uint8_t  version;       /* Версия формата */
    uint8_t  pad[3];        /* Выравнивание */
    uint32_t iv_count;      /* Количество записей */
    uint32_t reserved[13];  /* Резерв */
} iv_file_header;

/*
 * Одна запись в файле IV.
 * Привязывает IV к конкретному кортежу (таблица + блок + смещение).
 */
typedef struct {
    Oid          table_oid;        /* OID таблицы */
    BlockNumber  block;            /* Номер блока (страницы) */
    OffsetNumber offset;           /* Смещение внутри блока */
    uint16_t     pad;              /* Выравнивание */
    uint32_t     key_version;      /* Версия DEK, которой зашифрован payload */
    uint8_t      iv[DATA_IV_SIZE]; /* Вектор инициализации (16 байт) */
    uint64_t     created_at;       /* Время создания */
} iv_file_entry;

/* =====================================================================
 * Структуры данных — состояние в памяти
 * ===================================================================== */

/*
 * Расшифрованный DEK для одной таблицы (хранится в памяти процесса).
 */
typedef struct {
    uint8_t dek[DEK_SIZE];                   /* Расшифрованный ключ таблицы */
    uint8_t wrapped_dek[WRAPPED_DEK_SIZE];   /* Обёрнутая копия (для записи в файл) */
    Oid     table_oid;                       /* OID таблицы */
    uint32_t key_version;                    /* Версия DEK таблицы */
    bool     is_active;                      /* true = активный DEK для новых записей */
        kuz_key_t round_keys;                    /* Кэшированные раундовые ключи Kuznechik */
        bool     round_keys_ready;               /* true, если round_keys инициализированы */
} opentde_key_entry;

/*
 * IV кортежа в памяти (без временной метки).
 */
typedef struct {
    Oid          table_oid;
    BlockNumber  block;
    OffsetNumber offset;
    uint32_t     key_version;
    uint8_t      iv[DATA_IV_SIZE];
} opentde_iv_entry;

/*
 * Глобальный менеджер ключей — синглтон в TopMemoryContext.
 * Хранит мастер-ключ, все DEK таблиц и все IV кортежей.
 */
typedef struct {
    uint8_t           master_key[MASTER_KEY_SIZE];
    opentde_key_entry *keys;          /* Динамический массив DEK */
    int               key_count;
    int               key_capacity;
    opentde_iv_entry  *ivs;           /* Динамический массив IV */
    int               iv_count;
    int               iv_capacity;
} opentde_key_manager;

/* =====================================================================
 * Глобальные переменные (определены в opentde_keymanager.c)
 * ===================================================================== */
extern opentde_key_manager *global_key_mgr;
extern bool master_key_set;

/* =====================================================================
 * Прототипы — opentde_keymanager.c
 * ===================================================================== */

/* Инициализация менеджера ключей (выделение памяти) */
void opentde_init_key_manager(void);

/* Получение пути к PGDATA */
char *opentde_get_pgdata_path(void);

/* Создание директории pg_encryption в PGDATA */
void opentde_ensure_key_directory(void);

/* Загрузка / сохранение файла ключей (DEK) */
bool opentde_load_key_file(void);
void opentde_save_key_file(void);

/* Загрузка / сохранение файла IV */
bool opentde_load_iv_file(void);
void opentde_save_iv_file(void);

/* Загрузка / сохранение мастер-ключа из файла */
bool opentde_load_master_key_from_file(void);
void opentde_save_master_key_to_file(void);

/* Регистрация и поиск IV для кортежа */
void opentde_register_tuple_iv(Oid table_oid, const ItemPointer tid,
                                                             const uint8_t *iv, uint32_t key_version);
bool opentde_lookup_tuple_iv(Oid table_oid, const ItemPointer tid,
                                                         uint8_t *iv_out, uint32_t *key_version_out);

/* =====================================================================
 * Прототипы — opentde_crypto.c
 * ===================================================================== */

/* Генерация криптографически стойких случайных байт */
void opentde_fill_random_bytes(uint8_t *buf, size_t len,
                               const char *context_name);

/* Обёртывание DEK мастер-ключом (шифрование для хранения на диске) */
void opentde_wrap_dek(const uint8_t *master_key, const uint8_t *dek,
                      uint8_t *wrapped);

/* Разворачивание DEK (расшифровка из файла) */
bool opentde_unwrap_dek(const uint8_t *master_key, const uint8_t *wrapped_dek,
                        uint8_t *dek);

/* Получение DEK для таблицы (создаёт новый, если не существует) */
uint8_t *opentde_get_table_dek(Oid table_oid);
uint8_t *opentde_get_table_dek_by_version(Oid table_oid, uint32_t key_version);
uint32_t opentde_get_active_table_key_version(Oid table_oid);
uint32_t opentde_rotate_table_dek(Oid table_oid);

/* Шифрование / дешифрование данных шифром «Кузнечик» в режиме CTR */
void opentde_gost_encrypt_decrypt(char *data, int len, Oid table_oid,
                                  uint32_t key_version, const uint8_t *iv);

/* Шифрование payload кортежа в памяти (in-place, до вызова heap_insert) */
int opentde_encrypt_tuple_inplace(HeapTuple tuple, Oid table_oid,
                                  uint8_t *iv_out,
                                  uint32_t *key_version_out);

#endif /* OPENTDE_H */
