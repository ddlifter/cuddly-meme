

#ifndef OPENTDE_H
#define OPENTDE_H

/* Vault environment variable defaults */
#define OPENTDE_VAULT_FIELD_DEFAULT "master_key"
#define OPENTDE_VAULT_PATH_DEFAULT  "secret/pg_tde"
#define OPENTDE_VAULT_TOKEN_DEFAULT "root"

#include <stddef.h>
#include <stdbool.h>
#include "postgres.h"
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

#include <stddef.h>
#include <stdbool.h>
#include "postgres.h"
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

/* Размеры криптографических параметров в байтах */
#define MASTER_KEY_SIZE   32
#define DEK_SIZE          32
#define DATA_IV_SIZE      16
#define WRAPPED_DEK_SIZE  (DATA_IV_SIZE + DEK_SIZE)

/* Начальные размеры динамических массивов */
#define INITIAL_KEY_CAPACITY  64
#define INITIAL_IV_CAPACITY   1024


typedef struct {
    uint32_t magic;
    uint8_t  version;
    uint8_t  pad[3];        /* Выравнивание */
    uint32_t key_count;     /* Количество записей */
    uint32_t reserved[13];  /* Резерв для будущих полей */
} key_file_header;

typedef struct {
    uint8_t dek[DEK_SIZE];                   /* Расшифрованный ключ таблицы */
    uint8_t wrapped_dek[WRAPPED_DEK_SIZE];   /* Обёрнутая копия (для записи в файл) */
    Oid     table_oid;                       /* OID таблицы */
    uint32_t key_version;                    /* Версия DEK таблицы */
    bool     is_active;                      /* true = активный DEK для новых записей */
} opentde_key_entry;

typedef struct {
    uint8_t           master_key[MASTER_KEY_SIZE];
    opentde_key_entry *keys;          /* Динамический массив DEK */
    int               key_count;
    int               key_capacity;
} opentde_key_manager;


extern opentde_key_manager *global_key_mgr;
extern bool master_key_set;
extern Oid opentde_pending_index_parent_storage_oid;
extern Oid opentde_pending_index_child_storage_oid;

typedef struct {
    Oid     table_oid;
    uint32_t key_version;
    uint8_t  wrapped_dek[WRAPPED_DEK_SIZE];
    uint8_t  is_active;
    uint64_t created_at;
} key_file_entry;

void opentde_ensure_keys_loaded(void);
void opentde_install_md_hooks(void);
void opentde_init_utility_hooks(void);
void opentde_init_key_manager(void);
bool opentde_load_key_file(void);
bool opentde_reload_key_file(void);
bool opentde_load_master_key_from_file(void);
void opentde_save_master_key_to_file(void);
void opentde_ensure_key_directory(void);
char *opentde_get_pgdata_path(void);
void opentde_save_key_file(void);
void opentde_forget_table_keys(Oid table_oid);
bool opentde_storage_key_exists(Oid storage_oid);
void opentde_copy_active_storage_key(Oid source_storage_oid, Oid target_storage_oid);
void opentde_reencrypt_relation_storage(Oid relation_oid);



/* Загрузка / сохранение файла IV */

/* Загрузка / сохранение мастер-ключа из файла */
bool opentde_load_master_key_from_file(void);
void opentde_save_master_key_to_file(void);

/* Регистрация и поиск IV для кортежа */

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




#endif /* OPENTDE_H */
