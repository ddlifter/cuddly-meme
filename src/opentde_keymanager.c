/*
 * opentde_keymanager.c — Модуль управления ключами OpenTDE.
 *
 * Отвечает за:
 *   - Хранение и загрузку мастер-ключа (pg_encryption/master.key)
 *   - Создание, обёртывание и хранение DEK таблиц (pg_encryption/keys)
 *   - Хранение и загрузку IV кортежей (pg_encryption/ivs)
 *   - Поиск IV по TID (таблица + блок + смещение)
 *
 * Все данные хранятся в бинарных файлах в каталоге PGDATA/pg_encryption.
 * Формат файлов включает magic-значение и версию для защиты от повреждений.
 */
#include "opentde.h"

#include "port.h"          /* PG_BINARY */
#include "utils/guc.h"     /* GetConfigOption */

#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* =====================================================================
 * Глобальные переменные модуля
 * ===================================================================== */

/* Синглтон менеджера ключей; инициализируется при первом обращении */
opentde_key_manager *global_key_mgr = NULL;

/* Флаг: мастер-ключ установлен (вручную или загружен из файла) */
bool master_key_set = false;

/* =====================================================================
 * Внутренние вспомогательные функции (static)
 * ===================================================================== */

/*
 * Возвращает полный путь к файлу ключей: $PGDATA/pg_encryption/keys.
 */
static char *
get_key_file_path(void)
{
    char *pgdata;
    char *key_path;

    pgdata = opentde_get_pgdata_path();
    key_path = psprintf("%s/%s", pgdata, KEY_FILE_PATH);
    pfree(pgdata);
    return key_path;
}

/*
 * Возвращает полный путь к файлу IV: $PGDATA/pg_encryption/ivs.
 */
static char *
get_iv_file_path(void)
{
    char *pgdata;
    char *iv_path;

    pgdata = opentde_get_pgdata_path();
    iv_path = psprintf("%s/%s", pgdata, IV_FILE_PATH);
    pfree(pgdata);
    return iv_path;
}

/* =====================================================================
 * Экспортируемые функции — общие утилиты
 * ===================================================================== */

/*
 * Получение пути к каталогу данных PostgreSQL ($PGDATA).
 * Использует GUC-параметр data_directory.
 */
char *
opentde_get_pgdata_path(void)
{
    const char *data_dir;

    data_dir = GetConfigOption("data_directory", false, false);
    return pstrdup(data_dir);
}

/*
 * Создание директории pg_encryption внутри PGDATA (если не существует).
 * Права доступа: 0700 (только владелец сервера).
 */
void
opentde_ensure_key_directory(void)
{
    char *pgdata;
    char *dir_path;

    pgdata = opentde_get_pgdata_path();
    dir_path = psprintf("%s/pg_encryption", pgdata);
    mkdir(dir_path, 0700);
    pfree(dir_path);
    pfree(pgdata);
}

/*
 * Инициализация менеджера ключей.
 * Выделяет память в TopMemoryContext (живёт всё время жизни бэкенда).
 * При повторном вызове ничего не делает (идемпотентна).
 */
void
opentde_init_key_manager(void)
{
    if (global_key_mgr)
        return;

    global_key_mgr = MemoryContextAllocZero(TopMemoryContext,
                                            sizeof(opentde_key_manager));

    /* Массив ключей таблиц (DEK) */
    global_key_mgr->key_capacity = INITIAL_KEY_CAPACITY;
    global_key_mgr->keys = MemoryContextAllocZero(
        TopMemoryContext,
        global_key_mgr->key_capacity * sizeof(opentde_key_entry));

    /* Массив IV кортежей */
    global_key_mgr->iv_capacity = INITIAL_IV_CAPACITY;
    global_key_mgr->ivs = MemoryContextAllocZero(
        TopMemoryContext,
        global_key_mgr->iv_capacity * sizeof(opentde_iv_entry));
}

/* =====================================================================
 * Файл ключей (DEK) — pg_encryption/keys
 *
 * Формат:
 *   [key_file_header]          — 64 байта
 *   [key_file_entry] * N       — по 60 байт на запись
 *
 * При загрузке каждый обёрнутый DEK расшифровывается мастер-ключом.
 * При сохранении каждый открытый DEK заново оборачивается (новый IV).
 * ===================================================================== */

/*
 * Загрузка файла ключей с диска.
 * Требует: мастер-ключ установлен, менеджер инициализирован, ключи ещё не загружены.
 * Возвращает true при успехе.
 */
bool
opentde_load_key_file(void)
{
    char            *key_path;
    int              fd;
    key_file_header  header;
    int              entries_read;
    uint32_t         i;

    key_path = get_key_file_path();
    entries_read = 0;

    /* Загрузка возможна только при установленном мастер-ключе и пустом массиве */
    if (!master_key_set || !global_key_mgr || global_key_mgr->key_count > 0)
    {
        pfree(key_path);
        return false;
    }

    fd = open(key_path, O_RDONLY | PG_BINARY, 0600);
    if (fd < 0)
    {
        pfree(key_path);
        return false;
    }

    /* Чтение и валидация заголовка */
    if (read(fd, &header, sizeof(key_file_header)) != sizeof(key_file_header))
    {
        close(fd);
        pfree(key_path);
        return false;
    }

    if (header.magic != KEY_FILE_MAGIC)
    {
        close(fd);
        pfree(key_path);
        return false;
    }

    if (header.version != KEY_VERSION)
    {
        close(fd);
        elog(WARNING,
             "[OpenTDE] unsupported key file version %u (expected %u); ignoring old key file",
             header.version, KEY_VERSION);
        pfree(key_path);
        return false;
    }

    /* Последовательное чтение записей DEK */
    for (i = 0; i < header.key_count; i++)
    {
        key_file_entry entry;

        if (read(fd, &entry, sizeof(key_file_entry)) != sizeof(key_file_entry))
            break;

        /* Расширение массива при необходимости (удвоение ёмкости) */
        if (global_key_mgr->key_count >= global_key_mgr->key_capacity)
        {
            global_key_mgr->key_capacity *= 2;
            global_key_mgr->keys = repalloc(
                global_key_mgr->keys,
                global_key_mgr->key_capacity * sizeof(opentde_key_entry));
        }

        global_key_mgr->keys[global_key_mgr->key_count].table_oid = entry.table_oid;
        memcpy(global_key_mgr->keys[global_key_mgr->key_count].wrapped_dek,
               entry.wrapped_dek, WRAPPED_DEK_SIZE);

        /* Разворачивание DEK мастер-ключом; пропускаем при ошибке */
        if (!opentde_unwrap_dek(global_key_mgr->master_key,
                                entry.wrapped_dek,
                                global_key_mgr->keys[global_key_mgr->key_count].dek))
        {
            continue;
        }

        global_key_mgr->key_count++;
        entries_read++;
    }

    close(fd);
    elog(LOG, "[OpenTDE] Loaded %d keys from %s", entries_read, key_path);
    pfree(key_path);
    return true;
}

/*
 * Сохранение всех DEK в файл ключей.
 * Каждый DEK заново оборачивается мастер-ключом (со свежим IV).
 * Файл перезаписывается целиком (O_TRUNC).
 */
void
opentde_save_key_file(void)
{
    char            *key_path;
    int              fd;
    key_file_header  header;
    int              i;

    key_path = get_key_file_path();
    opentde_ensure_key_directory();

    fd = open(key_path, O_RDWR | O_CREAT | O_TRUNC | PG_BINARY, 0600);
    if (fd < 0)
    {
        pfree(key_path);
        ereport(ERROR,
                (errcode_for_file_access(),
                 errmsg("cannot open key file %s", key_path)));
    }

    /* Формирование и запись заголовка */
    memset(&header, 0, sizeof(header));
    header.magic     = KEY_FILE_MAGIC;
    header.version   = KEY_VERSION;
    header.key_count = (uint32_t) global_key_mgr->key_count;

    if (write(fd, &header, sizeof(key_file_header)) != sizeof(key_file_header))
    {
        close(fd);
        pfree(key_path);
        ereport(ERROR,
                (errcode_for_file_access(),
                 errmsg("cannot write key file header")));
    }

    /* Запись каждого DEK в обёрнутом виде */
    for (i = 0; i < global_key_mgr->key_count; i++)
    {
        key_file_entry entry;

        memset(&entry, 0, sizeof(entry));
        entry.table_oid  = global_key_mgr->keys[i].table_oid;
        entry.created_at = (uint64_t) time(NULL);

        opentde_wrap_dek(global_key_mgr->master_key,
                         global_key_mgr->keys[i].dek,
                         entry.wrapped_dek);

        memcpy(global_key_mgr->keys[i].wrapped_dek,
               entry.wrapped_dek, WRAPPED_DEK_SIZE);

        if (write(fd, &entry, sizeof(key_file_entry)) != sizeof(key_file_entry))
        {
            close(fd);
            pfree(key_path);
            ereport(ERROR,
                    (errcode_for_file_access(),
                     errmsg("cannot write key entry %d", i)));
        }
    }

    close(fd);
    elog(LOG, "[OpenTDE] Saved %d keys to %s", global_key_mgr->key_count, key_path);
    pfree(key_path);
}

/* =====================================================================
 * Файл IV кортежей — pg_encryption/ivs
 *
 * Формат:
 *   [iv_file_header]           — 64 байта
 *   [iv_file_entry] * N        — по 36 байт на запись
 *
 * Каждый кортеж имеет свой уникальный случайный IV для режима CTR.
 * ===================================================================== */

/*
 * Загрузка файла IV с диска.
 * Вызывается при старте бэкенда (из _PG_init) или при установке мастер-ключа.
 */
bool
opentde_load_iv_file(void)
{
    char            *iv_path;
    int              fd;
    iv_file_header   header;
    uint32_t         i;
    int              entries_read;

    if (!global_key_mgr || global_key_mgr->iv_count > 0)
        return false;

    iv_path = get_iv_file_path();
    entries_read = 0;

    fd = open(iv_path, O_RDONLY | PG_BINARY, 0600);
    if (fd < 0)
    {
        pfree(iv_path);
        return false;
    }

    /* Валидация заголовка: magic + версия */
    if (read(fd, &header, sizeof(iv_file_header)) != sizeof(iv_file_header))
    {
        close(fd);
        pfree(iv_path);
        return false;
    }

    if (header.magic != IV_FILE_MAGIC || header.version != IV_VERSION)
    {
        close(fd);
        pfree(iv_path);
        return false;
    }

    /* Чтение записей IV */
    for (i = 0; i < header.iv_count; i++)
    {
        iv_file_entry entry;

        if (read(fd, &entry, sizeof(iv_file_entry)) != sizeof(iv_file_entry))
            break;

        /* Расширение динамического массива при необходимости */
        if (global_key_mgr->iv_count >= global_key_mgr->iv_capacity)
        {
            global_key_mgr->iv_capacity *= 2;
            global_key_mgr->ivs = repalloc(
                global_key_mgr->ivs,
                global_key_mgr->iv_capacity * sizeof(opentde_iv_entry));
        }

        global_key_mgr->ivs[global_key_mgr->iv_count].table_oid = entry.table_oid;
        global_key_mgr->ivs[global_key_mgr->iv_count].block     = entry.block;
        global_key_mgr->ivs[global_key_mgr->iv_count].offset    = entry.offset;
        memcpy(global_key_mgr->ivs[global_key_mgr->iv_count].iv, entry.iv, DATA_IV_SIZE);

        global_key_mgr->iv_count++;
        entries_read++;
    }

    close(fd);
    elog(LOG, "[OpenTDE] Loaded %d tuple IVs from %s", entries_read, iv_path);
    pfree(iv_path);
    return true;
}

/*
 * Сохранение всех IV в файл. Файл перезаписывается целиком.
 * Вызывается после каждого register_tuple_iv, чтобы IV не терялись
 * при аварийной перезагрузке.
 */
void
opentde_save_iv_file(void)
{
    char            *iv_path;
    int              fd;
    iv_file_header   header;
    int              i;

    if (!global_key_mgr)
        return;

    iv_path = get_iv_file_path();
    opentde_ensure_key_directory();

    fd = open(iv_path, O_RDWR | O_CREAT | O_TRUNC | PG_BINARY, 0600);
    if (fd < 0)
    {
        pfree(iv_path);
        ereport(ERROR,
                (errcode_for_file_access(),
                 errmsg("cannot open iv file %s", iv_path)));
    }

    memset(&header, 0, sizeof(header));
    header.magic    = IV_FILE_MAGIC;
    header.version  = IV_VERSION;
    header.iv_count = (uint32_t) global_key_mgr->iv_count;

    if (write(fd, &header, sizeof(iv_file_header)) != sizeof(iv_file_header))
    {
        close(fd);
        pfree(iv_path);
        ereport(ERROR,
                (errcode_for_file_access(),
                 errmsg("cannot write iv file header")));
    }

    for (i = 0; i < global_key_mgr->iv_count; i++)
    {
        iv_file_entry entry;

        memset(&entry, 0, sizeof(entry));
        entry.table_oid  = global_key_mgr->ivs[i].table_oid;
        entry.block      = global_key_mgr->ivs[i].block;
        entry.offset     = global_key_mgr->ivs[i].offset;
        entry.created_at = (uint64_t) time(NULL);
        memcpy(entry.iv, global_key_mgr->ivs[i].iv, DATA_IV_SIZE);

        if (write(fd, &entry, sizeof(iv_file_entry)) != sizeof(iv_file_entry))
        {
            close(fd);
            pfree(iv_path);
            ereport(ERROR,
                    (errcode_for_file_access(),
                     errmsg("cannot write iv entry %d", i)));
        }
    }

    close(fd);
    pfree(iv_path);
}

/* =====================================================================
 * Регистрация и поиск IV кортежей
 *
 * Каждый кортеж идентифицируется тройкой (table_oid, block, offset).
 * При UPDATE IV перезаписывается для нового TID.
 * ===================================================================== */

/*
 * Регистрация IV для кортежа.
 * Если запись с таким TID уже есть — обновляет IV (случай UPDATE).
 * Иначе добавляет новую запись. После изменения сохраняет файл.
 */
void
opentde_register_tuple_iv(Oid table_oid, const ItemPointer tid,
                          const uint8_t *iv)
{
    BlockNumber  block;
    OffsetNumber offset;
    int          i;

    if (!global_key_mgr || !ItemPointerIsValid(tid))
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("cannot register tuple IV without a valid TID")));

    block  = ItemPointerGetBlockNumber(tid);
    offset = ItemPointerGetOffsetNumber(tid);

    /* Поиск существующей записи (обновление при UPDATE) */
    for (i = 0; i < global_key_mgr->iv_count; i++)
    {
        opentde_iv_entry *entry = &global_key_mgr->ivs[i];

        if (entry->table_oid == table_oid &&
            entry->block == block &&
            entry->offset == offset)
        {
            memcpy(entry->iv, iv, DATA_IV_SIZE);
            opentde_save_iv_file();
            return;
        }
    }

    /* Расширение массива при необходимости */
    if (global_key_mgr->iv_count >= global_key_mgr->iv_capacity)
    {
        global_key_mgr->iv_capacity *= 2;
        global_key_mgr->ivs = repalloc(
            global_key_mgr->ivs,
            global_key_mgr->iv_capacity * sizeof(opentde_iv_entry));
    }

    /* Добавление новой записи */
    global_key_mgr->ivs[global_key_mgr->iv_count].table_oid = table_oid;
    global_key_mgr->ivs[global_key_mgr->iv_count].block     = block;
    global_key_mgr->ivs[global_key_mgr->iv_count].offset    = offset;
    memcpy(global_key_mgr->ivs[global_key_mgr->iv_count].iv, iv, DATA_IV_SIZE);
    global_key_mgr->iv_count++;

    opentde_save_iv_file();
}

/*
 * Поиск IV для кортежа по TID.
 * Ищет с конца массива (более новые записи проверяются первыми).
 * Возвращает true при нахождении, копируя IV в iv_out.
 */
bool
opentde_lookup_tuple_iv(Oid table_oid, const ItemPointer tid,
                        uint8_t *iv_out)
{
    int          i;
    BlockNumber  block;
    OffsetNumber offset;

    if (!global_key_mgr || !ItemPointerIsValid(tid))
        return false;

    block  = ItemPointerGetBlockNumber(tid);
    offset = ItemPointerGetOffsetNumber(tid);

    /* Обратный обход — последняя запись наиболее актуальна */
    for (i = global_key_mgr->iv_count - 1; i >= 0; i--)
    {
        opentde_iv_entry *entry = &global_key_mgr->ivs[i];

        if (entry->table_oid == table_oid &&
            entry->block == block &&
            entry->offset == offset)
        {
            memcpy(iv_out, entry->iv, DATA_IV_SIZE);
            return true;
        }
    }

    return false;
}

/* =====================================================================
 * Мастер-ключ — pg_encryption/master.key
 *
 * Мастер-ключ хранится в открытом виде (32 байта).
 * Используется для обёртывания/разворачивания DEK таблиц.
 * При старте бэкенда автоматически загружается из файла.
 * ===================================================================== */

/*
 * Автозагрузка мастер-ключа из файла.
 * Вызывается в _PG_init при старте каждого бэкенда.
 * Возвращает true, если ключ успешно загружен.
 */
bool
opentde_load_master_key_from_file(void)
{
    char    *pgdata;
    char    *key_path;
    int      fd;
    uint8_t  key[MASTER_KEY_SIZE];
    ssize_t  bytes_read;

    pgdata   = opentde_get_pgdata_path();
    key_path = psprintf("%s/%s", pgdata, MASTER_KEY_PATH);
    pfree(pgdata);

    fd = open(key_path, O_RDONLY | PG_BINARY, 0600);
    if (fd < 0)
    {
        pfree(key_path);
        return false;
    }

    bytes_read = read(fd, key, MASTER_KEY_SIZE);
    close(fd);
    pfree(key_path);

    if (bytes_read != MASTER_KEY_SIZE)
        return false;

    opentde_init_key_manager();
    memcpy(global_key_mgr->master_key, key, MASTER_KEY_SIZE);
    master_key_set = true;

    elog(LOG, "[OpenTDE] Master key auto-loaded from %s", MASTER_KEY_PATH);
    return true;
}

/*
 * Сохранение мастер-ключа в файл.
 * Вызывается из opentde_set_master_key() после установки ключа пользователем.
 */
void
opentde_save_master_key_to_file(void)
{
    char    *pgdata;
    char    *key_path;
    int      fd;
    ssize_t  bytes_written;

    pgdata   = opentde_get_pgdata_path();
    key_path = psprintf("%s/%s", pgdata, MASTER_KEY_PATH);

    opentde_ensure_key_directory();

    fd = open(key_path, O_RDWR | O_CREAT | O_TRUNC | PG_BINARY, 0600);
    if (fd < 0)
    {
        pfree(key_path);
        pfree(pgdata);
        ereport(ERROR,
                (errcode_for_file_access(),
                 errmsg("cannot open master key file %s", key_path)));
    }

    bytes_written = write(fd, global_key_mgr->master_key, MASTER_KEY_SIZE);
    close(fd);
    pfree(key_path);
    pfree(pgdata);

    if (bytes_written != MASTER_KEY_SIZE)
        ereport(ERROR,
                (errcode_for_file_access(),
                 errmsg("cannot write full master key")));

    elog(LOG, "[OpenTDE] Master key saved to %s", MASTER_KEY_PATH);
}
