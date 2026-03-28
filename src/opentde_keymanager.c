#include "opentde.h"
#include "port.h"
#include "utils/guc.h"
#include "utils/hsearch.h"
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define OPENTDE_VAULT_ADDR_DEFAULT   "http://127.0.0.1:8200"
#define OPENTDE_VAULT_PATH_DEFAULT   "secret/data/opentde/master"
#define OPENTDE_VAULT_FIELD_DEFAULT  "key_hex"
#define OPENTDE_VAULT_TOKEN_DEFAULT  "root"
#define OPENTDE_IV_FLUSH_EVERY       1000

typedef struct {
    Oid          table_oid;
    BlockNumber  block;
    OffsetNumber offset;
} opentde_iv_hash_key;

typedef struct {
    opentde_iv_hash_key key;
    int                 index;
} opentde_iv_hash_entry;

/* Формат записи key-файла до KEY_VERSION=3 */
typedef struct {
    Oid      table_oid;
    uint8_t  wrapped_dek[WRAPPED_DEK_SIZE];
    uint64_t created_at;
} key_file_entry_v2;

/* Формат записи iv-файла до IV_VERSION=2 */
typedef struct {
    Oid          table_oid;
    BlockNumber  block;
    OffsetNumber offset;
    uint16_t     pad;
    uint8_t      iv[DATA_IV_SIZE];
    uint64_t     created_at;
} iv_file_entry_v1;

/* Синглтон менеджера ключей; инициализируется при первом обращении */
opentde_key_manager *global_key_mgr = NULL;

/* Флаг: мастер-ключ установлен */
bool master_key_set = false;

/* Счётчик несброшенных IV-изменений для пакетной записи на диск. */
static int opentde_pending_iv_flush = 0;
/* Хеш-индекс IV по (table_oid, block, offset) -> index в global_key_mgr->ivs */
static HTAB *opentde_iv_hash = NULL;
/* Сколько записей сейчас в iv-файле на диске. */
static uint32 opentde_iv_file_entry_count = 0;

static char *get_iv_file_path(void);

static void
opentde_append_iv_file_entry(Oid table_oid,
                             BlockNumber block,
                             OffsetNumber offset,
                             uint32_t key_version,
                             const uint8_t *iv)
{
    char          *iv_path;
    int            fd;
    struct stat    st;
    iv_file_header header;
    iv_file_entry  entry;

    opentde_ensure_key_directory();
    iv_path = get_iv_file_path();
    fd = open(iv_path, O_RDWR | O_CREAT | PG_BINARY, 0600);
    if (fd < 0)
    {
        pfree(iv_path);
        ereport(ERROR,
                (errcode_for_file_access(),
                 errmsg("cannot open iv file %s", iv_path)));
    }

    if (fstat(fd, &st) != 0)
    {
        close(fd);
        pfree(iv_path);
        ereport(ERROR,
                (errcode_for_file_access(),
                 errmsg("cannot stat iv file %s", iv_path)));
    }

    if ((size_t) st.st_size < sizeof(iv_file_header))
    {
        memset(&header, 0, sizeof(header));
        header.magic = IV_FILE_MAGIC;
        header.version = IV_VERSION;
        header.iv_count = 0;

        if (pwrite(fd, &header, sizeof(header), 0) != sizeof(header))
        {
            close(fd);
            pfree(iv_path);
            ereport(ERROR,
                    (errcode_for_file_access(),
                     errmsg("cannot write iv file header")));
        }
        opentde_iv_file_entry_count = 0;
    }
    else
    {
        if (pread(fd, &header, sizeof(header), 0) != sizeof(header))
        {
            close(fd);
            pfree(iv_path);
            ereport(ERROR,
                    (errcode_for_file_access(),
                     errmsg("cannot read iv file header")));
        }
        opentde_iv_file_entry_count = header.iv_count;
    }

    memset(&entry, 0, sizeof(entry));
    entry.table_oid = table_oid;
    entry.block = block;
    entry.offset = offset;
    entry.key_version = key_version;
    entry.created_at = (uint64_t) time(NULL);
    memcpy(entry.iv, iv, DATA_IV_SIZE);

    if (lseek(fd, 0, SEEK_END) < 0 ||
        write(fd, &entry, sizeof(entry)) != sizeof(entry))
    {
        ereport(ERROR,
                (errcode_for_file_access(),
                 errmsg("cannot append iv entry")));
    }

    header.magic = IV_FILE_MAGIC;
    header.version = IV_VERSION;
    header.iv_count = ++opentde_iv_file_entry_count;
    if (pwrite(fd, &header, sizeof(header), 0) != sizeof(header))
    {
        close(fd);
        pfree(iv_path);
        ereport(ERROR,
                (errcode_for_file_access(),
                 errmsg("cannot update iv file header")));
    }

    close(fd);
    pfree(iv_path);
}

static void
opentde_init_iv_hash(void)
{
    HASHCTL ctl;

    if (opentde_iv_hash)
        return;

    MemSet(&ctl, 0, sizeof(ctl));
    ctl.keysize = sizeof(opentde_iv_hash_key);
    ctl.entrysize = sizeof(opentde_iv_hash_entry);
    ctl.hcxt = TopMemoryContext;

    opentde_iv_hash = hash_create("OpenTDE tuple IV hash",
                                  INITIAL_IV_CAPACITY,
                                  &ctl,
                                  HASH_ELEM | HASH_BLOBS | HASH_CONTEXT);
}

static void
opentde_iv_hash_put(Oid table_oid, BlockNumber block, OffsetNumber offset, int index)
{
    opentde_iv_hash_key key;
    opentde_iv_hash_entry *entry;
    bool found;

    opentde_init_iv_hash();

    MemSet(&key, 0, sizeof(key));
    key.table_oid = table_oid;
    key.block = block;
    key.offset = offset;

    entry = (opentde_iv_hash_entry *) hash_search(opentde_iv_hash,
                                                  &key,
                                                  HASH_ENTER,
                                                  &found);
    entry->index = index;
}

static bool
opentde_iv_hash_get(Oid table_oid, BlockNumber block, OffsetNumber offset, int *index_out)
{
    opentde_iv_hash_key key;
    opentde_iv_hash_entry *entry;

    if (!opentde_iv_hash)
        return false;

    MemSet(&key, 0, sizeof(key));
    key.table_oid = table_oid;
    key.block = block;
    key.offset = offset;

    entry = (opentde_iv_hash_entry *) hash_search(opentde_iv_hash,
                                                  &key,
                                                  HASH_FIND,
                                                  NULL);
    if (!entry)
        return false;

    *index_out = entry->index;
    return true;
}

typedef struct {
    char   *data;
    size_t  size;
} opentde_http_response;

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

/* Берёт значение переменной окружения или возвращает default_value. */
static const char *
opentde_getenv_or_default(const char *name, const char *default_value)
{
    const char *value = getenv(name);

    if (value && value[0] != '\0')
        return value;

    return default_value;
}

/* Парсит HTTP URL вида http://host[:port]/path */
static bool
opentde_parse_http_url(const char *url,
                       char **host_out,
                       int *port_out,
                       char **path_out)
{
    const char *p;
    const char *host_start;
    const char *port_start;
    const char *path_start;
    int         host_len;

    if (strncmp(url, "http://", 7) != 0)
        return false;

    p = url + 7;
    host_start = p;

    while (*p && *p != ':' && *p != '/')
        p++;

    host_len = (int) (p - host_start);
    if (host_len <= 0)
        return false;

    *host_out = palloc(host_len + 1);
    memcpy(*host_out, host_start, host_len);
    (*host_out)[host_len] = '\0';

    *port_out = 80;

    if (*p == ':')
    {
        long parsed_port;

        port_start = ++p;
        while (*p && *p != '/')
            p++;

        if (p == port_start)
            return false;

        parsed_port = strtol(port_start, NULL, 10);
        if (parsed_port <= 0 || parsed_port > 65535)
            return false;

        *port_out = (int) parsed_port;
    }

    path_start = (*p == '/') ? p : "/";
    *path_out = pstrdup(path_start);

    return true;
}

/* Отправляет HTTP запрос через TCP-сокет и возвращает сырой ответ. */
static bool
opentde_http_send_request(const char *host,
                          int port,
                          const char *request,
                          opentde_http_response *resp)
{
    struct hostent     *server;
    struct sockaddr_in  serv_addr;
    int                 sockfd;
    ssize_t             sent_n;
    ssize_t             recv_n;
    const char         *send_ptr;
    size_t              send_left;
    char                chunk[2048];

    resp->data = NULL;
    resp->size = 0;

    server = gethostbyname(host);
    if (server == NULL)
        return false;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        return false;

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons((uint16_t) port);
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr_list[0], (size_t) server->h_length);

    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
    {
        close(sockfd);
        return false;
    }

    send_ptr = request;
    send_left = strlen(request);

    while (send_left > 0)
    {
        sent_n = send(sockfd, send_ptr, send_left, 0);
        if (sent_n <= 0)
        {
            close(sockfd);
            return false;
        }

        send_ptr += sent_n;
        send_left -= (size_t) sent_n;
    }

    while ((recv_n = recv(sockfd, chunk, sizeof(chunk), 0)) > 0)
    {
        size_t new_size;
        char  *new_data;

        new_size = resp->size + (size_t) recv_n;
        new_data = (char *) realloc(resp->data, new_size + 1);
        if (!new_data)
        {
            if (resp->data)
                free(resp->data);
            close(sockfd);
            resp->data = NULL;
            resp->size = 0;
            return false;
        }

        resp->data = new_data;
        memcpy(resp->data + resp->size, chunk, (size_t) recv_n);
        resp->size = new_size;
        resp->data[resp->size] = '\0';
    }

    close(sockfd);

    if (!resp->data)
    {
        resp->data = (char *) malloc(1);
        if (!resp->data)
            return false;
        resp->data[0] = '\0';
        resp->size = 0;
    }

    return true;
}

/* Вытаскивает последний HTTP status code из блока с сохранёнными заголовками. */
static long
opentde_extract_http_code(const char *headers_and_body)
{
    const char *p;
    long        code;
    long        last_code;

    p = headers_and_body;
    last_code = 0;

    while ((p = strstr(p, "HTTP/")) != NULL)
    {
        if (sscanf(p, "HTTP/%*d.%*d %ld", &code) == 1)
            last_code = code;
        p += 5;
    }

    return last_code;
}

/* Отделяет body от блока "headers + body" */
static char *
opentde_extract_http_body(const char *headers_and_body)
{
    const char *cursor;
    const char *body;
    const char *sep_crlf;
    const char *sep_lf;
    const char *next;
    size_t      body_len;
    char       *result;

    cursor = headers_and_body;
    body = headers_and_body;

    for (;;)
    {
        sep_crlf = strstr(cursor, "\r\n\r\n");
        sep_lf = strstr(cursor, "\n\n");

        if (sep_crlf && sep_lf)
            next = (sep_crlf < sep_lf) ? sep_crlf : sep_lf;
        else if (sep_crlf)
            next = sep_crlf;
        else
            next = sep_lf;

        if (!next)
            break;

        if (next == sep_crlf)
            body = next + 4;
        else
            body = next + 2;

        cursor = body;
    }

    body_len = strlen(body);
    result = (char *) malloc(body_len + 1);
    if (!result)
        return NULL;

    memcpy(result, body, body_len);
    result[body_len] = '\0';
    return result;
}

/* Формирует URL Vault API: <addr>/v1/<path>. */
static char *
opentde_vault_build_url(void)
{
    const char *addr;
    const char *path;

    addr = opentde_getenv_or_default("OPENTDE_VAULT_ADDR", OPENTDE_VAULT_ADDR_DEFAULT);
    path = opentde_getenv_or_default("OPENTDE_VAULT_PATH", OPENTDE_VAULT_PATH_DEFAULT);

    while (*path == '/')
        path++;

    return psprintf("%s/v1/%s", addr, path);
}

/* Выполняет HTTP-запрос к Vault API */
static bool
opentde_vault_http_request(const char *method,
                           const char *url,
                           const char *payload,
                           long *http_code_out,
                           char **response_out)
{
    const char           *token;
    const char           *payload_text;
    char                 *host;
    char                 *path;
    char                 *request;
    char                 *raw_body;
    int                   port;
    long                  code;
    size_t                payload_len;
    opentde_http_response resp;

    *http_code_out = 0;
    *response_out = NULL;

    token = opentde_getenv_or_default("OPENTDE_VAULT_TOKEN", OPENTDE_VAULT_TOKEN_DEFAULT);

    if (!opentde_parse_http_url(url, &host, &port, &path))
        return false;

    payload_text = payload ? payload : "";
    payload_len = strlen(payload_text);

    request = psprintf(
        "%s %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "X-Vault-Token: %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        method,
        path,
        host,
        token,
        payload_len,
        payload_text);
    if (!opentde_http_send_request(host, port, request, &resp))
    {
        pfree(request);
        pfree(path);
        pfree(host);
        return false;
    }

    pfree(request);
    pfree(path);
    pfree(host);

    code = opentde_extract_http_code(resp.data);
    raw_body = opentde_extract_http_body(resp.data);
    free(resp.data);

    if (!raw_body)
        return false;

    *http_code_out = code;
    *response_out = raw_body;

    if (*http_code_out == 0)
        *http_code_out = 500;

    return true;
}

/* Ищет строковое поле JSON вида "<field>":"<value>" и возвращает копию value. */
static char *
opentde_json_extract_string_field(const char *json, const char *field)
{
    char       *pattern;
    const char *start;
    const char *end;
    char       *result;
    int         value_len;

    pattern = psprintf("\"%s\":\"", field);
    start = strstr(json, pattern);
    pfree(pattern);

    if (!start)
        return NULL;

    start += strlen(field) + 4;
    end = strchr(start, '"');
    if (!end)
        return NULL;

    value_len = (int) (end - start);
    result = palloc(value_len + 1);
    memcpy(result, start, value_len);
    result[value_len] = '\0';

    return result;
}

/* hex -> bytes для фиксированной длины буфера. */
static bool
opentde_hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    size_t i;

    if (strlen(hex) != out_len * 2)
        return false;

    for (i = 0; i < out_len; i++)
    {
        unsigned int byte_val;

        if (sscanf(hex + (i * 2), "%2x", &byte_val) != 1)
            return false;

        out[i] = (uint8_t) byte_val;
    }

    return true;
}

/* bytes -> lowercase hex. */
static void
opentde_bytes_to_hex(const uint8_t *in, size_t len, char *out)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; i++)
    {
        out[i * 2] = hex[(in[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex[in[i] & 0x0F];
    }

    out[len * 2] = '\0';
}

/*
 * Получение пути к PGDATA.
 */
char *
opentde_get_pgdata_path(void)
{
    const char *data_dir;

    data_dir = GetConfigOption("data_directory", false, false);
    return pstrdup(data_dir);
}

/*
 * Создание директории pg_encryption внутри PGDATA.
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

    opentde_init_iv_hash();
}

/*
 * Загрузка файла ключей с диска.
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

    if (header.version != 2 && header.version != KEY_VERSION)
    {
        close(fd);
        elog(WARNING,
             "[OpenTDE] unsupported key file version %u (expected 2 or %u); ignoring old key file",
             header.version, KEY_VERSION);
        pfree(key_path);
        return false;
    }

    /* Последовательное чтение записей DEK */
    for (i = 0; i < header.key_count; i++)
    {
        opentde_key_entry *dst;

        /* Расширение массива при необходимости (удвоение ёмкости) */
        if (global_key_mgr->key_count >= global_key_mgr->key_capacity)
        {
            global_key_mgr->key_capacity *= 2;
            global_key_mgr->keys = repalloc(
                global_key_mgr->keys,
                global_key_mgr->key_capacity * sizeof(opentde_key_entry));
        }

        dst = &global_key_mgr->keys[global_key_mgr->key_count];

        if (header.version == 2)
        {
            key_file_entry_v2 entry_v2;

            if (read(fd, &entry_v2, sizeof(key_file_entry_v2)) != sizeof(key_file_entry_v2))
                break;

            dst->table_oid = entry_v2.table_oid;
            dst->key_version = DEFAULT_DEK_VERSION;
            dst->is_active = true;
            memcpy(dst->wrapped_dek, entry_v2.wrapped_dek, WRAPPED_DEK_SIZE);

            if (!opentde_unwrap_dek(global_key_mgr->master_key,
                                    entry_v2.wrapped_dek,
                                    dst->dek))
            {
                continue;
            }
        }
        else
        {
            key_file_entry entry;

            if (read(fd, &entry, sizeof(key_file_entry)) != sizeof(key_file_entry))
                break;

            dst->table_oid = entry.table_oid;
            dst->key_version = entry.key_version == 0 ? DEFAULT_DEK_VERSION : entry.key_version;
            dst->is_active = (entry.is_active != 0);
            memcpy(dst->wrapped_dek, entry.wrapped_dek, WRAPPED_DEK_SIZE);

            if (!opentde_unwrap_dek(global_key_mgr->master_key,
                                    entry.wrapped_dek,
                                    dst->dek))
            {
                continue;
            }
        }

        global_key_mgr->key_count++;
        entries_read++;
    }

    close(fd);
    elog(DEBUG1, "[OpenTDE] Loaded %d keys from %s", entries_read, key_path);
    pfree(key_path);
    return true;
}

/*
 * Сохранение всех DEK в файл ключей.
 * Каждый DEK заново оборачивается мастер-ключом.
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
        entry.table_oid   = global_key_mgr->keys[i].table_oid;
        entry.key_version = global_key_mgr->keys[i].key_version;
        entry.is_active   = global_key_mgr->keys[i].is_active ? 1 : 0;
        entry.created_at  = (uint64_t) time(NULL);

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
    elog(DEBUG1, "[OpenTDE] Saved %d keys to %s", global_key_mgr->key_count, key_path);
    pfree(key_path);
}

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

    if (header.magic != IV_FILE_MAGIC || (header.version != 1 && header.version != IV_VERSION))
    {
        close(fd);
        pfree(iv_path);
        return false;
    }

    opentde_iv_file_entry_count = header.iv_count;

    /* Чтение записей IV */
    for (i = 0; i < header.iv_count; i++)
    {
        opentde_iv_entry *dst;

        /* Расширение динамического массива при необходимости */
        if (global_key_mgr->iv_count >= global_key_mgr->iv_capacity)
        {
            global_key_mgr->iv_capacity *= 2;
            global_key_mgr->ivs = repalloc(
                global_key_mgr->ivs,
                global_key_mgr->iv_capacity * sizeof(opentde_iv_entry));
        }

        dst = &global_key_mgr->ivs[global_key_mgr->iv_count];

        if (header.version == 1)
        {
            iv_file_entry_v1 entry_v1;

            if (read(fd, &entry_v1, sizeof(iv_file_entry_v1)) != sizeof(iv_file_entry_v1))
                break;

            dst->table_oid = entry_v1.table_oid;
            dst->block = entry_v1.block;
            dst->offset = entry_v1.offset;
            dst->key_version = DEFAULT_DEK_VERSION;
            memcpy(dst->iv, entry_v1.iv, DATA_IV_SIZE);
        }
        else
        {
            iv_file_entry entry;

            if (read(fd, &entry, sizeof(iv_file_entry)) != sizeof(iv_file_entry))
                break;

            dst->table_oid = entry.table_oid;
            dst->block = entry.block;
            dst->offset = entry.offset;
            dst->key_version = entry.key_version == 0 ? DEFAULT_DEK_VERSION : entry.key_version;
            memcpy(dst->iv, entry.iv, DATA_IV_SIZE);
        }

        global_key_mgr->iv_count++;
        opentde_iv_hash_put(dst->table_oid, dst->block, dst->offset,
                            global_key_mgr->iv_count - 1);
        entries_read++;
    }

    close(fd);
    elog(DEBUG1, "[OpenTDE] Loaded %d tuple IVs from %s", entries_read, iv_path);
    pfree(iv_path);
    opentde_pending_iv_flush = 0;
    return true;
}

/*
 * Сохранение всех IV в файл. Файл перезаписывается целиком.
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
        entry.key_version = global_key_mgr->ivs[i].key_version;
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
    opentde_pending_iv_flush = 0;
    opentde_iv_file_entry_count = (uint32) global_key_mgr->iv_count;
}

/*
 * Регистрация IV для кортежа.
 */
void
opentde_register_tuple_iv(Oid table_oid, const ItemPointer tid,
                          const uint8_t *iv, uint32_t key_version)
{
    BlockNumber  block;
    OffsetNumber offset;
    int          i;
    int          cached_index = -1;

    if (!global_key_mgr || !ItemPointerIsValid(tid))
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("cannot register tuple IV without a valid TID")));

    block  = ItemPointerGetBlockNumber(tid);
    offset = ItemPointerGetOffsetNumber(tid);

    if (key_version == 0)
        key_version = DEFAULT_DEK_VERSION;

    if (opentde_iv_hash_get(table_oid, block, offset, &cached_index) &&
        cached_index >= 0 &&
        cached_index < global_key_mgr->iv_count)
    {
        opentde_iv_entry *entry = &global_key_mgr->ivs[cached_index];

        if (entry->table_oid == table_oid &&
            entry->block == block &&
            entry->offset == offset)
        {
            memcpy(entry->iv, iv, DATA_IV_SIZE);
            entry->key_version = key_version;
            opentde_append_iv_file_entry(table_oid, block, offset,
                                         key_version, iv);
            return;
        }
    }

    /* Поиск существующей записи (обновление при UPDATE) */
    for (i = 0; i < global_key_mgr->iv_count; i++)
    {
        opentde_iv_entry *entry = &global_key_mgr->ivs[i];

        if (entry->table_oid == table_oid &&
            entry->block == block &&
            entry->offset == offset)
        {
            memcpy(entry->iv, iv, DATA_IV_SIZE);
            entry->key_version = key_version;
            opentde_iv_hash_put(table_oid, block, offset, i);
            opentde_append_iv_file_entry(table_oid, block, offset,
                                         key_version, iv);
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
    global_key_mgr->ivs[global_key_mgr->iv_count].key_version = key_version;
    memcpy(global_key_mgr->ivs[global_key_mgr->iv_count].iv, iv, DATA_IV_SIZE);
    opentde_iv_hash_put(table_oid, block, offset, global_key_mgr->iv_count);
    global_key_mgr->iv_count++;

    opentde_append_iv_file_entry(table_oid, block, offset,
                                 key_version, iv);
}

/*
 * Поиск IV для кортежа по TID.
 */
bool
opentde_lookup_tuple_iv(Oid table_oid, const ItemPointer tid,
                        uint8_t *iv_out, uint32_t *key_version_out)
{
    int          i;
    BlockNumber  block;
    OffsetNumber offset;
    int          cached_index = -1;

    if (!global_key_mgr || !ItemPointerIsValid(tid))
        return false;

    block  = ItemPointerGetBlockNumber(tid);
    offset = ItemPointerGetOffsetNumber(tid);

    if (opentde_iv_hash_get(table_oid, block, offset, &cached_index) &&
        cached_index >= 0 &&
        cached_index < global_key_mgr->iv_count)
    {
        opentde_iv_entry *entry = &global_key_mgr->ivs[cached_index];

        if (entry->table_oid == table_oid &&
            entry->block == block &&
            entry->offset == offset)
        {
            memcpy(iv_out, entry->iv, DATA_IV_SIZE);
            if (key_version_out)
                *key_version_out = entry->key_version == 0 ? DEFAULT_DEK_VERSION : entry->key_version;
            return true;
        }
    }

    /* Обратный обход — последняя запись наиболее актуальна */
    for (i = global_key_mgr->iv_count - 1; i >= 0; i--)
    {
        opentde_iv_entry *entry = &global_key_mgr->ivs[i];

        if (entry->table_oid == table_oid &&
            entry->block == block &&
            entry->offset == offset)
        {
            opentde_iv_hash_put(table_oid, block, offset, i);
            memcpy(iv_out, entry->iv, DATA_IV_SIZE);
            if (key_version_out)
                *key_version_out = entry->key_version == 0 ? DEFAULT_DEK_VERSION : entry->key_version;
            return true;
        }
    }

    return false;
}

/*
 * Автозагрузка мастер-ключа из Vault.
 * Вызывается в _PG_init при старте каждого бэкенда.
 */
bool
opentde_load_master_key_from_file(void)
{
    char       *url;
    char       *response;
    char       *hex_value;
    const char *field_name;
    const char *vault_path;
    long        http_code;
    bool        ok;
    uint8_t     key[MASTER_KEY_SIZE];

    url = opentde_vault_build_url();
    field_name = opentde_getenv_or_default("OPENTDE_VAULT_FIELD", OPENTDE_VAULT_FIELD_DEFAULT);
    vault_path = opentde_getenv_or_default("OPENTDE_VAULT_PATH", OPENTDE_VAULT_PATH_DEFAULT);

    ok = opentde_vault_http_request("GET", url, NULL, &http_code, &response);
    pfree(url);

    if (!ok)
    {
        elog(WARNING, "[OpenTDE] Vault GET request failed while loading master key");
        return false;
    }

    if (http_code == 404)
    {
        free(response);
        return false;
    }

    if (http_code != 200)
    {
        elog(WARNING,
             "[OpenTDE] Vault returned HTTP %ld while loading master key",
             http_code);
        free(response);
        return false;
    }

    hex_value = opentde_json_extract_string_field(response, field_name);
    free(response);

    if (!hex_value)
    {
        elog(WARNING,
             "[OpenTDE] Vault secret does not contain field '%s'",
             field_name);
        return false;
    }

    if (!opentde_hex_to_bytes(hex_value, key, MASTER_KEY_SIZE))
    {
        pfree(hex_value);
        elog(WARNING, "[OpenTDE] Invalid master key format in Vault (expected %d-byte hex)",
             MASTER_KEY_SIZE);
        return false;
    }

    pfree(hex_value);

    opentde_init_key_manager();
    memcpy(global_key_mgr->master_key, key, MASTER_KEY_SIZE);
    master_key_set = true;

    elog(DEBUG1, "[OpenTDE] Master key auto-loaded from Vault path %s", vault_path);
    return true;
}

/*
 * Сохранение мастер-ключа в Vault.
 * Вызывается из opentde_set_master_key() после установки ключа пользователем.
 */
void
opentde_save_master_key_to_file(void)
{
    char        key_hex[MASTER_KEY_SIZE * 2 + 1];
    char       *url;
    char       *payload;
    char       *response;
    const char *field_name;
    const char *vault_path;
    long        http_code;
    bool        ok;

    if (!global_key_mgr)
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("key manager is not initialized")));

    field_name = opentde_getenv_or_default("OPENTDE_VAULT_FIELD", OPENTDE_VAULT_FIELD_DEFAULT);
    vault_path = opentde_getenv_or_default("OPENTDE_VAULT_PATH", OPENTDE_VAULT_PATH_DEFAULT);

    opentde_bytes_to_hex(global_key_mgr->master_key, MASTER_KEY_SIZE, key_hex);

    url = opentde_vault_build_url();
    payload = psprintf("{\"data\":{\"%s\":\"%s\"}}", field_name, key_hex);

    ok = opentde_vault_http_request("POST", url, payload, &http_code, &response);

    pfree(url);
    pfree(payload);

    if (!ok)
        ereport(ERROR,
                (errcode(ERRCODE_CONNECTION_FAILURE),
                 errmsg("Vault POST request failed while saving master key")));

    if (http_code != 200 && http_code != 204)
        ereport(ERROR,
                (errcode(ERRCODE_CONNECTION_EXCEPTION),
                 errmsg("Vault returned HTTP %ld while saving master key", http_code),
                 errdetail("Vault response: %s", response ? response : "<empty>")));

    if (response)
        free(response);

    elog(DEBUG1, "[OpenTDE] Master key saved to Vault path %s", vault_path);
}
