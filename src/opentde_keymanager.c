#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

// Вспомогательная функция для записи ответа libcurl в буфер
static size_t curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    char **response_ptr = (char **)userp;
    size_t old_len = *response_ptr ? strlen(*response_ptr) : 0;
    *response_ptr = realloc(*response_ptr, old_len + realsize + 1);
    if (*response_ptr == NULL) return 0;
    memcpy(*response_ptr + old_len, contents, realsize);
    (*response_ptr)[old_len + realsize] = '\0';
    return realsize;
}
#include "opentde.h"
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include "postgres.h"
#include "utils/guc.h"

/*
 * Гарантирует, что мастер-ключ и DEK загружены в память процесса.
 * Если ключи не загружены — пытается загрузить их с диска/Vault.
 */
opentde_key_manager *global_key_mgr = NULL; // Define the global key manager pointer (was only declared as extern)
bool master_key_set = false; // Define the global master key set flag (was only declared as extern)

static time_t key_file_last_mtime = 0;
static off_t key_file_last_size = 0;
static bool master_key_load_failed_logged = false;

static void
opentde_record_key_file_signature(const char *key_path)
{
    struct stat st;

    if (stat(key_path, &st) == 0)
    {
        key_file_last_mtime = st.st_mtime;
        key_file_last_size = st.st_size;
    }
}
void opentde_ensure_keys_loaded(void)
{
    if (master_key_set)
        return;

    if (opentde_load_master_key_from_file())
    {
        master_key_set = true;
        master_key_load_failed_logged = false;

        if (!global_key_mgr)
            opentde_init_key_manager();
        opentde_load_key_file();
    }
    else
    {
        if (!master_key_load_failed_logged)
        {
            elog(LOG,
                 "[OpenTDE] master key is unavailable from Vault; backend will keep retrying load");
            master_key_load_failed_logged = true;
        }
    }
}
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

/*
 * Берёт значение из нового имени переменной, а затем из legacy-алиаса.
 * Это позволяет поддерживать оба варианта: OPENTDE_VAULT_* и VAULT_*.
 */
static const char *
opentde_getenv_compat(const char *primary_name,
                      const char *fallback_name,
                      const char *default_value)
{
    const char *value = getenv(primary_name);

    if (value && value[0] != '\0')
        return value;

    value = getenv(fallback_name);
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

    // Для Vault kv v2: ищем "data":{"data":{"master_key":"..."}}
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
    addr = opentde_getenv_compat("OPENTDE_VAULT_ADDR", "VAULT_ADDR", OPENTDE_VAULT_ADDR_DEFAULT);
    path = opentde_getenv_compat("OPENTDE_VAULT_PATH", "VAULT_PATH", OPENTDE_VAULT_PATH_DEFAULT);
    if (strncmp(path, "secret/data/", 12) == 0)
        return psprintf("%s/v1/%s", addr, path);
    else if (strncmp(path, "secret/", 7) == 0)
        return psprintf("%s/v1/secret/data/%s", addr, path + 7);
    else
        return psprintf("%s/v1/secret/data/%s", addr, path);
}

/* Выполняет HTTP-запрос к Vault API */
static bool
opentde_vault_http_request(const char *method,
                           const char *url,
                           const char *payload,
                           long *http_code_out,
                           char **response_out)
{
    const char *token = opentde_getenv_compat("OPENTDE_VAULT_TOKEN", "VAULT_TOKEN", OPENTDE_VAULT_TOKEN_DEFAULT);
    bool ok = false;

    *http_code_out = 0;
    *response_out = NULL;

    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;
    char *response = calloc(1, 1);
    long http_code = 0;

    curl = curl_easy_init();
    if (!curl) {
        free(response);
        return false;
    }

    headers = curl_slist_append(headers, "Content-Type: application/json");
    char token_hdr[256];
    snprintf(token_hdr, sizeof(token_hdr), "X-Vault-Token: %s", token);
    headers = curl_slist_append(headers, token_hdr);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);

    if (payload && strcmp(method, "GET") != 0) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    }

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    if (res == CURLE_OK && http_code > 0) {
        *http_code_out = http_code;
        *response_out = response;
        ok = true;
    } else {
        free(response);
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return ok;
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

        global_key_mgr->key_count++;
        entries_read++;
    }

    close(fd);
    elog(DEBUG1, "[OpenTDE] Loaded %d keys from %s", entries_read, key_path);
    opentde_record_key_file_signature(key_path);
    pfree(key_path);
    return true;
}

bool
opentde_reload_key_file(void)
{
    if (!master_key_set || !global_key_mgr)
        return false;

    global_key_mgr->key_count = 0;
    return opentde_load_key_file();
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
 * Удаляет все DEK-записи для указанной таблицы из key ring.
 * Используется при явном выключении шифрования для relation.
 */
void
opentde_forget_table_keys(Oid table_oid)
{
    int  read_idx;
    int  write_idx;
    bool changed;

    opentde_ensure_keys_loaded();

    if (!master_key_set || !global_key_mgr)
    {
        ereport(ERROR,
                (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                 errmsg("master key is not set")));
    }

    changed = false;
    write_idx = 0;

    for (read_idx = 0; read_idx < global_key_mgr->key_count; read_idx++)
    {
        opentde_key_entry *entry = &global_key_mgr->keys[read_idx];

        if (entry->table_oid == table_oid)
        {
            changed = true;
            continue;
        }

        if (write_idx != read_idx)
            global_key_mgr->keys[write_idx] = *entry;
        write_idx++;
    }

    if (!changed)
        return;

    global_key_mgr->key_count = write_idx;
    opentde_save_key_file();
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
    field_name = opentde_getenv_compat("OPENTDE_VAULT_FIELD", "VAULT_FIELD", OPENTDE_VAULT_FIELD_DEFAULT);
    vault_path = opentde_getenv_compat("OPENTDE_VAULT_PATH", "VAULT_PATH", OPENTDE_VAULT_PATH_DEFAULT);

    ok = opentde_vault_http_request("GET", url, NULL, &http_code, &response);
    pfree(url);

    if (!ok) 
    {
        elog(DEBUG1, "[OpenTDE] Vault GET request failed while loading master key");
        return false;
    }

    if (http_code == 404)
    {
        free(response);
        return false;
    }

    if (http_code != 200)
    {
        elog(DEBUG1,
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
    opentde_install_md_hooks();

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

    field_name = opentde_getenv_compat("OPENTDE_VAULT_FIELD", "VAULT_FIELD", OPENTDE_VAULT_FIELD_DEFAULT);
    vault_path = opentde_getenv_compat("OPENTDE_VAULT_PATH", "VAULT_PATH", OPENTDE_VAULT_PATH_DEFAULT);

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
