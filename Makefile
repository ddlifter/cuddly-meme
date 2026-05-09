# Имя расширения
EXTENSION = opentde
# SQL-файл расширения
DATA = opentde--1.0.sql
# Имя разделяемой библиотеки (.so)
MODULE_big = opentde
# Список исходников для компиляции

OBJS = src/kuznechik.o src/opentde_crypto.o src/opentde_keymanager.o src/opentde_sql.o src/pg_encrypted_smgr.o src/opentde_pagestore.o
SRCS = src/kuznechik.c src/opentde_crypto.c src/opentde_keymanager.c src/opentde_sql.c src/pg_encrypted_smgr.c src/opentde_pagestore.c

# Подключаем конфигурацию PostgreSQL
PG_CONFIG = /home/winter/pg19-customsmgr/bin/pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

# Линкуем с OpenSSL и libcurl для криптографии и HTTP
# Убедись, что стоят пакеты libssl-dev и libcurl4-openssl-dev
SHLIB_LINK += -lssl -lcrypto -lcurl

# Не навязываем оптимизации (-O3/-flto/-DNDEBUG): расширение должно собираться
# теми же флагами, что и текущая сборка PostgreSQL (у вас она отладочная).

# Заголовки расширения
PG_CPPFLAGS += -Isrc

# Важно: расширение использует некоторые внутренние заголовки PostgreSQL,
# которые не всегда устанавливаются в $(includedir-server) при `make install`.
# Поэтому добавляем путь к дереву исходников PostgreSQL.
#
# Примечание: для гарантии, что ключи -I попадут в фактическую команду компиляции
# (через PGXS), добавляем путь также в CPPFLAGS.
PG_CPPFLAGS += -I/home/winter/postgres/src/include
override CPPFLAGS += -I/home/winter/postgres/src/include
