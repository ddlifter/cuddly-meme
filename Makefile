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
PG_CONFIG = /home/ddlifter/diploma/pg_build/bin/pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

# Линкуем с OpenSSL и libcurl для криптографии и HTTP
# Убедись, что стоят пакеты libssl-dev и libcurl4-openssl-dev
SHLIB_LINK += -lssl -lcrypto -lcurl

PG_CFLAGS += -O3 -DNDEBUG -flto
PG_CPPFLAGS += -Isrc -I/home/ddlifter/diploma/pg_build/include/postgresql/server -I/home/ddlifter/diploma/pg_build/include/postgresql
SHLIB_LINK += -flto
