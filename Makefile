# Имя расширения
EXTENSION = opentde
# SQL-файл расширения
DATA = opentde--1.0.sql
# Имя разделяемой библиотеки (.so)
MODULE_big = opentde
# Список исходников для компиляции
OBJS = src/kuznechik.o src/opentde_crypto.o src/opentde_keymanager.o src/opentde_sql.o src/pg_encrypted_smgr.o src/opentde_pageam.o

# Подключаем конфигурацию PostgreSQL
PG_CONFIG = /home/ddlifter/diploma/pg_build/bin/pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

# Линкуем с OpenSSL и libcurl для криптографии и HTTP
# Убедись, что стоят пакеты libssl-dev и libcurl4-openssl-dev
SHLIB_LINK += -lssl -lcrypto -lcurl

# Для бенчмарков явно включаем оптимизацию расширения,
# даже если сам PostgreSQL собран с debug-флагами.
PG_CFLAGS += -O3 -DNDEBUG
PG_CPPFLAGS += -Isrc
