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

# Линкуем с OpenSSL для криптографии
# Убедись, что стоит пакет libssl-dev
SHLIB_LINK += -lssl -lcrypto

# Для бенчмарков явно включаем оптимизацию расширения,
# даже если сам PostgreSQL собран с debug-флагами.
PG_CFLAGS += -O3 -DNDEBUG
PG_CPPFLAGS += -Isrc
