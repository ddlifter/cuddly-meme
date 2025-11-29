# Имя расширения
EXTENSION = opentde
# SQL-файл, который выполнится при CREATE EXTENSION
DATA = opentde--1.0.sql
# Имя разделяемой библиотеки (.so)
MODULE_big = opentde
# Список исходников для компиляции
OBJS = src/opentde.o src/opentde_am.o src/opentde_wal.o src/opentde_crypto.o src/kuznechik.o
# Подключаем конфигурацию PostgreSQL
# ВАЖНО: pg_config должен быть из ТВОЕЙ сборки (export PATH=...)
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

# Линкуем с OpenSSL для криптографии
# Убедись, что стоит пакет libssl-dev
SHLIB_LINK += -lssl -lcrypto
