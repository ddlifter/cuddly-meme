# Имя расширения
EXTENSION = opentde
# SQL-файл, который выполнится при CREATE EXTENSION
DATA = opentde--1.0.sql
# Имя разделяемой библиотеки (.so)
MODULE_big = opentde
# Список исходников для компиляции
OBJS = src/opentde_tableam.o src/opentde_keymanager.o src/opentde_crypto.o src/opentde_sql.o src/kuznechik.o
# Подключаем конфигурацию PostgreSQL
PG_CONFIG = /home/ddlifter/diploma/pg_build/bin/pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

# Линкуем с OpenSSL для криптографии
# Убедись, что стоит пакет libssl-dev
SHLIB_LINK += -lssl -lcrypto
