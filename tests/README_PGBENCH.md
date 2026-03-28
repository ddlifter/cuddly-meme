# pgbench Performance Test для OpenTDE

Этот набор скриптов позволяет провести полное сравнение производительности между:
- **Зашифрованными таблицами** (OpenTDE с вашим расширением)
- **Обычными таблицами** (стандартный heap storage)

## Структура файлов

```
pgbench_setup.sql                    # Подготовка: создание расширения и таблиц
pgbench_readonly_encrypted.sql       # Read-only тест (зашифрованная таблица)
pgbench_readonly_plain.sql           # Read-only тест (обычная таблица)
pgbench_readwrite_encrypted.sql      # Mixed R/W тест (зашифрованная)
pgbench_readwrite_plain.sql          # Mixed R/W тест (обычная)
pgbench_index_encrypted.sql          # Index scan тест (зашифрованная)
pgbench_index_plain.sql              # Index scan тест (обычная)
pgbench_perf_test.sh                 # Главный скрипт тестирования
```

## Быстрый старт

### Шаг 1: Убедитесь, что расширение скомпилировано

```bash
cd /home/ddlifter/diploma/opentde_project
make
# или с явным путем PostgreSQL:
make USE_PGXS=1 PG_CONFIG=$HOME/diploma/pg_build/bin/pg_config
```

### Шаг 2: Установите расширение (если еще не установлено)

```bash
make install
# или:
make install USE_PGXS=1 PG_CONFIG=$HOME/diploma/pg_build/bin/pg_config
```

### Шаг 3: Запустите тесты

```bash
cd tests/
./pgbench_perf_test.sh postgres ~/diploma/pg_build/bin
```

Параметры:
- `postgres` — имя базы данных (по умолчанию)
- `~/diploma/pg_build/bin` — путь к PostgreSQL bin (по умолчанию)

## Что измеряется?

### Test 1: Read-Only (простые SELECT)
Измеряет **пиковую пропускную способность** при чтении отдельных строк.
```sql
SELECT id, name, balance FROM t_encrypted WHERE id = ?
```

**Ожидаемый результат**: Небольшое замедление на OpenTDE из-за расхода CPU на дешифрование.

### Test 2: Read-Write Mixed (3 SELECT + 1 UPDATE)
Смешанная нагрузка, типичная для OLTP приложений.
```sql
-- 3x SELECT
SELECT id, name, balance FROM t_encrypted WHERE id = ?
-- + 1x UPDATE
UPDATE t_encrypted SET balance = balance + 1 WHERE id = ?
```

**Ожидаемый результат**: UPDATE на OpenTDE медленнее из-за шифрования перед записью.

### Test 3: Index Scan (поиск по индексу)
Поиск по текстовому индексу (выборочно).
```sql
SELECT id, balance FROM t_encrypted 
WHERE name = 'user_' || ? LIMIT 10
```

**Ожидаемый результат**: Зависит от размера результата и наличия фильтра на зашифрованные столбцы.

## Результаты

Результаты сохраняются в `pgbench_results/perf_report_YYYYMMDD_HHMMSS.txt`

Типичный вывод:
```
═══════════════════════════════════════════════════════════════════════════
Test: Read-Only (СЕЛЕКТы)
═══════════════════════════════════════════════════════════════════════════

ENCRYPTED TABLE:
transactions: 125450 (2090 tps)
latency average = 1.91 ms

PLAIN TABLE:
transactions: 142500 (2375 tps)
latency average = 1.68 ms
```

## Интерпретация результатов

Показатели:
- **tps** (transactions per second) — количество транзакций в секунду (выше = лучше)
- **latency** — среднее время ответа в миллисекундах (ниже = лучше)

Примерные результаты для 1M записей:
- **Read-Only**: OpenTDE медленнее на 10-20% (дешифрование данных)
- **Read-Write**: OpenTDE медленнее на 15-30% (шифрование + дешифрование)
- **Index Scan**: Зависит от размера результата (индексы обычно в порядке)

## Параметры тестирования

Отредактируйте `pgbench_perf_test.sh` для изменения:

```bash
CLIENTS=4          # Число клиентов (параллельных соединений)
THREADS=4          # Число потоков
DURATION=60        # Длительность теста в секундах (60s по умолчанию)
WARMUP=10          # Разминка перед измерением (10s)
```

Для более точных результатов увеличьте:
- `CLIENTS` (до 8-16)
- `DURATION` (до 120-300s)
- Запустите несколько раз

## Отладка

### Если расширение не загружается:

```bash
ALTER SYSTEM SET shared_preload_libraries = 'opentde';
SELECT pg_reload_conf();
SELECT pg_sleep(1);
-- Перезагрузите PostgreSQL или переподключитесь
```

### Если tableam не используется:

```bash
SELECT * FROM pg_table_am WHERE amname LIKE '%opentde%';
-- Должна появиться строка с вашим TAM
```

### Проверить данные в таблице:

```bash
SELECT count(*) FROM t_encrypted;  -- Должно быть 1000000
SELECT count(*) FROM t_plain;       -- Должно быть 1000000

-- Убедиться, что данные в обеих таблицах идентичны:
SELECT count(*) FROM (
  SELECT id, name, balance FROM t_encrypted EXCEPT
  SELECT id, name, balance FROM t_plain
) x;
-- Должно быть 0
```

## Расширенное тестирование

### Тест на INSERT (массовая вставка)

Добавьте в `pgbench_perf_test.sh`:

```bash
run_test "Insert Heavy" \
  "pgbench_insert_encrypted.sql" \
  "pgbench_insert_plain.sql" \
  "Массовая вставка данных"
```

И создайте:
```sql
-- pgbench_insert_encrypted.sql
\set id random(1000001, 2000000)
INSERT INTO t_encrypted VALUES (:id, 'new_' || :id, random()*1000, '', gen_random_bytes(100));

-- pgbench_insert_plain.sql
\set id random(1000001, 2000000)
INSERT INTO t_plain VALUES (:id, 'new_' || :id, random()*1000, '', gen_random_bytes(100));
```

### Тест UPDATE-heavy

```bash
-- pgbench_update_encrypted.sql
\set id random(1, 1000000)
UPDATE t_encrypted SET balance = (random() * 10000)::int WHERE id = :id;
```

### Тест FULL SCAN

```bash
-- pgbench_fullscan_encrypted.sql
SELECT avg(balance) FROM t_encrypted;
```

## Сравнение результатов

После запуска несколько раз создайте таблицу сравнения:

| операция | Обычная таблица | OpenTDE | Overhead |
|----------|------------------|---------|----------|
| SELECT   | 2375 tps         | 2090 tps   | 12% |
| R/W Mix  | 1850 tps         | 1540 tps   | 17% |
| Index Scan | 890 tps        | 850 tps    | 4% |

## Советы по оптимизации

1. **Отключите fsync для тестирования** (будьте осторожны):
   ```sql
   ALTER SYSTEM SET fsync = off;
   SELECT pg_reload_conf();
   ```

2. **Увеличьте shared_buffers**:
   ```sql
   ALTER SYSTEM SET shared_buffers = '2GB';
   -- Требует перезагрузку
   ```

3. **Используйте unlogged таблицы для baseline**:
   ```sql
   CREATE UNLOGGED TABLE t_encrypted_unlogged (...) USING opentde_page;
   ```

## Контакт

Для вопросов о расширении см. документацию и исходный код в `src/`.
