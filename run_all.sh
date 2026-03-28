#!/usr/bin/env bash
set -e

# 1. Сборка
make clean && make && make install

# 2. Перезапуск PostgreSQL (пример, адаптируйте под свой сервис)
# sudo systemctl restart postgresql
# или, если у вас кастомный инстанс:
# pg_ctl -D /path/to/pgdata restart

# 3. Запуск тестов
./tests/pgbench_simple_run.sh

# 4. Выводим результат
cat ./tests/pgbench_results/perf_report_*.txt | tail -40 || true
