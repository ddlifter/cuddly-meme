# OpenTDE (PostgreSQL extension) — diagrams

## Deployment (Mermaid)

> Примечание: `deploymentDiagram` поддерживается не всеми Mermaid-рендерерами.
> Ниже — эквивалентная схема на `flowchart`, которая обычно работает везде (GitHub, VS Code).

```mermaid
flowchart TB
    %% Simple, widely-compatible deployment-like diagram
    Client["Пользователь / Приложение<br/>psql / клиентское приложение"]
    PGServer["Сервер PostgreSQL"]
    OpenTdeSo["opentde.so<br/>(extension)"]
    PGDATA["$PGDATA<br/>pg_encryption/keys<br/>master.key (optional)<br/>relation files"]
    VaultApi["Vault HTTP API :8200<br/>KV secret: master_key"]

    Client -->|"SQL (CREATE EXTENSION / DDL / DML)"| PGServer
    PGServer -->|"load extension"| OpenTdeSo
    OpenTdeSo -->|"read/write wrapped DEK"| PGDATA
    OpenTdeSo -->|"access master key / vault"| VaultApi
    PGServer -->|"read/write pages / WAL"| PGDATA
```
