# OpenTDE Page-Level Encryption as PostgreSQL Extension

## Goal
Implement page-level encryption while staying a PostgreSQL extension.

## Key Constraint
Current implementation wraps heap callbacks and uses heap tuple format directly.
This is not enough for true page-level encryption.

Why:
- If page data in shared buffers is plaintext, checkpointer writes plaintext to disk.
- If page data in shared buffers is ciphertext, heap APIs cannot operate on tuples without decrypting.
- Extension has no generic hook to transparently decrypt/encrypt buffer I/O for heap pages.

Conclusion:
- Real page-level encryption in extension form requires a dedicated Table AM with its own page format and read/write path.
- Do not rely on heap_insert/heap_update/heap scan internals for encrypted pages.

## Target Architecture

### 1. New AM mode
Add a new mode (or new AM handler) for page-level encrypted relations.

Recommended split:
- `opentde_tupleam` (existing behavior, tuple payload crypto)
- `opentde_pageam` (new behavior, encrypted page images)

### 2. Encrypted page layout
Store encrypted payload at page granularity.

Minimal page model:
- Cleartext small header:
  - magic/version
  - key_version
  - flags
  - nonce/counter (or page IV)
  - ciphertext length
  - auth tag (if AEAD)
- Ciphertext body:
  - serialized logical page content

### 3. Per-backend decrypted page cache
For scan/update workloads:
- Read encrypted page from relation fork.
- Decrypt once per page into backend-local memory.
- Iterate tuples from decrypted image.
- Re-encrypt page on writeback path.

This avoids per-tuple decrypt cost and is the main performance lever for seq scan.

### 4. Crypto mode upgrade
Current CTR without integrity is risky for page-level design.

Use authenticated encryption:
- Preferred: AES-256-GCM (or Kuznechik AEAD equivalent if required by policy).
- Bind AAD to `(relfilenode, forknum, blockno, key_version)`.
- Reject page on tag mismatch.

### 5. Key hierarchy
Use two levels:
- Master key in KMS/Vault (already present)
- Per-relation DEK
- Optional: derive per-page subkey/nonce from DEK + block number via KDF

### 6. WAL and crash safety
For extension-only page AM:
- WAL records must never contain plaintext page image.
- Log encrypted delta/image and metadata needed for redo.
- Redo path must decrypt/reencrypt deterministically.

### 7. Maintenance operations
Need AM-safe implementations for:
- vacuum hooks
- analyze hooks
- relation extension/truncation
- visibility/cleanup strategy

Avoid depending on heap internals for these in page mode.

## Migration Strategy

### Phase A (MVP)
- Keep existing tuple mode untouched.
- Add new page mode behind explicit `USING opentde_page`.
- Support only:
  - create table
  - insert
  - seq scan
  - simple update/delete
- Disable unsupported features with clear ERRORs.

### Phase B
- Add indexes and index fetch path.
- Add vacuum/analyze correctness.
- Add robust WAL redo for crash recovery.

### Phase C
- Optimize:
  - page cache reuse
  - background prefetch/decrypt
  - key rotation at page granularity

## Why this is better than micro-optimizations
Current tuple mode does crypto and IV lookup per row.
Page mode does crypto per page.
For dense pages this cuts crypto calls by orders of magnitude in seq scans.

## Immediate Implementation Tasks
1. Introduce new AM handler symbol for page mode.
2. Add page format structs and serializer/deserializer module.
3. Add encrypt/decrypt page API with AEAD and AAD binding.
4. Implement `scan_begin/scan_getnextslot` for page mode with one decrypt per page.
5. Add pgbench scenario specifically for seq scan over wide rows to validate gain.

## Risks
- Full table AM scope is large.
- WAL/redo correctness is non-trivial.
- Feature parity with heap is multi-phase work.

## Decision
If page-level encryption must remain extension-only, implement a dedicated page AM and treat it as a new storage engine, not an incremental patch over heap wrapper mode.
