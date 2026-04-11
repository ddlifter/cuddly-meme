#!/usr/bin/env bash
set -euo pipefail

WAL_NAME="${1:-}"
DEST_PATH="${2:-}"
URL_BASE="${3:-}"
TMP_DIR="${4:-}"

if [[ -z "$WAL_NAME" || -z "$DEST_PATH" || -z "$URL_BASE" || -z "$TMP_DIR" ]]; then
  echo "Usage: wal_restore_fetch_decrypt.sh <wal_filename> <destination_path> <url_base> <tmp_dir>" >&2
  exit 2
fi

mkdir -p "$TMP_DIR"
ENC_PATH="$TMP_DIR/$WAL_NAME.tde"

if ! curl -fsS "$URL_BASE/$WAL_NAME.tde" -o "$ENC_PATH"; then
  exit 1
fi

"$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/wal_restore_decrypt.sh" "$WAL_NAME" "$DEST_PATH" "$TMP_DIR"
