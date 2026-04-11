#!/usr/bin/env bash
set -euo pipefail

WAL_NAME="${1:-}"
DEST_PATH="${2:-}"
ARCHIVE_DIR="${3:-${OPENTDE_WAL_ARCHIVE_DIR:-}}"
KEY_HEX="${OPENTDE_WAL_ARCHIVE_KEY_HEX:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KUZ_BIN="$SCRIPT_DIR/kuz_wal_crypt"

ensure_kuz_bin() {
  if [[ -x "$KUZ_BIN" ]]; then
    return 0
  fi

  cc -O2 -Isrc "$SCRIPT_DIR/kuz_wal_crypt.c" "$ROOT_DIR/src/kuznechik.c" -o "$KUZ_BIN"
}

if [[ -z "$WAL_NAME" || -z "$DEST_PATH" || -z "$ARCHIVE_DIR" ]]; then
  echo "Usage: wal_restore_decrypt.sh <wal_filename> <destination_path> [archive_dir]" >&2
  echo "archive_dir can be passed as arg3 or OPENTDE_WAL_ARCHIVE_DIR env" >&2
  exit 2
fi

if [[ ! "$KEY_HEX" =~ ^[0-9A-Fa-f]{64}$ ]]; then
  echo "OPENTDE_WAL_ARCHIVE_KEY_HEX must be 64 hex chars (32 bytes)" >&2
  exit 1
fi

SRC_PATH="$ARCHIVE_DIR/$WAL_NAME.tde"
if [[ ! -f "$SRC_PATH" ]]; then
  exit 1
fi

MAGIC="$(dd if="$SRC_PATH" bs=1 count=8 status=none || true)"
if [[ "$MAGIC" != "OTWAL001" ]]; then
  echo "Invalid encrypted WAL archive header in $SRC_PATH" >&2
  exit 1
fi

IV_HEX="$(dd if="$SRC_PATH" bs=1 skip=8 count=16 status=none | od -An -tx1 -v | tr -d ' \n')"
TMP_CIPHER="$(mktemp)"
TMP_PLAIN="$(mktemp)"
trap 'rm -f "$TMP_CIPHER" "$TMP_PLAIN"' EXIT

dd if="$SRC_PATH" bs=1 skip=24 of="$TMP_CIPHER" status=none
ensure_kuz_bin
"$KUZ_BIN" dec "$KEY_HEX" "$IV_HEX" "$TMP_CIPHER" "$TMP_PLAIN"

mv "$TMP_PLAIN" "$DEST_PATH"
chmod 600 "$DEST_PATH"
