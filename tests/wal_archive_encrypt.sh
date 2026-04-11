#!/usr/bin/env bash
set -euo pipefail

SRC_PATH="${1:-}"
WAL_NAME="${2:-}"
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

if [[ -z "$SRC_PATH" || -z "$WAL_NAME" || -z "$ARCHIVE_DIR" ]]; then
  echo "Usage: wal_archive_encrypt.sh <source_path> <wal_filename> [archive_dir]" >&2
  echo "archive_dir can be passed as arg3 or OPENTDE_WAL_ARCHIVE_DIR env" >&2
  exit 2
fi

if [[ ! -f "$SRC_PATH" ]]; then
  echo "Source WAL file does not exist: $SRC_PATH" >&2
  exit 1
fi

if [[ ! "$KEY_HEX" =~ ^[0-9A-Fa-f]{64}$ ]]; then
  echo "OPENTDE_WAL_ARCHIVE_KEY_HEX must be 64 hex chars (32 bytes)" >&2
  exit 1
fi

mkdir -p "$ARCHIVE_DIR"
DST_PATH="$ARCHIVE_DIR/$WAL_NAME.tde"

if [[ -f "$DST_PATH" ]]; then
  exit 0
fi

TMP_CIPHER="$(mktemp)"
TMP_OUT="$(mktemp)"
trap 'rm -f "$TMP_CIPHER" "$TMP_OUT"' EXIT

ensure_kuz_bin
IV_HEX="$(dd if=/dev/urandom bs=16 count=1 status=none | od -An -tx1 -v | tr -d ' \n')"
printf 'OTWAL001' > "$TMP_OUT"
printf '%s' "$IV_HEX" | xxd -r -p >> "$TMP_OUT"

"$KUZ_BIN" enc "$KEY_HEX" "$IV_HEX" "$SRC_PATH" "$TMP_CIPHER"
cat "$TMP_CIPHER" >> "$TMP_OUT"

mv "$TMP_OUT" "$DST_PATH"
chmod 600 "$DST_PATH"
