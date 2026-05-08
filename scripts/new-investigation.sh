#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <slug>"
  echo "       slug is typically the CVE id (CVE-2026-XXXXX) or a short descriptor."
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SLUG="$1"
DEST="$ROOT_DIR/findings/$SLUG"

if [[ -e "$DEST" ]]; then
  echo "already exists: $DEST" >&2
  exit 1
fi

cp -r "$ROOT_DIR/findings/_template" "$DEST"
echo "$DEST"
