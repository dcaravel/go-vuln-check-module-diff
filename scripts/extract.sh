#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <image> <file_path>" >&2
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)/extracted"

IMAGE="$1"
if [[ "$IMAGE" != docker://* ]]; then
  IMAGE="docker://$IMAGE"
fi

FILE_PATH="${2#/}"
case "$FILE_PATH" in
  ""|..|../*|*/..|*/../*)
    echo "file_path must be a path inside the image" >&2
    exit 1
    ;;
esac

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

skopeo copy --override-os linux --override-arch amd64 "$IMAGE" "dir:$TMP_DIR" > /dev/null
mkdir -p "$OUTPUT_DIR"

found=0
while IFS= read -r -d '' layer; do
  if tar -tf "$layer" "$FILE_PATH" > /dev/null 2>&1; then
    tar -xf "$layer" -C "$OUTPUT_DIR" "$FILE_PATH"
    found=1
  fi
done < <(find "$TMP_DIR" -type f -print0)

if [ "$found" -eq 0 ]; then
  echo "File not found in image: $FILE_PATH" >&2
  exit 1
fi

printf 'Extracted to %s\n' "$OUTPUT_DIR/$FILE_PATH"
