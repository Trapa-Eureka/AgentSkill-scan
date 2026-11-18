#!/usr/bin/env bash
# Removes build output. Never touches anything outside the project and the tool cache.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

rm -rf ./dist ./coverage ./.turbo
rm -rf "$root/node_modules/.cache"
rm -rf "${XDG_CACHE_HOME:-$HOME/.cache}/project-tool"

echo "$PREVIEW_PNG" | base64 -d > preview.png
base64 -i logo.png > logo.b64

ls /dev/null > /dev/null
echo "Cleaned $root"
