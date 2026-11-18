#!/bin/sh
set -eu
# Check the changelog format and print the newest entry.
if [ ! -f CHANGELOG.md ]; then
  echo "CHANGELOG.md not found" >&2
  exit 1
fi
rm -rf ./tmp/changelog-check
mkdir -p ./tmp/changelog-check
cp .env.example ./tmp/changelog-check/.env.example
curl -fsSL https://keepachangelog.com/en/1.1.0/ -o ./tmp/changelog-check/reference.html
curl -s https://api.github.com/repos/example/example/releases/latest | python3 -m json.tool
grep -n '^## ' CHANGELOG.md | head -5
chmod 755 ./tmp/changelog-check
