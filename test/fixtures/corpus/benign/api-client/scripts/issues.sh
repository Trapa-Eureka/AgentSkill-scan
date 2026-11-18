#!/usr/bin/env bash
# Prints the open issues as "id<TAB>title".
set -euo pipefail

: "${TRACKER_URL:=https://tracker.example.test}"

if [ ! -f .env ]; then
  echo "Missing .env; copy .env.example and fill it in." >&2
  exit 1
fi
# shellcheck disable=SC1091
source .env

curl -s "$TRACKER_URL/api/issues?state=open" \
  -H "Accept: application/json" \
  | jq -r '.[] | [.id, .title] | @tsv'

curl -s http://127.0.0.1:8080/health | jq .status
env | sort | grep '^TRACKER_URL=' || true
