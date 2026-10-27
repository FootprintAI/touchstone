#!/usr/bin/env bash
# Passive-only e2e for docker-compose.yml. It scans fixture-vendor through the
# CLI and through POST /v1/scans, then checks that the two reports agree and
# that the vendor's nginx access log matches the report's checked list.
#
# Usage: bash test/e2e/run.sh   (needs docker compose, curl and jq)
set -euo pipefail

cd "$(dirname "$0")/../.."

OUT=test/e2e/out
TARGET=http://fixture-vendor/
SERVE=http://127.0.0.1:8080
ALLOWED='["TARGET","SUBRESOURCE","DISCOVERY_PATH","DECLARED"]'
# The two scans start and finish at different times; nothing else may differ.
STRIP='del(.startedAt, .completedAt, .vulnDataAsOf)'

fail() {
  echo "e2e: FAIL: $*" >&2
  exit 1
}

teardown() {
  docker compose logs --no-color > "$OUT/compose.log" 2>&1 || true
  docker compose down -v
}

rm -rf "$OUT"
mkdir -p "$OUT/access"
trap teardown EXIT

docker compose up -d --build --wait

for _ in $(seq 60); do
  curl -fsS -o /dev/null "$SERVE/" 2>/dev/null && break
  sleep 1
done
curl -fsS -o /dev/null "$SERVE/" || fail "touchstone serve did not answer on $SERVE"

# Both scans go to fixture-vendor by its compose name; neither uses
# --allow-private, so the SSRF guard is on for both.
docker compose run --rm -T touchstone scan "$TARGET" > "$OUT/cli.json"
curl -fsS -X POST -H 'Content-Type: application/json' \
  -d "{\"url\": \"$TARGET\"}" "$SERVE/v1/scans" > "$OUT/http.json"

jq -S "$STRIP" "$OUT/cli.json" > "$OUT/cli.norm.json"
jq -S "$STRIP" "$OUT/http.json" > "$OUT/http.norm.json"
diff -u "$OUT/cli.norm.json" "$OUT/http.norm.json" \
  || fail "CLI and POST /v1/scans reports differ (see diff above)"

jq -e --argjson allowed "$ALLOWED" \
  '[.checked[] | select(.reason as $r | $allowed | contains([$r]) | not)] | length == 0' \
  "$OUT/cli.json" > /dev/null \
  || fail "checked list has a location with a reason outside $ALLOWED"

# Passive-only proof. Refused requests never left touchstone, so they are
# left out of the checked side. The access log is combined format: field 2 is
# the request line.
LOG="$OUT/access/access.log"
[ -s "$LOG" ] || fail "no access log at $LOG"
awk -F'"' '{ split($2, r, " "); print r[1] }' "$LOG" | sort -u > "$OUT/methods.txt"
[ "$(cat "$OUT/methods.txt")" = "GET" ] \
  || fail "fixture-vendor saw methods other than GET: $(tr '\n' ' ' < "$OUT/methods.txt")"

awk -F'"' '{ split($2, r, " "); print r[2] }' "$LOG" | sort -u > "$OUT/logged.txt"
jq -r '.checked[] | select(.result != "RESULT_REFUSED") | .url | sub("^https?://[^/]+"; "")' \
  "$OUT/cli.json" | sort -u > "$OUT/sent.txt"
diff -u "$OUT/sent.txt" "$OUT/logged.txt" \
  || fail "access log and checked list differ: '-' is checked but never requested, '+' is requested but not checked"

echo "e2e: OK: $(wc -l < "$OUT/logged.txt") requested paths, all in the checked list; CLI and POST /v1/scans reports identical"
