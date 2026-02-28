#!/bin/sh
set -eu

BIN="${1:-./awdog-saver}"
TMPDIR="$(mktemp -d)"
TESTS=0

cleanup() {
  rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

assert_json() {
  file="$1"
  filter="$2"
  msg="$3"
  if ! jq -e "$filter" "$file" >/dev/null 2>&1; then
    echo "JSON payload:" >&2
    cat "$file" >&2
    fail "$msg"
  fi
}

run_case() {
  TESTS=$((TESTS + 1))
  echo "ok - $1"
}

if [ ! -x "$BIN" ]; then
  fail "missing binary: $BIN"
fi

# 1) Legacy reason-only invocation still works and auto-classifies timeout.
OUT1="$TMPDIR/out1.json"
AWDOG_PSTORE_PATH="$OUT1" "$BIN" "timeout"
assert_json "$OUT1" \
  '.reason=="timeout" and .phase=="heartbeat_rejected" and .raw_line=="awdog: tamper tripped: timeout" and .source=="awdog-live-trip" and .pstore_backend=="pstore_blk" and (.pstore_sink|type)=="string" and (.ingested_at|type)=="number" and (.attributes|type)=="object" and (.attributes|length)==0' \
  "legacy invocation fields mismatch"
run_case "legacy invocation"

# 2) Structured AWDOG_TRIP key/value attributes are parsed into attributes map.
OUT2="$TMPDIR/out2.json"
AWDOG_PSTORE_PATH="$OUT2" "$BIN" \
  "AWDOG_TRIP phase=tamper_tripped reason=timeout policy=strict action=reset"
assert_json "$OUT2" \
  '.phase=="tamper_tripped" and .reason=="timeout" and .attributes.policy=="strict" and .attributes.action=="reset" and (.attributes|has("phase")|not) and (.attributes|has("reason")|not)' \
  "structured AWDOG_TRIP parsing mismatch"
run_case "structured attributes"

# 3) CLI options override message attributes; source attribute overrides env.
OUT3="$TMPDIR/out3.json"
AWDOG_TRIP_SOURCE="env-source" AWDOG_PSTORE_PATH="$OUT3" "$BIN" \
  --phase heartbeat_rejected \
  --reason verify-failed \
  --raw-line "awdog: tamper tripped: verify-failed" \
  "AWDOG_TRIP phase=tamper_tripped reason=timeout source=attr-source k=v"
assert_json "$OUT3" \
  '.phase=="heartbeat_rejected" and .reason=="verify-failed" and .raw_line=="awdog: tamper tripped: verify-failed" and .source=="attr-source" and .attributes.k=="v" and (.attributes|has("source")|not)' \
  "CLI/env precedence mismatch"
run_case "argument precedence"

# 4) --source has highest precedence over AWDOG_TRIP source field.
OUT4="$TMPDIR/out4.json"
AWDOG_TRIP_SOURCE="env-source" AWDOG_PSTORE_PATH="$OUT4" "$BIN" \
  --source cli-source \
  "AWDOG_TRIP source=attr-source reason=foo"
assert_json "$OUT4" \
  '.source=="cli-source" and .reason=="foo" and .phase=="tamper_tripped"' \
  "--source precedence mismatch"
run_case "source override"

# 5) Backend is fixed to pstore_blk.
OUT5="$TMPDIR/out5.json"
AWDOG_PSTORE_PATH="$OUT5" "$BIN" "reboot by policy"
assert_json "$OUT5" '.phase=="reboot_requested" and .pstore_backend=="pstore_blk"' \
  "default backend mismatch"
run_case "default backend"

OUT6="$TMPDIR/out6.json"
AWDOG_PSTORE_PATH="$OUT6" "$BIN" \
  "AWDOG_TRIP backend=attr-backend reason=timeout"
assert_json "$OUT6" '.pstore_backend=="pstore_blk" and .reason=="timeout"' \
  "fixed backend behavior mismatch"
run_case "fixed backend behavior"

# 6) New generic pstore path env/flag are honored.
OUT7="$TMPDIR/out7.json"
AWDOG_PSTORE_PATH="$OUT7" "$BIN" "timeout"
assert_json "$OUT7" '(.pstore_sink|type)=="string" and .phase=="heartbeat_rejected"' \
  "AWDOG_PSTORE_PATH behavior mismatch"
run_case "pstore path env"

OUT8="$TMPDIR/out8.json"
"$BIN" --pstore-path "$OUT8" "timeout"
assert_json "$OUT8" '(.pstore_sink|type)=="string" and .phase=="heartbeat_rejected"' \
  "--pstore-path behavior mismatch"
run_case "pstore path flag"

# 7) Auto-phase classification for test reason still works.
OUT9="$TMPDIR/out9.json"
AWDOG_PSTORE_PATH="$OUT9" "$BIN" "test mode trip"
assert_json "$OUT9" '.phase=="test_mode_trip"' "test phase classification mismatch"
run_case "test-mode classification"

# 8) Unknown flag must fail.
if AWDOG_PSTORE_PATH="$TMPDIR/out10.json" "$BIN" --bogus >/dev/null 2>&1; then
  fail "unknown flag unexpectedly succeeded"
fi
run_case "unknown flag rejection"

# 9) Removed backend flag must fail.
if AWDOG_PSTORE_PATH="$TMPDIR/out11.json" "$BIN" --backend anything >/dev/null 2>&1; then
  fail "--backend unexpectedly succeeded"
fi
run_case "backend flag rejection"

echo "PASS: $TESTS tests"
