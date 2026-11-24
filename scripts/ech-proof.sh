#!/usr/bin/env bash
# #################################################################
# /qompassai/vongola/scripts/ech-proof.sh
# Qompass AI — vongola ECH end-to-end proof (OpenSSL 4)
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Qompass AI
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# #################################################################
#
# Proves ECH (RFC 9849) end to end against the default release
# binary (target/release/vongola built with the `ech` feature
# against OpenSSL 4.0.3, i.e. the flake's default package or an
# equivalent cargo build): the server generates its ECH
# keypair on first start, a client offering the published
# ECHConfigList gets
# ECH accepted, a client offering a stale config gets the
# server's retry config, and classical clients are unaffected.
# Loopback only. The ECH-disabled negative is covered by
# scripts/smoke.sh (its config has no tls.ech block and must
# stay 38/0). Exits non-zero if any check fails.
#
# The client is the flake's pinned OpenSSL 4.0.3 `openssl`
# binary; set OPENSSL4_BIN to override its location.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/target/release/vongola"
WORK="/tmp/vongola-ech-proof"
TOKEN=ech-proof-operator-token
FAILS=0

if [[ -n "${OPENSSL4_BIN:-}" ]]; then
    S_CLIENT_SSL="$OPENSSL4_BIN"
else
    OPENSSL4_DIR="$(cd "$ROOT" && nix build --no-link --print-out-paths .#openssl4)"
    S_CLIENT_SSL="$OPENSSL4_DIR/bin/openssl"
fi
export LD_LIBRARY_PATH="$(dirname "$(dirname "$S_CLIENT_SSL")")/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILS=$((FAILS + 1)); }
check() { # check <name> <expected-substring> <actual>
    if [[ "$3" == *"$2"* ]]; then pass "$1"; else fail "$1 (want '$2' in '$3')"; fi
}

rm -rf "$WORK"
mkdir -p "$WORK/state"

PIDS=()
cleanup() {
    for pid in "${PIDS[@]:-}"; do kill -KILL "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT

# ---- config -------------------------------------------------------
cat > "$WORK/ech.yaml" <<YAMEOF
admin_token_env: VONGOLA_ECH_OPERATOR_TOKEN
listeners:
  admin: {bind: "127.0.0.1:19093"}
  http: {bind: "127.0.0.1:18084"}
  https: {bind: "127.0.0.1:18445"}
node_name: ech-proof
profile: lean
routes:
  - host: site.example.test
    name: site
    self_signed_fallback: true
    static_root: ./examples/site
shutdown_grace_secs: 5
state_dir: $WORK/state
tls:
  ech:
    enabled: true
    key_file: "$WORK/ech/ech.pem"
    public_name: "cover.example.test"
worker_threads: 2
YAMEOF

cd "$ROOT"
if "$BIN" validate-config --config "$WORK/ech.yaml" >"$WORK/validate.log" 2>&1; then
    pass "validate-config ech.yaml"
else
    fail "validate-config ech.yaml ($(cat "$WORK/validate.log"))"
fi

start_server() {
    VONGOLA_ECH_OPERATOR_TOKEN="$TOKEN" \
        "$BIN" serve --config "$WORK/ech.yaml" >>"$WORK/vongola.log" 2>&1 &
    PIDS+=($!)
    for _ in $(seq 1 40); do
        curl -s -o /dev/null "http://127.0.0.1:19093/healthz" && return 0
        sleep 0.5
    done
    return 1
}

start_server || fail "server starts with ECH enabled"
[[ -f "$WORK/ech/ech.pem" ]] && pass "ECH key file generated on first start" \
    || fail "ECH key file generated on first start"
MODE="$(stat -c %a "$WORK/ech/ech.pem" 2>/dev/null || echo missing)"
check "ECH key file mode 0600" "600" "$MODE"
LIST_FILE="$WORK/state/ech/echconfiglist.b64"
[[ -s "$LIST_FILE" ]] && pass "ECHConfigList emitted to state dir" \
    || fail "ECHConfigList emitted to state dir"
ECH_LIST="$(tr -d '\n' < "$LIST_FILE")"
CA_FILE="$WORK/state/certs/site.example.test.crt"

# ---- 1. ECH accepted ----------------------------------------------
OUT="$(echo | "$S_CLIENT_SSL" s_client -connect 127.0.0.1:18445 \
    -servername site.example.test -CAfile "$CA_FILE" \
    -ech_config_list "$ECH_LIST" 2>&1 || true)"
check "ECH accepted with published config" "ECH: success: 1" "$OUT"
check "ECH handshake verifies" "Verify return code: 0" "$OUT"

BODY="$(printf 'GET / HTTP/1.0\r\nHost: site.example.test\r\n\r\n' | \
    "$S_CLIENT_SSL" s_client -connect 127.0.0.1:18445 -quiet \
    -servername site.example.test -CAfile "$CA_FILE" \
    -ech_config_list "$ECH_LIST" 2>/dev/null || true)"
check "fixture served over the ECH connection" "Qompass AI" "$BODY"

# ---- 2. Operator surfaces ------------------------------------------
METRICS="$(curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:19093/metrics)"
check "metrics carries the ECH enabled gauge" "vongola_ech_enabled{} 1" "$METRICS"
ACCEPTED="$(echo "$METRICS" | sed -n 's/.*vongola_ech_handshakes_total{result="accepted"} \([0-9]*\).*/\1/p')"
if [[ "${ACCEPTED:-0}" -ge 1 ]]; then
    pass "metrics counts accepted ECH handshakes [$ACCEPTED]"
else
    fail "metrics counts accepted ECH handshakes (got '${ACCEPTED:-none}')"
fi
STATE_JSON="$(curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:19093/api/state)"
check "dashboard state carries the public name" "cover.example.test" "$STATE_JSON"
check "dashboard state carries the config list" "$ECH_LIST" "$STATE_JSON"

# ---- 3. Classical clients are unaffected ----------------------------
OUT="$(echo | "$S_CLIENT_SSL" s_client -connect 127.0.0.1:18445 \
    -servername site.example.test -CAfile "$CA_FILE" 2>&1 || true)"
check "classical client handshake verifies" "Verify return code: 0" "$OUT"
if [[ "$OUT" == *"ECH: success"* ]]; then
    fail "classical client must not report ECH success"
else
    pass "classical client does not use ECH"
fi
BODY="$(curl -sk --resolve site.example.test:18445:127.0.0.1 https://site.example.test:18445/)"
check "curl fixture over classical TLS" "Qompass AI" "$BODY"

# ---- 4. Stale config gets the retry config --------------------------
# A stale config = the same public name but a rotated-away
# key (fresh keypair here): the server cannot decrypt the
# client's ECH, rejects it, and supplies its current config
# as the retry config; this client treats a supplied config
# list as required and aborts with an ech_required alert,
# which is the protocol-correct strict behavior. There is
# deliberately NO server-side rejected metric to assert
# here: in OpenSSL 4.0.3 a rejected attempt is folded into
# the GREASE state server-side (by design), so the honest
# server-side invariant is that the accepted counter does
# NOT move for the rejected attempt.
"$S_CLIENT_SSL" ech -public_name site.example.test -out "$WORK/stale.pem" 2>/dev/null
STALE_LIST="$(sed -n '/BEGIN ECHCONFIG/,/END ECHCONFIG/p' "$WORK/stale.pem" | sed '1d;$d' | tr -d '\n')"
OUT="$(echo | "$S_CLIENT_SSL" s_client -connect 127.0.0.1:18445 \
    -servername site.example.test -CAfile "$CA_FILE" \
    -ech_config_list "$STALE_LIST" 2>&1 || true)"
echo "$OUT" > "$WORK/stale-client.log"
ECH_LINE="$(echo "$OUT" | grep -m1 '^ECH' || true)"
check "stale config is answered with a retry" "retry" "$ECH_LINE"
check "retry-configs carry the current public name" "public_name: cover.example.test" "$OUT"
METRICS="$(curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:19093/metrics)"
ACCEPTED_AFTER="$(echo "$METRICS" | sed -n 's/.*vongola_ech_handshakes_total{result="accepted"} \([0-9]*\).*/\1/p')"
check "rejected attempt does not inflate the accepted counter" "$ACCEPTED" "$ACCEPTED_AFTER"

# ---- 5. Restart keeps the published config stable -------------------
kill -TERM "${PIDS[-1]}" 2>/dev/null || true
sleep 1
start_server || fail "server restarts with the persisted ECH key"
LIST_AFTER="$(tr -d '\n' < "$LIST_FILE")"
check "config list stable across restart" "$ECH_LIST" "$LIST_AFTER"
OUT="$(echo | "$S_CLIENT_SSL" s_client -connect 127.0.0.1:18445 \
    -servername site.example.test -CAfile "$CA_FILE" \
    -ech_config_list "$ECH_LIST" 2>&1 || true)"
check "ECH accepted after restart" "ECH: success: 1" "$OUT"

echo "ech-proof: $FAILS failure(s)"
[[ "$FAILS" -eq 0 ]]
