#!/usr/bin/env bash
# #################################################################
# /qompassai/vongola/scripts/smoke.sh
# Qompass AI — vongola live smoke suite
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
# Runs the release binary against loopback fixtures on primo and
# checks the behaviors SPEC.md promises. Every check prints one
# PASS/FAIL line with its evidence; the script exits non-zero if
# any check fails. Nothing here touches non-loopback traffic
# except the local Tor daemon's own network activity and the
# config-gated, short-lived NAT mapping attempt (released on
# shutdown).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/target/release/vongola"
WORK="/tmp/vongola-smoke"
TOKEN="smoke-operator-token"
TOR_PW="smoke-tor-pw"
FAILS=0

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILS=$((FAILS + 1)); }
check() { # check <name> <expected-substring> <actual>
    if [[ "$3" == *"$2"* ]]; then pass "$1 [$3]"; else fail "$1 (want '$2' in '$3')"; fi
}

rm -rf "$WORK"
mkdir -p "$WORK/state1" "$WORK/state2" "$WORK/tor-data" "$WORK/upstream"
echo "fixture-upstream-ok" > "$WORK/upstream/index.html"

PIDS=()
cleanup() {
    for pid in "${PIDS[@]:-}"; do kill -KILL "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT

# ---- fixtures: upstream, socks5 hop, tor daemon -----------------
python3 -m http.server 18099 --directory "$WORK/upstream" --bind 127.0.0.1 \
    >"$WORK/httpserver.log" 2>&1 &
PIDS+=($!)

cat > "$WORK/socks5.py" <<'PYEOF'
import socket
import threading

def relay(a, b):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        try:
            b.shutdown(socket.SHUT_WR)
        except OSError:
            pass

def handle(conn):
    try:
        greeting = conn.recv(262)
        conn.sendall(b"\x05\x00")
        head = conn.recv(4)
        atyp = head[3]
        if atyp == 1:
            host = socket.inet_ntoa(conn.recv(4))
        elif atyp == 3:
            length = conn.recv(1)[0]
            host = conn.recv(length).decode()
        else:
            return
        port = int.from_bytes(conn.recv(2), "big")
        upstream = socket.create_connection((host, port), timeout=5)
        conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        threading.Thread(target=relay, args=(conn, upstream), daemon=True).start()
        relay(upstream, conn)
    except OSError:
        pass
    finally:
        conn.close()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 19060))
server.listen(64)
while True:
    conn, _ = server.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
PYEOF
python3 "$WORK/socks5.py" >"$WORK/socks5.log" 2>&1 &
PIDS+=($!)

TOR_HASH="$(tor --hash-password "$TOR_PW" | tail -1)"
# Hermetic torrc: primo's /etc/tor/torrc sets "User tor", which is
# fatal for a non-root launch; -f replaces it entirely.
cat > "$WORK/torrc" <<TEOF
ControlPort 127.0.0.1:19051
DataDirectory $WORK/tor-data
ExitPolicy reject *:*
ExitRelay 0
HashedControlPassword $TOR_HASH
Log notice stdout
SocksPort 127.0.0.1:19050
TEOF
tor -f "$WORK/torrc" >"$WORK/tor-stdout.log" 2>&1 &
PIDS+=($!)
sleep 2

# ---- config -----------------------------------------------------
cat > "$WORK/smoke.yaml" <<'YAMEOF'
a2a: {enabled: true}
admin_token_env: VONGOLA_SMOKE_OPERATOR_TOKEN
listeners:
  admin: {bind: "127.0.0.1:19091"}
  http: {bind: "127.0.0.1:18080"}
  https:
    bind: "127.0.0.1:18443"
    nat: {enabled: true, lease_secs: 120, protocols: [natpmp, pcp]}
node_name: smoke-node
profile: hosting
shutdown_grace_secs: 5
routes:
  - additional_hosts: ["www.qompass.local"]
    host: qompass.local
    name: apex
    onion: {enabled: true}
    redirect_www_to_apex: true
    self_signed_fallback: true
    static_root: ./examples/site
  - host: api.local
    name: api
    self_signed_fallback: true
    upstreams: [{address: "127.0.0.1:18099"}]
  - chain: [{address: "127.0.0.1:19060", kind: socks5}]
    host: chained.local
    name: chained
    self_signed_fallback: true
    upstreams: [{address: "127.0.0.1:18099"}]
  - chain: [{address: "127.0.0.1:9", kind: socks5}]
    host: chained-dead.local
    name: chained-dead
    self_signed_fallback: true
    upstreams: [{address: "127.0.0.1:18099"}]
state_dir: /tmp/vongola-smoke/state1
tor:
  control_addr: "127.0.0.1:19051"
  control_password_env: VONGOLA_SMOKE_TOR_PW
  enabled: true
worker_threads: 2
YAMEOF

cat > "$WORK/node2.yaml" <<'YAMEOF'
bundle_version: "2026.10.10-1"
listeners:
  admin: {bind: "127.0.0.1:19092"}
  http: {bind: "127.0.0.1:18082"}
  https: {bind: "127.0.0.1:18444"}
node_name: fleet-2
profile: fleet
shutdown_grace_secs: 5
routes:
  - host: qompass.local
    name: apex
    self_signed_fallback: true
    static_root: ./examples/site
state_dir: /tmp/vongola-smoke/state2
worker_threads: 2
YAMEOF

# ---- validate-config on examples + smoke configs ----------------
cd "$ROOT"
for cfg in examples/lean.yaml examples/fleet-node.yaml "$WORK/smoke.yaml" "$WORK/node2.yaml"; do
    if "$BIN" validate-config --config "$cfg" >"$WORK/validate.log" 2>&1; then
        pass "validate-config $cfg"
    else
        fail "validate-config $cfg ($(cat "$WORK/validate.log"))"
    fi
done
# qompass.yaml references operator cert paths; generate throwaway
# certs and validate an adjusted copy (the committed example is
# the operator template).
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout "$WORK/qompass.key" -out "$WORK/qompass.crt" \
    -subj "/CN=qompass.local" \
    -addext "subjectAltName=DNS:qompass.local,DNS:www.qompass.local" 2>/dev/null
sed -e "s|examples/certs/qompass.ai.crt|$WORK/qompass.crt|" \
    -e "s|examples/certs/qompass.ai.key|$WORK/qompass.key|" \
    examples/qompass.yaml > "$WORK/qompass-adjusted.yaml"
if "$BIN" validate-config --config "$WORK/qompass-adjusted.yaml" >"$WORK/validate.log" 2>&1; then
    pass "validate-config examples/qompass.yaml (adjusted cert paths)"
else
    fail "validate-config qompass adjusted ($(cat "$WORK/validate.log"))"
fi

# ---- start node 1 ----------------------------------------------
VONGOLA_SMOKE_OPERATOR_TOKEN="$TOKEN" VONGOLA_SMOKE_TOR_PW="$TOR_PW" \
    "$BIN" serve --config "$WORK/smoke.yaml" >"$WORK/vongola1.log" 2>&1 &
NODE1=$!
PIDS+=($NODE1)
for _ in $(seq 1 40); do
    curl -s -o /dev/null "http://127.0.0.1:19091/healthz" && break
    sleep 0.5
done

R="--resolve"
# 1. HTTP -> HTTPS 308
OUT="$(curl -s -o /dev/null -w "%{http_code} %{redirect_url}" -H "Host: qompass.local" http://127.0.0.1:18080/)"
check "http->https 308 redirect" "308 https://qompass.local:18443/" "$OUT"

# 2. HTTPS static fixture via SNI
BODY="$(curl -sk $R qompass.local:18443:127.0.0.1 https://qompass.local:18443/)"
check "https static fixture served" "Qompass AI" "$BODY"

# 3. Cache headers: fingerprinted asset immutable, HTML no-cache
HDR="$(curl -sk $R qompass.local:18443:127.0.0.1 -D - -o /dev/null https://qompass.local:18443/app.a1b2c3d4.js)"
check "fingerprinted asset immutable" "immutable" "$HDR"
HDR="$(curl -sk $R qompass.local:18443:127.0.0.1 -D - -o /dev/null https://qompass.local:18443/)"
check "html no-cache" "no-cache" "$HDR"
check "security headers present" "strict-transport-security" "$HDR"

# 4. gzip for compressible asset
ENC="$(curl -sk $R qompass.local:18443:127.0.0.1 -H "Accept-Encoding: gzip" -D - -o /dev/null https://qompass.local:18443/app.a1b2c3d4.js | grep -i "content-encoding" || true)"
check "gzip encoding applied" "gzip" "$ENC"

# 5. www -> apex 308
OUT="$(curl -sk $R www.qompass.local:18443:127.0.0.1 -o /dev/null -w "%{http_code} %{redirect_url}" https://www.qompass.local:18443/)"
check "www->apex 308" "308 https://qompass.local:18443/" "$OUT"

# 6. Proxied upstream + request id
HDR="$(curl -sk $R api.local:18443:127.0.0.1 -D - https://api.local:18443/)"
check "proxied upstream body" "fixture-upstream-ok" "$HDR"
check "x-request-id propagated" "x-request-id" "$HDR"

# 7. Agent card (signed)
CARD="$(curl -sk $R qompass.local:18443:127.0.0.1 https://qompass.local:18443/.well-known/agent-card.json)"
check "agent card published" '"signature"' "$CARD"
check "agent card names the service" "smoke-node" "$CARD"

# 8. Negotiated TLS group (the PQC evidence)
echo | openssl s_client -connect 127.0.0.1:18443 -servername qompass.local -tls1_3 \
    > "$WORK/sclient13.txt" 2>/dev/null || true
GROUP="$(grep -i "group" "$WORK/sclient13.txt" | head -2 | tr '\n' ' ' || true)"
echo "INFO: tls13: $GROUP"
if echo "$GROUP" | grep -qi "MLKEM"; then
    pass "tls1.3 PQ hybrid group negotiated [$GROUP]"
elif [[ -n "$GROUP" ]]; then
    fail "tls1.3 negotiated a non-PQ group [$GROUP]"
else
    fail "tls1.3 group capture empty"
fi

# 9. TLS 1.2 must be refused
CIPHER="$(echo | openssl s_client -connect 127.0.0.1:18443 -servername qompass.local -tls1_2 2>/dev/null | grep "Cipher is" || true)"
check "tls1.2 refused" "(NONE)" "$CIPHER"

# 10. Unknown SNI must be refused
CIPHER="$(echo | openssl s_client -connect 127.0.0.1:18443 -servername nope.invalid -tls1_3 2>/dev/null | grep "Cipher is" || true)"
check "unknown SNI refused" "(NONE)" "$CIPHER"

# 11. Metrics: unauthenticated 401; authenticated populated
CODE="$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:19091/metrics)"
check "metrics unauthenticated denied" "401" "$CODE"
METRICS="$(curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:19091/metrics)"
check "metrics populated vongola_up" "vongola_up 1" "$METRICS"
check "metrics request counter live" "vongola_requests_total" "$METRICS"

# 12. Dashboard: unauthenticated 401; authenticated HTML
CODE="$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:19091/dashboard)"
check "dashboard unauthenticated denied" "401" "$CODE"
DASH="$(curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:19091/dashboard)"
check "dashboard renders" "Vongola operator dashboard" "$DASH"
check "dashboard has NAT panel" "NAT traversal" "$DASH"
check "dashboard has Tor panel" "Tor onion services (never an exit node)" "$DASH"
check "dashboard has chain panel" "Proxy chains" "$DASH"

# 13. Live state JSON: NAT + Tor + chains (poll for tor publish)
STATE=""
for _ in $(seq 1 40); do
    STATE="$(curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:19091/api/state)"
    echo "$STATE" | grep -q '\.onion' && break
    sleep 1
done
ONION="$(echo "$STATE" | grep -o '[a-z2-7]\{56\}\.onion' | head -1 || true)"
echo "INFO: onion=${ONION:-none}"
if [[ -n "$ONION" ]]; then pass "tor onion service published"; else fail "tor onion service missing from state"; fi
NAT_STATUS="$(echo "$STATE" | python3 -c 'import json,sys; d=json.load(sys.stdin); entries=list((d.get("nat") or {}).values()); m=entries[0] if entries else {}; print(m.get("state","missing"), m.get("external_addr") or m.get("last_error") or "")' 2>/dev/null || echo parse-error)"
echo "INFO: nat=$NAT_STATUS"
if [[ "$NAT_STATUS" != "parse-error" && "$NAT_STATUS" != "missing "* && -n "$NAT_STATUS" ]]; then
    pass "nat structured outcome reported [$NAT_STATUS]"
else
    fail "nat state missing/structured outcome absent [$NAT_STATUS]"
fi

# 14. Live chain: socks5 hop fetches upstream; dead hop fails closed
BODY="$(curl -sk $R chained.local:18443:127.0.0.1 https://chained.local:18443/)"
check "chained route fetches via socks5 hop" "fixture-upstream-ok" "$BODY"
CODE="$(curl -sk $R chained-dead.local:18443:127.0.0.1 -o /dev/null -w "%{http_code}" https://chained-dead.local:18443/)"
check "dead chain hop fails closed (502, no direct fallback)" "502" "$CODE"

# 15. Oversized body bounded (413)
dd if=/dev/zero of="$WORK/big.bin" bs=1M count=17 2>/dev/null
CODE="$(curl -sk $R api.local:18443:127.0.0.1 -o /dev/null -w "%{http_code}" --data-binary @"$WORK/big.bin" https://api.local:18443/upload)"
check "oversized body rejected 413" "413" "$CODE"

# 16. MCP over stdio: read tool without token; mutation denied
MCP_IN='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"route_list","arguments":{}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"config_reload","arguments":{}}}'
MCP_OUT="$(printf '%s\n' "$MCP_IN" | "$BIN" mcp --config "$WORK/smoke.yaml" 2>/dev/null || true)"
check "mcp route_list answers" "qompass.local" "$MCP_OUT"
check "mcp unauthenticated mutation denied" "operator authorization required" "$MCP_OUT"

# 17. Memory footprint: idle vs under load
RSS_IDLE="$(grep VmRSS /proc/$NODE1/status | awk '{print $2}')"
for _ in $(seq 1 300); do curl -sk $R qompass.local:18443:127.0.0.1 -o /dev/null https://qompass.local:18443/app.a1b2c3d4.js; done
RSS_LOAD="$(grep VmRSS /proc/$NODE1/status | awk '{print $2}')"
echo "INFO: rss_idle_kb=$RSS_IDLE rss_after_300_requests_kb=$RSS_LOAD"
pass "memory measured (idle ${RSS_IDLE} kB, loaded ${RSS_LOAD} kB)"

# 18. Node 2 (fleet): independent instance, same fixture
VONGOLA_SMOKE_OPERATOR_TOKEN="$TOKEN" "$BIN" serve --config "$WORK/node2.yaml" \
    >"$WORK/vongola2.log" 2>&1 &
NODE2=$!
PIDS+=($NODE2)
for _ in $(seq 1 40); do
    curl -s -o /dev/null "http://127.0.0.1:19092/healthz" && break
    sleep 0.5
done
BODY="$(curl -sk $R qompass.local:18444:127.0.0.1 https://qompass.local:18444/)"
check "fleet node 2 serves fixture" "Qompass AI" "$BODY"

# 19. SIGTERM graceful shutdown timing (node 1)
START_NS="$(date +%s%N)"
kill -TERM "$NODE1"
while kill -0 "$NODE1" 2>/dev/null; do sleep 0.1; done
END_NS="$(date +%s%N)"
SHUTDOWN_MS=$(( (END_NS - START_NS) / 1000000 ))
echo "INFO: sigterm_shutdown_ms=$SHUTDOWN_MS"
if [[ "$SHUTDOWN_MS" -lt 10000 ]]; then
    pass "sigterm shutdown completed in ${SHUTDOWN_MS} ms"
else
    fail "sigterm shutdown too slow: ${SHUTDOWN_MS} ms"
fi

# 20. Log audit: no secrets in node logs
if grep -Eq "$TOKEN|$TOR_PW" "$WORK/vongola1.log" "$WORK/vongola2.log"; then
    fail "secret material found in logs"
else
    pass "log audit clean (no operator token / tor password)"
fi

# Node 2 shutdown too (its timing is not asserted).
kill -TERM "$NODE2" 2>/dev/null || true

echo "-----"
if [[ "$FAILS" -eq 0 ]]; then
    echo "SMOKE: ALL CHECKS PASSED"
else
    echo "SMOKE: $FAILS CHECK(S) FAILED"
    exit 1
fi
