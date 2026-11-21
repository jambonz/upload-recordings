#!/bin/bash
# Shared settings and helpers for the benchmark and equivalence scripts.
# Everything runs in Docker on one network; nothing is installed on the host.
set -euo pipefail

BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_DIR="$(dirname "$BENCH_DIR")"
REPO_DIR="$(dirname "$GO_DIR")"
RESULTS="${RESULTS:-$BENCH_DIR/results}"
CERTS="$BENCH_DIR/certs"

NET=urbench
CPP_IMAGE="${CPP_IMAGE:-upload-recordings-cpp:v1.9.3}"
GO_IMAGE="${GO_IMAGE:-upload-recordings-go:dev}"
TOOLS_IMAGE="${TOOLS_IMAGE:-upload-recordings-tools:dev}"
# MinIO no longer publishes images on Docker Hub; Chainguard builds the same server.
MINIO_IMAGE="${MINIO_IMAGE:-cgr.dev/chainguard/minio:latest}"
MYSQL_IMAGE="${MYSQL_IMAGE:-mysql:8.4}"

# CPU layout on the Docker host (12 CPUs here). The server under test never
# shares a core with the load generator, the object store or the database.
SUT_CPUS="${SUT_CPUS:-0-3}"      # default: 4 cores
STORE_CPUS="${STORE_CPUS:-8-9}"  # MinIO, fault proxy
LOAD_CPUS="${LOAD_CPUS:-10-11}"  # load generator, MySQL
SECRET=bench-secret

mkdir -p "$RESULTS"

sut_image() { if [ "$1" = cpp ]; then echo "$CPP_IMAGE"; else echo "$GO_IMAGE"; fi; }

# start_sut <cpp|go> <cpuset> [server args...]
start_sut() {
  local impl=$1 cpus=$2; shift 2
  docker rm -f ur-sut >/dev/null 2>&1 || true
  docker run -d --name ur-sut --network $NET --cpuset-cpus "$cpus" --ulimit nofile=65536:65536 \
    -e ENCRYPTION_SECRET=$SECRET -e BASIC_AUTH_USERNAME=bench -e BASIC_AUTH_PASSWORD=bench \
    -e MYSQL_HOST=mysql -e MYSQL_USER=root -e MYSQL_PASSWORD=bench -e MYSQL_DATABASE=jambones \
    -e S3_PATH_STYLE_SERVICES=minio,faultproxy -e STATS_HOST=127.0.0.1 \
    -v "$CERTS/ca.crt:/etc/ssl/certs/ca-certificates.crt:ro" \
    "$(sut_image "$impl")" --port 3017 "$@" >/dev/null
  local i
  for i in $(seq 1 120); do
    if docker run --rm --network $NET "$TOOLS_IMAGE" bash -c 'exec 3<>/dev/tcp/ur-sut/3017' 2>/dev/null; then return 0; fi
    sleep 0.5
  done
  echo "server did not start" >&2; docker logs ur-sut | tail -20 >&2; return 1
}

# start_monitor <label> <file>: samples the server from inside its PID namespace.
start_monitor() {
  docker rm -f ur-mon >/dev/null 2>&1 || true
  docker run -d --name ur-mon --pid container:ur-sut --cpuset-cpus "$LOAD_CPUS" \
    -v "$RESULTS:/results" "$TOOLS_IMAGE" procmon -label "$1" -out "/results/$2" >/dev/null
}
stop_monitor() { docker stop -t 5 ur-mon >/dev/null 2>&1 || true; docker rm -f ur-mon >/dev/null 2>&1 || true; }

# loadgen <args...>: runs the load generator; its JSON result goes to stdout.
loadgen() {
  docker run --rm --network $NET --cpuset-cpus "$LOAD_CPUS" --ulimit nofile=65536:65536 \
    -e SSL_CERT_FILE=/certs/ca.crt -v "$CERTS:/certs:ro" -v "$RESULTS:/results" \
    "$TOOLS_IMAGE" loadgen -url ws://ur-sut:3017 "$@"
}

ncpus() { # "0-3" -> 4, "0" -> 1
  local a=${1%-*} b=${1#*-}; echo $((b - a + 1))
}

# run_one <suite> <impl> <cpuset> <format> <sessions> <call_secs> <ramp_secs> <rep> [loadgen args...]
# Starts a fresh server, drives one load, and appends one merged JSON line
# (loadgen result + server resource usage) to $RESULTS/<suite>.jsonl.
run_one() {
  local suite=$1 impl=$2 cpus=$3 format=$4 sessions=$5 call=$6 ramp=$7 rep=$8; shift 8
  local n; n=$(ncpus "$cpus")
  local label="$suite/$impl/c$n/$format/s$sessions/r$rep"
  local run="${suite}${impl}c${n}${format}s${sessions}r${rep}x$$"
  echo "=== $label"
  # Same explicit settings for both: N worker threads / GOMAXPROCS for an
  # N-core limit (the C++ binary would otherwise size its pool from the
  # host's 12 CPUs), and the same upload connection cap.
  start_sut "$impl" "$cpus" --threads "${THREADS:-$n}" --aws-max-connections "${MAXCONNS:-64}"
  start_monitor "$label" "mon-$run.json"
  sleep 3
  loadgen -account "acct-$format${ACCOUNT_SUFFIX:-}" -format "$format" -sessions "$sessions" -call "$call" -ramp "$ramp" \
    -run "$run" -label "$label" -out "/results/lg-$run.json" "$@" >/dev/null
  sleep 2
  stop_monitor
  local t0 t1; t0=$(date +%s)
  docker stop -t 120 ur-sut >/dev/null; t1=$(date +%s)
  docker logs ur-sut > "$RESULTS/last-server.txt" 2>&1 || true
  python3 - "$RESULTS/lg-$run.json" "$RESULTS/mon-$run.json" "$suite" "$impl" "$n" "$format" "$rep" "$((t1 - t0))" \
    "$(grep -c -i 'dropping' "$RESULTS/last-server.txt" || true)" >> "$RESULTS/$suite.jsonl" <<'PY'
import json, sys
lg = json.load(open(sys.argv[1])); mon = json.load(open(sys.argv[2]))
out = dict(suite=sys.argv[3], impl=sys.argv[4], cores=int(sys.argv[5]), format=sys.argv[6], rep=int(sys.argv[7]),
           stop_secs=int(sys.argv[8]), drop_log_lines=int(sys.argv[9]), load=lg, server=mon)
print(json.dumps(out))
PY
  rm -f "$RESULTS/lg-$run.json" "$RESULTS/mon-$run.json"
  tail -1 "$RESULTS/$suite.jsonl" | python3 -c '
import json,sys
r=json.loads(sys.stdin.read()); l=r["load"]; s=r["server"]
print("    cpu %.1fs avg %.0f%% peak %.0f%% | rss idle %.0f median %.0f peak %.0f MB | found %d missing %d short %d | latency p50 %.0f p99 %.0f max %.0f ms | late %d (max %d ms) | busiest thread %.0f%%" % (
  s["cpu_secs"], s["avg_cpu_pct"], s["peak_cpu_pct"], s["start_rss_mb"], s["median_rss_mb"], s["peak_rss_mb"],
  l["objects_found"], l["objects_missing"], l["objects_short"], l["latency_ms"]["P50"], l["latency_ms"]["P99"], l["latency_ms"]["Max"],
  l["late_frames"], l["max_late_ms"], s["busiest_thread_share_pct"]))'
}
