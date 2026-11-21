#!/bin/bash
# Benchmark suites. Run setup.sh first. Each run starts a fresh server, so
# runs are independent; results are appended to results/<suite>.jsonl.
#
#   ./run.sh main       4 cores; 10/100/500/1000 sessions; WAV and MP3; 60 s calls; 3 runs each
#   ./run.sh rate16k    as main at 16 kHz, 500 sessions, 2 runs each
#   ./run.sh scaling    1/2/4/8 cores; 1000 sessions; WAV and MP3; 30 s calls; 2 runs each
#   ./run.sh blast      1/2/4/8 cores; 8 connections sending as fast as the server reads for 1 s; 3 runs each
#   ./run.sh slow       one tenant's storage slow while another tenant records
#   ./run.sh stalled    as slow, but so slow that the uploads time out
#   ./run.sh failing    storage answering 503
#   ./run.sh coldstart  process start to accepting connections, 5 runs each
#   ./run.sh all
source "$(dirname "$0")/lib.sh"
IMPLS="${IMPLS:-cpp go}"

cpuset() { if [ "$1" = 1 ]; then echo 0; else echo "0-$(($1 - 1))"; fi; }

suite_main() {
  local rep s f impl
  for rep in 1 2 3; do for s in 10 100 500 1000; do for f in wav mp3; do for impl in $IMPLS; do
    run_one main $impl "$SUT_CPUS" $f $s 60 10 $rep
  done; done; done; done
}

suite_rate16k() {
  local rep f impl
  for rep in 1 2; do for f in wav mp3; do for impl in $IMPLS; do
    run_one rate16k $impl "$SUT_CPUS" $f 500 60 10 $rep -rate 16000
  done; done; done
}

suite_scaling() {
  local rep n f impl
  for rep in 1 2; do for n in 1 2 4 8; do for f in wav mp3; do for impl in $IMPLS; do
    run_one scaling $impl "$(cpuset $n)" $f 1000 30 10 $rep
  done; done; done; done
}

suite_blast() {
  local rep n impl
  for rep in 1 2 3; do for n in 1 2 4 8; do for impl in $IMPLS; do
    run_one blast $impl "$(cpuset $n)" wav 8 1 0 $rep -blast -summary=false -jitter 0
  done; done; done
}

start_proxy() { # faultproxy args...
  docker rm -f ur-faultproxy >/dev/null 2>&1 || true
  docker run -d --name ur-faultproxy --network $NET --network-alias faultproxy --cpuset-cpus "$STORE_CPUS" \
    -v "$CERTS:/certs:ro" "$TOOLS_IMAGE" faultproxy "$@" >/dev/null
  sleep 1
}

# Tenant A's bucket is slow: each upload is throttled, so a 10 s call (320 kB)
# takes 20 s to store at 16 kB/s. Tenant B's bucket is healthy and B has 50
# calls of 150 s in progress the whole time. Does A's backlog hurt B?
# "stalled" is the same at 4 kB/s: 80 s per upload, longer than either
# implementation waits, so every one of A's uploads times out.
suite_slow() { slow_like slow 16000; }
suite_stalled() { slow_like stalled 4000; }
slow_like() {
  local name=$1 bps=$2 impl rep
  start_proxy -bps "$bps"
  for rep in 1 2; do for impl in $IMPLS; do
    echo "=== $name/$impl/r$rep"
    start_sut $impl "$SUT_CPUS" --threads 4 --aws-max-connections 64
    start_monitor "$name/$impl/r$rep" "mon-slow.json"
    local run="${name}${impl}r${rep}x$$"
    loadgen -account acct-wav-fault -format wav -sessions 24 -call 10 -ramp 1 -jitter 0 -run "${run}a" \
      -label tenantA-slow -wait 600s -out /results/lg-slowA.json >/dev/null &
    loadgen -account acct-wav -format wav -sessions 50 -call 150 -ramp 1 -jitter 0 -run "${run}b" \
      -label tenantB-healthy -wait 600s -out /results/lg-slowB.json >/dev/null &
    wait
    stop_monitor
    docker stop -t 120 ur-sut >/dev/null; docker logs ur-sut > "$RESULTS/last-server.txt" 2>&1 || true
    grep -i -E 'error|fail' "$RESULTS/last-server.txt" | head -5 > "$RESULTS/$name-$impl-r$rep-errors.txt" || true
    python3 - "$RESULTS" "$impl" "$rep" "$(grep -c -i 'dropping' "$RESULTS/last-server.txt" || true)" "$name" >> "$RESULTS/$name.jsonl" <<'PY'
import json, sys
d = sys.argv[1]
print(json.dumps(dict(suite=sys.argv[5], impl=sys.argv[2], rep=int(sys.argv[3]), drop_log_lines=int(sys.argv[4]),
    tenantA=json.load(open(d + "/lg-slowA.json")), tenantB=json.load(open(d + "/lg-slowB.json")),
    server=json.load(open(d + "/mon-slow.json")))))
PY
    rm -f "$RESULTS"/lg-slow?.json "$RESULTS/mon-slow.json"
    tail -1 "$RESULTS/$name.jsonl" | python3 -c '
import json,sys
r=json.loads(sys.stdin.read())
for t in ("tenantA","tenantB"):
    l=r[t]; print("    %s: found %d missing %d short %d, audio lost %.1f MB of %.1f, latency p50 %.0f max %.0f ms" % (t, l["objects_found"], l["objects_missing"], l["objects_short"], l["audio_bytes_lost"]/1e6, l["bytes_sent"]/1e6, l["latency_ms"]["P50"], l["latency_ms"]["Max"]))
print("    server: peak rss %.0f MB, drop log lines %d" % (r["server"]["peak_rss_mb"], r["drop_log_lines"]))'
  done; done
  docker rm -f ur-faultproxy >/dev/null 2>&1 || true
}

# Storage answers every PUT with 503. 100 calls of 20 s end; then, with the
# server still running, 20 calls go to a healthy bucket.
suite_failing() {
  local impl
  start_proxy -fail 503
  for impl in $IMPLS; do
    echo "=== failing/$impl"
    start_sut $impl "$SUT_CPUS" --threads 4 --aws-max-connections 64
    start_monitor "failing/$impl" "mon-fail.json"
    local run="fail${impl}x$$" t0; t0=$(date +%s)
    loadgen -account acct-wav-fault -format wav -sessions 100 -call 20 -ramp 2 -run "${run}a" \
      -label storage-503 -wait 90s -out /results/lg-failA.json >/dev/null
    loadgen -account acct-wav -format wav -sessions 20 -call 5 -ramp 1 -run "${run}b" \
      -label healthy-after -wait 120s -out /results/lg-failB.json >/dev/null
    local left; left=$(docker exec ur-sut sh -c 'ls /tmp/uploads | wc -l')
    stop_monitor
    docker stop -t 120 ur-sut >/dev/null; docker logs ur-sut > "$RESULTS/last-server.txt" 2>&1 || true
    python3 - "$RESULTS" "$impl" "$left" "$(grep -c -i -E 'failed to upload' "$RESULTS/last-server.txt" || true)" >> "$RESULTS/failing.jsonl" <<'PY'
import json, sys
d = sys.argv[1]
print(json.dumps(dict(suite="failing", impl=sys.argv[2], spool_files_left=int(sys.argv[3]), upload_error_lines=int(sys.argv[4]),
    failing=json.load(open(d + "/lg-failA.json")), healthy_after=json.load(open(d + "/lg-failB.json")),
    server=json.load(open(d + "/mon-fail.json")))))
PY
    rm -f "$RESULTS"/lg-fail?.json "$RESULTS/mon-fail.json"
    tail -1 "$RESULTS/failing.jsonl" | cut -c1-200
  done
  docker rm -f ur-faultproxy >/dev/null 2>&1 || true
}

# Time from exec to the port accepting connections, measured inside the
# container so Docker's own start-up is excluded.
suite_coldstart() {
  local impl i
  for impl in $IMPLS; do for i in 1 2 3 4 5; do
    docker run --rm --network $NET --entrypoint bash \
      -e ENCRYPTION_SECRET=$SECRET -e BASIC_AUTH_USERNAME=bench -e BASIC_AUTH_PASSWORD=bench \
      -e MYSQL_HOST=mysql -e MYSQL_USER=root -e MYSQL_PASSWORD=bench -e MYSQL_DATABASE=jambones \
      "$(sut_image $impl)" -c '
        t0=$(date +%s%N); upload_recordings --port 3017 >/dev/null 2>&1 &
        until (exec 3<>/dev/tcp/127.0.0.1/3017) 2>/dev/null; do sleep 0.01; done
        echo "{\"suite\":\"coldstart\",\"impl\":\"'$impl'\",\"ms\":$(( ($(date +%s%N) - t0) / 1000000 ))}"' \
      | tee -a "$RESULTS/coldstart.jsonl"
  done; done
}

case "${1:-}" in
  main|rate16k|scaling|blast|slow|stalled|failing|coldstart) "suite_$1" ;;
  all) suite_coldstart; suite_main; suite_rate16k; suite_scaling; suite_blast; suite_failing; suite_slow; suite_stalled ;;
  *) sed -n '2,14p' "$0"; exit 2 ;;
esac
