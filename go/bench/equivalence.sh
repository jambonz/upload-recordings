#!/bin/bash
# Plays the same websocket sessions to the C++ service and to the Go service
# and compares the objects each one stored. Run setup.sh first.
source "$(dirname "$0")/lib.sh"
OUT="$RESULTS/equiv"
rm -rf "$OUT"; mkdir -p "$OUT"

equiv() {
  docker run --rm --network $NET -e SSL_CERT_FILE=/certs/ca.crt -v "$CERTS:/certs:ro" \
    -v "$RESULTS:/results" "$TOOLS_IMAGE" equiv "$@"
}
for impl in cpp go; do
  start_sut $impl "$SUT_CPUS" --threads 4
  equiv run -out /results/equiv/$impl
  docker stop -t 30 ur-sut >/dev/null
  docker logs ur-sut > "$OUT/$impl-server.txt" 2>&1
done
equiv diff /results/equiv/cpp /results/equiv/go | tee "$OUT/diff.txt"
