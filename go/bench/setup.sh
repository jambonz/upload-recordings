#!/bin/bash
# Builds the images and starts the fixtures the benchmarks need: MySQL with
# an accounts table, MinIO behind TLS (the C++ service only speaks HTTPS to
# S3-compatible stores) and a bucket.
#
#   CPP_REF=v1.9.3 ./setup.sh
source "$(dirname "$0")/lib.sh"
CPP_REF="${CPP_REF:-v1.9.3}"

docker network inspect $NET >/dev/null 2>&1 || docker network create $NET >/dev/null

if [ ! -f "$CERTS/ca.crt" ]; then
  mkdir -p "$CERTS"
  ( cd "$CERTS"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=upload-recordings bench CA" \
      -keyout ca.key -out ca.crt 2>/dev/null
    openssl req -newkey rsa:2048 -nodes -subj "/CN=minio" -keyout private.key -out server.csr 2>/dev/null
    printf "subjectAltName=DNS:minio,DNS:faultproxy,DNS:localhost\n" > san.ext
    openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 3650 \
      -extfile san.ext -out public.crt 2>/dev/null
    chmod 644 private.key )
fi

if ! docker image inspect "$CPP_IMAGE" >/dev/null 2>&1; then
  echo "building $CPP_IMAGE from $CPP_REF (this is the slow one)"
  tmp=$(mktemp -d); git -C "$REPO_DIR" archive "$CPP_REF" | tar -x -C "$tmp"
  docker build -t "$CPP_IMAGE" "$tmp"; rm -rf "$tmp"
fi
docker build -q -t "$GO_IMAGE" --target server "$GO_DIR" >/dev/null
docker build -q -t "$TOOLS_IMAGE" --target tools "$GO_DIR" >/dev/null

docker rm -f ur-mysql ur-minio >/dev/null 2>&1 || true
docker run -d --name ur-mysql --network $NET --network-alias mysql --cpuset-cpus "$LOAD_CPUS" \
  -e MYSQL_ROOT_PASSWORD=bench -e MYSQL_DATABASE=jambones "$MYSQL_IMAGE" >/dev/null
docker run -d --name ur-minio --network $NET --network-alias minio --cpuset-cpus "$STORE_CPUS" \
  --user 0 -v "$CERTS:/certs:ro" "$MINIO_IMAGE" server /data --certs-dir /certs >/dev/null

echo "waiting for MySQL"
until docker exec ur-mysql mysql -uroot -pbench -e 'select 1' jambones >/dev/null 2>&1; do sleep 1; done
docker run --rm "$TOOLS_IMAGE" seed -secret $SECRET | docker exec -i ur-mysql mysql -uroot -pbench jambones
docker run --rm --network $NET -e SSL_CERT_FILE=/certs/ca.crt -v "$CERTS:/certs:ro" "$TOOLS_IMAGE" seed -mkbucket
echo "ready"
