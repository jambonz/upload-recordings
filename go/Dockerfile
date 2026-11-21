# Go implementation of upload-recordings (proposal; the C++ service and its
# Dockerfile at the repository root are untouched).
#
#   docker build -t upload-recordings-go --target server .
#   docker build -t upload-recordings-tools --target tools .   # benchmark tools
#   docker build --target test .                               # go test -race
FROM golang:1.26-bookworm AS build
RUN apt-get update \
  && apt-get install -y --no-install-recommends libmp3lame-dev \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN go build -trimpath -ldflags "-X main.version=${VERSION}" -o /out/upload_recordings ./cmd/upload-recordings

FROM build AS test
RUN go vet ./... && go test -race -count=1 ./...

FROM build AS tools-build
RUN CGO_ENABLED=0 go build -trimpath -o /out/ ./cmd/loadgen ./cmd/procmon ./cmd/seed ./cmd/faultproxy ./cmd/equiv

FROM debian:bookworm-slim AS tools
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*
COPY --from=tools-build /out/loadgen /out/procmon /out/seed /out/faultproxy /out/equiv /usr/local/bin/

FROM debian:bookworm-slim AS server
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates libmp3lame0 \
  && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/upload_recordings /usr/local/bin/upload_recordings
RUN mkdir -p /tmp/uploads
EXPOSE 3000
ENTRYPOINT ["upload_recordings"]
CMD ["--port", "3000"]
