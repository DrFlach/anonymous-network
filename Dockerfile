# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS builder
WORKDIR /src

# Cache deps first
COPY go.mod ./
RUN go mod download

# Build router binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/anon-router ./cmd/router/

# Runtime image
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /data
COPY --from=builder /out/anon-router /usr/local/bin/anon-router

# P2P + SOCKS5
EXPOSE 7656/tcp 4447/tcp

# Persist identity/config between restarts
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/anon-router"]
CMD ["-config", "/data/config.json", "-listen", "0.0.0.0:7656", "-socks", "0.0.0.0:4447", "-no-upnp"]
