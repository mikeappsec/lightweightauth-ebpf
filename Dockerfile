# Build stage
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache make clang llvm lld musl-dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN make bpf
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" \
    -o /bin/lwauth-ebpf ./cmd/lwauth-ebpf

# Runtime stage
FROM alpine:3.21

RUN apk add --no-cache ca-certificates

COPY --from=builder /bin/lwauth-ebpf /usr/local/bin/lwauth-ebpf
COPY --from=builder /src/bpf/*.o /opt/lwauth-ebpf/bpf/

ENTRYPOINT ["lwauth-ebpf"]
CMD ["--config=/etc/lwauth-ebpf/config.yaml"]
