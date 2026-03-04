FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build
RUN git clone https://github.com/hashicorp/vault-plugin-database-oracle.git .
RUN go build -o vault-plugin-database-oracle ./plugin

FROM hashicorp/vault:1.15

COPY --from=builder /build/vault-plugin-database-oracle /vault/plugins/vault-plugin-database-oracle
