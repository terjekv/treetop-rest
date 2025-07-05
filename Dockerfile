FROM rust:1.88-alpine AS builder
WORKDIR /usr/src/treetop-rest
RUN apk add --no-cache \
    openssl-dev \
    openssl-libs-static \
    musl-dev \
    curl
COPY . .
RUN cargo install --path .

FROM alpine:3.22                      
RUN apk add --no-cache ca-certificates
COPY --from=builder /usr/src/treetop-rest/target/release/server /usr/local/bin/
CMD ["server"]