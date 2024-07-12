FROM rust:latest AS builder

WORKDIR /app
#为了命中docker构建缓存，先拷贝这几个文件进去
RUN apt-get update &&\
    apt-get install -y --no-install-recommends gcc-multilib xz-utils liblz4-tool libc6-dev libssl-dev pkg-config musl-tools patchelf build-essential zlib1g-dev ca-certificates
COPY .cargo .cargo
COPY observer_ward/Cargo.toml Cargo.toml
COPY engine/ /engine
RUN cargo fetch
COPY observer_ward/src src
RUN rustup target add x86_64-unknown-linux-musl
RUN cargo build --release --target=x86_64-unknown-linux-musl

# Use any runner as you want
# But beware that some images have old glibc which makes rust unhappy
FROM alpine:latest AS observer_ward
ENV TZ=Asia/Shanghai
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/observer_ward /usr/local/bin/
ADD "https://0x727.github.io/FingerprintHub/web_fingerprint_v4.json" web_fingerprint_v4.json
RUN observer_ward --update-plugin
ENTRYPOINT [ "observer_ward" ]
#docker build --target observer_ward_with_nuclei -t "observer_ward:dev" . -f Dockerfile
FROM observer_ward AS observer_ward_with_nuclei
COPY --from=projectdiscovery/nuclei:latest /usr/local/bin/nuclei /usr/local/bin/
