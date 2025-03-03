FROM --platform=${BUILDPLATFORM:-linux/amd64} rust:latest AS builder

WORKDIR /app
#为了命中docker构建缓存，先拷贝这几个文件进去
RUN apt-get update &&\
    apt-get install -y --no-install-recommends xz-utils liblz4-tool libc6-dev libssl-dev pkg-config musl-tools patchelf build-essential zlib1g-dev ca-certificates
COPY .cargo .cargo
COPY observer_ward/Cargo.toml Cargo.toml
COPY engine/ /engine
RUN cargo fetch
COPY observer_ward/src src
# `ARG`/`ENV` pair is a workaround for `docker build` backward-compatibility.
#
# https://github.com/docker/buildx/issues/510
ARG BUILDPLATFORM
ENV BUILDPLATFORM=${BUILDPLATFORM:-linux/amd64}

RUN case "$BUILDPLATFORM" in \
        */amd64 ) PLATFORM=x86_64 ;; \
        */arm64 | */arm64/* ) PLATFORM=aarch64 ;; \
        * ) echo "Unexpected BUILDPLATFORM '$BUILDPLATFORM'" >&2; exit 1 ;; \
    esac; \
    \
    rustup target add $PLATFORM-unknown-linux-musl; \
    cargo build --release --target=$PLATFORM-unknown-linux-musl

# Use any runner as you want
# But beware that some images have old glibc which makes rust unhappy
FROM --platform=${BUILDPLATFORM:-linux/amd64} alpine:latest AS observer_ward
ENV TZ=Asia/Shanghai
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
COPY --from=builder /app/target/*/release/observer_ward /usr/local/bin/
ADD "https://0x727.github.io/FingerprintHub/web_fingerprint_v4.json" web_fingerprint_v4.json
RUN observer_ward --update-plugin
ENTRYPOINT [ "observer_ward" ]
#docker build --target observer_ward_with_nuclei -t "observer_ward:dev" . -f Dockerfile
FROM observer_ward AS observer_ward_with_nuclei
COPY --from=projectdiscovery/nuclei:latest /usr/local/bin/nuclei /usr/local/bin/
