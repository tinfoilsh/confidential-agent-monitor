FROM docker.io/library/ubuntu:24.04@sha256:224a1869083a311ef3f13648a154ba79832fbef6364d31493642ca03082da254 AS build
ARG TARGET
ARG LINUX=6.1.155
ARG LINUX_SHA256=c29387aeee085fbcbd91236224b9df805063bac43615e75cea2c6b29604a5c73
ENV DEBIAN_FRONTEND=noninteractive KBUILD_BUILD_TIMESTAMP=@0 KBUILD_BUILD_USER=perimeter KBUILD_BUILD_HOST=perimeter
RUN apt-get update && apt-get install -y --no-install-recommends \
    bc bison ca-certificates curl flex gcc gcc-aarch64-linux-gnu libc6-dev libelf-dev libssl-dev make xz-utils \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$LINUX.tar.xz" -o /tmp/linux.tar.xz \
    && echo "$LINUX_SHA256  /tmp/linux.tar.xz" | sha256sum -c --quiet \
    && tar -xJf /tmp/linux.tar.xz -C /usr/src \
    && rm /tmp/linux.tar.xz
WORKDIR /usr/src/linux-$LINUX
# Firecracker's CI kernel supplies the config; `perimeter network` also needs TUN.
RUN case $TARGET in \
      x86_64) set -- x86_64 '' vmlinux e20e46d0c36c55c0d1014eb20576171b3f3d922260d9f792017aeff53af3d4f2 ;; \
      aarch64) set -- arm64 aarch64-linux-gnu- arch/arm64/boot/Image e3544b10603acbf3db492cb52e000d22ba202cb4b63b9add027565683e11c591 ;; \
      *) exit 1 ;; \
    esac \
    && curl -fsSL "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/$TARGET/vmlinux-$LINUX" -o /tmp/ci-kernel \
    && echo "$4  /tmp/ci-kernel" | sha256sum -c --quiet \
    && scripts/extract-ikconfig /tmp/ci-kernel > .config \
    && scripts/config --enable TUN \
    && make ARCH="$1" CROSS_COMPILE="$2" olddefconfig \
    && grep -qx CONFIG_TUN=y .config \
    && make ARCH="$1" CROSS_COMPILE="$2" -j"$(nproc)" "${3##*/}" \
    && cp "$3" /kernel.bin

FROM scratch
COPY --from=build /kernel.bin /
