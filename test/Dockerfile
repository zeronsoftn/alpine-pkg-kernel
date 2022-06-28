FROM alpine:3.16

RUN apk update && \
    apk add \
    bash curl wget ca-certificates git \
    shadow \
    alpine-sdk sudo \
    mkinitfs \
    perl gmp-dev mpc1-dev mpfr-dev elfutils-dev bash flex bison zstd \
    sed installkernel bc linux-headers linux-firmware-any openssl-dev mawk diffutils findutils \
    libarchive-tools

RUN useradd -m -s /bin/bash -G wheel user && \
    chmod 777 /var/cache/distfiles/ && \
    echo "%wheel ALL=(ALL) NOPASSWD: ALL" | tee /etc/sudoers.d/wheel-group

RUN mkdir -p /work/src && \
    chown user:user -R /work/

USER user

ADD "." "/work/src/"

ARG PACKAGER=test@lists.alpinelinux.org
RUN abuild-keygen -an

RUN cd /work/src && \
    export MAKEFLAGS="-j $(getconf _NPROCESSORS_ONLN)" && \
    abuild

