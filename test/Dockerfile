FROM alpine:3.18

RUN apk update && \
    apk add \
    bash curl wget ca-certificates git \
    shadow \
    alpine-sdk sudo \
    mkinitfs \
    perl gmp-dev mpc1-dev mpfr-dev elfutils-dev bash flex bison zstd \
    sed installkernel bc linux-headers linux-firmware-any \
    openssl-dev mawk diffutils findutils \
    libarchive-tools \
    pahole python3

RUN apk add lzo-dev zstd-dev libarchive-dev
ARG ICECC_URL=https://github.com/icecc/icecream/releases/download/1.4/icecc-1.4.0.tar.gz
ARG ICECC_SHA256=884caebb93afa096e6d881677b9a432ae528bab297725f1d737a463ab45ba393
RUN wget -O /tmp/icecc.tar.xz "${ICECC_URL}" && \
    echo "${ICECC_SHA256}  /tmp/icecc.tar.xz" | sha256sum -c

RUN mkdir -p /tmp/icecc && \
    cd /tmp/icecc && \
    tar --strip-components 1 -xf /tmp/icecc.tar.xz && \
    [ -f ./autogen.sh ] && ./autogen.sh || true && \
    ./configure --prefix=/usr --without-libcap_ng && \
    make -j4 && \
    make install && \
    useradd -r -m -s /bin/bash icecc

RUN useradd -m -s /bin/bash -G wheel user && \
    chmod 777 /var/cache/distfiles/ && \
    echo "%wheel ALL=(ALL) NOPASSWD: ALL" | tee /etc/sudoers.d/wheel-group

RUN mkdir -p /work/src && \
    chown user:user -R /work/

USER user

ADD "." "/work/src/"

ARG PACKAGER=test@lists.alpinelinux.org
RUN abuild-keygen -an

ARG ICECC_SCHEDULER=
RUN cd /work/src && \
    mkdir -p $HOME/.log/ && \
    ([ -z "${ICECC_SCHEDULER:-}" ] && echo "NO ICECC_SCHEDULER" || iceccd -m 1 -s ${ICECC_SCHEDULER} -d -l $HOME/.log/iceccd.log) && \
    export PATH=/usr/libexec/icecc/bin:$PATH && \
    export MAKEFLAGS="-j $(getconf _NPROCESSORS_ONLN)" && \
    abuild

