# TODO: Add mcr.io retagged images
FROM registry.access.redhat.com/ubi8/ubi@sha256:2dcfc23b79d88fdaeefc6ed0cfb144e41dca600bfa73c38ab5d8dca5b05d1b7f

ARG CMAKE_VERSION=v3.30.1

RUN yum install -y --disableplugin=subscription-manager \
    autoconf \
    curl \
    gcc \
    gcc-c++ \
    git \
    jq \
    libtool \
    make \
    openssl-devel \
    perl \
    perl-IPC-Cmd \
    python38 \
    rpm-build \
    tar \
    unzip \
    zip

RUN python3.8 -m venv /opt/kompli-venv
ENV PATH="/opt/kompli-venv/bin:${PATH}"

WORKDIR /git

# CMake
RUN git clone https://github.com/Kitware/CMake --recursive -b ${CMAKE_VERSION}
RUN cd CMake && ./bootstrap && make -j$(nproc) && make install && hash -r && rm -rf /git/CMake

COPY .  /src
WORKDIR /src
RUN (cd external/vcpkg && ./bootstrap-vcpkg.sh) && (cd src && ../external/vcpkg/vcpkg install) && rm -rf /src
