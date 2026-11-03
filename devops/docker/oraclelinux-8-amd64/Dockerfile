# TODO: Add mcr.io retagged images
FROM oraclelinux:8@sha256:1f74281d8cc37c6e4adef0559f4c583022193dcfa8562d2e4a87161b6cd54df8

ARG CMAKE_VERSION=v3.30.1

RUN yum install -y \
    autoconf \
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
    rpm-build

RUN python3.8 -m venv /opt/kompli-venv
ENV PATH="/opt/kompli-venv/bin:${PATH}"

WORKDIR /git

# CMake
RUN git clone https://github.com/Kitware/CMake --recursive -b ${CMAKE_VERSION}
RUN cd CMake && ./bootstrap && make -j$(nproc) && make install && hash -r && rm -rf /git/CMake

COPY .  /src
WORKDIR /src
RUN (cd external/vcpkg && ./bootstrap-vcpkg.sh) && (cd src && ../external/vcpkg/vcpkg install) && rm -rf /src
