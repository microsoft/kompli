FROM mcr.microsoft.com/mirror/docker/library/ubuntu:24.04@sha256:c35e29c9450151419d9448b0fd75374fec4fff364a27f176fb458d472dfc9e54

ARG DEBIAN_FRONTEND=noninteractive

RUN apt -y update && apt-get -y install software-properties-common
RUN apt -y update && apt-get -y install \
    apt-transport-https \
    bc \
    build-essential \
    clang \
    clang-tools \
    cmake \
    curl \
    file \
    gcovr \
    git \
    jq \
    libasan8 \
    libcurl4-openssl-dev \
    libssl-dev \
    libubsan1 \
    pkg-config \
    pre-commit \
    python3-jsonschema \
    python3-venv \
    tar \
    unzip \
    uuid-dev \
    wget \
    zip

RUN python3 -m venv /opt/kompli-venv
ENV PATH="/opt/kompli-venv/bin:${PATH}"

WORKDIR /git

# Initial CMake version needed for vcpkg boostrap
ARG CMAKE_VERSION=v3.30.1
COPY devops/scripts/install-container-cmake.sh /usr/local/bin/install-container-cmake
RUN bash /usr/local/bin/install-container-cmake "$CMAKE_VERSION" /usr/local

ENV KOMPLI_VCPKG_ROOT=/opt/kompli/vcpkg \
    VCPKG_DOWNLOADS=/opt/kompli/downloads \
    VCPKG_DEFAULT_BINARY_CACHE=/opt/kompli/binary-cache \
    X_VCPKG_REGISTRIES_CACHE=/opt/kompli/registries \
    VCPKG_DISABLE_METRICS=1
COPY external/vcpkg /opt/kompli/vcpkg
COPY devops/scripts/download-vcpkg-asset.sh /usr/local/bin/download-vcpkg-asset.sh
COPY devops/scripts/prepare-container-dependencies.sh /usr/local/bin/prepare-container-dependencies
RUN --mount=type=bind,source=src,target=/src \
    bash /usr/local/bin/prepare-container-dependencies /src

ENV X_VCPKG_ASSET_SOURCES="clear;x-block-origin"
RUN --network=none --mount=type=bind,source=src,target=/source/src \
    cp -a /source /tmp/kompli-offline && \
    cmake -S /tmp/kompli-offline/src -B /tmp/kompli-offline/build \
        -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON -DBUILD_TELEMETRY=OFF && \
    cmake --build /tmp/kompli-offline/build --parallel "$(nproc)" && \
    rm -rf /tmp/kompli-offline
WORKDIR /kompli
