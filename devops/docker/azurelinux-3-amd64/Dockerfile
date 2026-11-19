FROM mcr.microsoft.com/azurelinux/base/core:3.0@sha256:bfb630450e9c3d7428d59f25ce6df95ba5634d664d96b06017aa56f87da5ec0e

RUN tdnf install -y azurelinux-repos-extended
RUN tdnf install -y \
    azurelinux-rpm-macros \
    build-essential \
    ca-certificates \
    cmake \
    file \
    git \
    jq \
    openssl-devel \
    perl \
    perl-IPC-Cmd \
    python3 \
    rpm-build \
    shadow-utils \
    tar \
    tmux \
    tree \
    unzip \
    util-linux \
    uuid-devel \
    wget \
    zip

RUN tdnf upgrade -y && \
    tdnf clean all

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
