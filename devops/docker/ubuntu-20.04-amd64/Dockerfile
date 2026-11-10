FROM mcr.microsoft.com/mirror/docker/library/ubuntu:20.04@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214

ARG DEBIAN_FRONTEND=noninteractive

RUN apt -y update && apt-get -y install software-properties-common
RUN apt -y update && apt-get -y install \
    apt-transport-https \
    bc \
    build-essential \
    cmake \
    curl \
    gcovr\
    git \
    jq \
    libcurl4-openssl-dev \
    libgmock-dev \
    libgtest-dev \
    libssl-dev \
    ninja-build \
    pkg-config \
    python3-jsonschema \
    python3-venv \
    tar \
    unzip \
    uuid-dev \
    wget \
    zip

RUN python3 -m venv /opt/kompli-venv
ENV PATH="/opt/kompli-venv/bin:${PATH}"

RUN wget https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
RUN dpkg -i packages-microsoft-prod.deb && rm packages-microsoft-prod.deb
RUN apt-get update && apt-get install -y dotnet-sdk-5.0

WORKDIR /git

# CMake
COPY external/vcpkg/scripts/vcpkg-tools.json /git/vcpkg-tools.json
RUN CMAKE_VERSION=$(jq -er '.tools[] | select(.name == "cmake" and .os == "linux" and .arch == "amd64") | .version' /git/vcpkg-tools.json) && \
    git clone https://github.com/Kitware/CMake --recursive -b "v${CMAKE_VERSION}" && \
    cd CMake && ./bootstrap && make -j$(nproc) && make install && hash -r && \
    cmake --version | grep -Fx "cmake version ${CMAKE_VERSION}" && \
    rm -rf /git/CMake && rm /git/vcpkg-tools.json

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
