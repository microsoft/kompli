FROM mcr.microsoft.com/mirror/docker/library/debian:bookworm@sha256:d74df7598108a173a621eda4d58a2adbf850b2d9a9d81bc2cca1a6c21174a880

ARG DEBIAN_FRONTEND=noninteractive

RUN apt -y update && apt-get -y install software-properties-common
RUN apt -y update && apt-get -y install \
    bc \
    build-essential \
    cmake \
    curl \
    file \
    gcovr \
    git \
    jq \
    libssl-dev \
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

WORKDIR /git

# CMake
COPY external/vcpkg/scripts/vcpkg-tools.json /git/vcpkg-tools.json
RUN CMAKE_VERSION=$(jq -er '.tools[] | select(.name == "cmake" and .os == "linux" and .arch == "amd64") | .version' /git/vcpkg-tools.json) && \
    git clone https://github.com/Kitware/CMake --recursive -b "v${CMAKE_VERSION}" && \
    cd CMake && ./bootstrap && make -j$(nproc) && make install && hash -r && \
    cmake --version | grep -Fx "cmake version ${CMAKE_VERSION}" && \
    rm -rf /git/CMake && rm /git/vcpkg-tools.json

COPY .  /src
WORKDIR /src
RUN (cd external/vcpkg && ./bootstrap-vcpkg.sh) && (cd src && ../external/vcpkg/vcpkg install) && rm -rf /src
