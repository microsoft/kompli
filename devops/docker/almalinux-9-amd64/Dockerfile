# TODO: Add mcr.io retagged images
FROM almalinux:10@sha256:cc24bc5b6ac7e284f2f62a07bdaa1b15d3319fdcf46413c6b8fe9fa245068ddd

ARG CMAKE_VERSION=v3.30.1

RUN dnf install -y \
    autoconf \
    gcc \
    gcc-c++ \
    git \
    jq \
    libtool \
    openssl-devel \
    make \
    perl \
    perl-IPC-Cmd \
    python3 \
    rpm-build \
    tar \
    unzip \
    zip

RUN python3 -m venv /opt/kompli-venv
ENV PATH="/opt/kompli-venv/bin:${PATH}"

WORKDIR /git

# CMake
RUN git clone https://github.com/Kitware/CMake --recursive -b ${CMAKE_VERSION}
RUN cd CMake && ./bootstrap && make -j$(nproc) && make install && hash -r && rm -rf /git/CMake


# Run vcpkg to install build depends
COPY .  /src
WORKDIR /src
RUN (cd external/vcpkg && ./bootstrap-vcpkg.sh) && (cd src && ../external/vcpkg/vcpkg install) && rm -rf /src
