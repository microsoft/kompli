# TODO: Add mcr.io retagged images
FROM registry.suse.com/bci/bci-base:15.7@sha256:a1bff75c7ab3d66c8423e3f2370838d5dbed077a4133e9f38a98d7525a630958

RUN zypper install -y \
    autoconf \
    curl \
    gcc \
    gcc-c++ \
    git \
    jq \
    libtool \
    make \
    libopenssl-devel \
    python3 \
    rpm-build \
    tar \
    unzip \
    zip

RUN python3 -m venv /opt/kompli-venv
ENV PATH="/opt/kompli-venv/bin:${PATH}"
RUN printf '%s\n' \
    'dataclasses==0.8 \' \
    '    --hash=sha256:0201d89fa866f68c8ebd9d08ee6ff50c0b255f8ec63a71c16fda7af82bb887bf \' \
    '    --hash=sha256:8479067f342acf957dc82ec415d355ab5edb7e7646b90dc6e2fd1d96ad084c97' \
    > /tmp/python-requirements.txt && \
    pip install --require-hashes -r /tmp/python-requirements.txt && \
    rm -f /tmp/python-requirements.txt

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
