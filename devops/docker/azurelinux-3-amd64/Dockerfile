FROM mcr.microsoft.com/azurelinux/base/core:3.0@sha256:8bb51342bd5eba915990ab608f91060d502bb7891a2d3d909e0419b932533029

RUN tdnf install -y azurelinux-repos-extended
RUN tdnf install -y \
    azurelinux-rpm-macros \
    build-essential \
    ca-certificates \
    cmake \
    file \
    git \
    jq \
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

COPY .  /src
WORKDIR /src
RUN (cd external/vcpkg && ./bootstrap-vcpkg.sh) && (cd src && ../external/vcpkg/vcpkg install) && rm -rf /src
