[![CI Tests](https://github.com/microsoft/kompli/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/kompli/actions/workflows/ci.yml)
[![insiders-fast](https://github.com/microsoft/kompli/actions/workflows/insiders-fast.yml/badge.svg)](https://github.com/microsoft/kompli/actions/workflows/insiders-fast.yml)
[![prod](https://github.com/microsoft/kompli/actions/workflows/prod.yml/badge.svg)](https://github.com/microsoft/kompli/actions/workflows/prod.yml)


# DevOps Folder
This folder contains the artifacts and scripts used by our engineering systems (build, test, package).

- `debian` - Debian packaging scripts
- `docker/<os>-<arch>` - Build containers for supported operating systems and architectures
  - `amd64`
  - `arm` (armv7)
  - `arm64` (aarch64)
- `e2e`
  - `cloudtest` - backup of 1ES managed CloudTest image definitions
  - `terraform` - terraform modules for provisioning Azure resources for E2E tests
- `rpm` - RPM packaging scripts

## Updating Build contaienrs used for CI builds
All build containers read the Linux amd64 CMake version from
[`external/vcpkg/scripts/vcpkg-tools.json`](../external/vcpkg/scripts/vcpkg-tools.json)
and build that version from source. The build verifies that `cmake` on `PATH`
reports the selected version before installing vcpkg dependencies. No manual
`CMAKE_VERSION` build argument is needed. Build images from the repository root
with the vcpkg submodule initialized, for example:

```bash
git submodule update --init --recursive
docker build -f devops/docker/ubuntu-24.04-amd64/Dockerfile .
```

Updating the vcpkg submodule also triggers the build-container workflow.

The `docker/<os>-<arch>` - Build containers are used by ci [ci.yml](.github/workflows/ci.yml)
Their version(digest's) are stored inside [test-matrix.json](.github/test-matrix.json)
The [build-containers.yml](.github/workflows/build-contains.yml) is ran whenever any Build Containers dockerfile is changed.
The [build-containers.yml](.github/workflows/build-contains.yml) produces new-test-matrix.json that can be copted to [test-matrix.json](.github/test-matrix.json) and commited. Then next [ci.yml](.github/workflows/ci.yml) will use updated containers to run builds & tests.
