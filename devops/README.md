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

## Development container

The [development container](../.devcontainer/devcontainer.json) includes Azure CLI
and its `azure-devops` extension for inspecting Azure Pipelines. After changing
the configuration, run **Dev Containers: Rebuild Container** in VS Code. Verify
the installation with `az --version` and `az extension show --name azure-devops`.
Authenticate with `az login` before accessing private builds.

## Updating build containers used for CI builds
All build containers use a two-stage CMake source build:

1. `ARG CMAKE_VERSION=v4.4.2` selects the CMake tag installed in the image.
2. The bootstrap CMake installs the dependencies from
   [`src/vcpkg.json`](../src/vcpkg.json), including OpenSSL 3.6 or newer. vcpkg
   acquires Ninja first, then uses the bootstrap tools without downloading a
   newer CMake binary.
3. The same CMake version is rebuilt from source against the static OpenSSL libraries installed by
   vcpkg. Static linking keeps the final tools usable after the temporary
   dependency installation is removed. Headers, libraries, and pkg-config
   metadata all come from that same OpenSSL prefix.
4. The manifest is installed again using vcpkg's normal tool selection to refresh
   package ABIs and populate the binary cache used by subsequent offline project
   builds. vcpkg may acquire a private CMake for dependencies, but it does not
   replace the image's CMake in `/usr/local`.

Both CMake builds verify the installed `cmake`, `ctest`, and `cpack` versions.
`--build-arg CMAKE_VERSION=v4.4.2` selects both the bootstrap and final versions;
the version must satisfy the project's `cmake_minimum_required`. Build images from the repository root
with Podman (or Docker with BuildKit enabled) and the vcpkg submodule initialized,
for example:

```bash
git submodule update --init --recursive
docker build --layers -f devops/docker/ubuntu-24.04-amd64/Dockerfile .
```

The images install all dependencies from [`src/vcpkg.json`](../src/vcpkg.json),
including Lua, while network access is available. The bootstrapped vcpkg tree,
downloaded source archives and helper tools, binary packages, and registry cache
are retained under `/opt/kompli`. `KOMPLI_VCPKG_ROOT` selects that bootstrapped
tree for CMake; builds outside these images still use a build-local vcpkg tree.
Each build restores dependencies into its own `build/vcpkg_installed` directory.
The image also retains the registry lock and seeds it into fresh build trees,
preventing vcpkg from fetching registry HEAD when no installation exists yet.
The images block vcpkg origin downloads after dependency preparation, so a
missing asset fails explicitly instead of downloading during the project build.
During dependency preparation, the asset helper retrieves Lua archives from the
MacPorts mirror; vcpkg still verifies the SHA512 from the selected port. Other
assets use their upstream URLs. The helper is disabled for offline builds.

Every image must pass a fresh Release configure and build with tests enabled,
telemetry disabled, and `RUN --network=none`. This checks the actual project
without network access before the image can be published. Optional telemetry
uses an external SDK outside the vcpkg manifest and is not covered by this
offline check.

Changes to the manifest, registry configuration, vcpkg submodule, overlays,
triplets, CMake installation script, dependency preparation script, root CMake configuration, or Dockerfiles
trigger the [build-container workflow](../.github/workflows/build-containers.yml).
Rebuild images when these dependency inputs change; do not enable downloads in
the later project build to work around stale images.

Run the container setup regression tests locally with:

```bash
python3 -m unittest discover -s devops/scripts/tests
```

The images are used by [CI](../.github/workflows/ci.yml), with pinned digests in
[`test-matrix.json`](../.github/test-matrix.json). After rebuilding, copy the
workflow's `new-test-matrix.json` artifact into that file and commit it so later
builds use the new images.
