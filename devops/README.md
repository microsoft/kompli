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

## Updating build containers used for CI builds
All build containers read the Linux amd64 CMake version from
[`external/vcpkg/scripts/vcpkg-tools.json`](../external/vcpkg/scripts/vcpkg-tools.json)
and build that version from source. The build verifies that `cmake` on `PATH`
reports the selected version before installing vcpkg dependencies. No manual
`CMAKE_VERSION` build argument is needed. Build images from the repository root
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
triplets, dependency preparation script, root CMake configuration, or Dockerfiles
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
