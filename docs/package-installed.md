# PackageInstalled: locally cached APT candidates

For Debian and Ubuntu, opt into checking that an installed package meets its
current locally cached APT candidate:

```json
{
  "PackageInstalled": {
    "packageName": "libpam-runtime",
    "packageManager": "dpkg",
    "latestPackageVersion": "true"
  }
}
```

This replaces a fixed minimum-version requirement for checks such as PAM package
updates. Use the same payload with `libpam-modules`, `libpam-pwquality`, or
`cracklib-runtime` to check those packages.

The engine reads `apt-cache policy` without refreshing repositories or installing
packages. A version below the candidate is non-compliant; the same or a newer
version is compliant. An installed package without an APT candidate is compliant.
Missing packages are non-compliant. Held installed packages are checked too.
Architecture-qualified package names are supported.

Candidate and installed versions are persisted together in the existing package
cache. Entries use its existing 3000-second refresh interval. Legacy caches
without candidates are enriched on demand. Unlike presence-only checks, latest
checks return an error if refreshing a stale cache fails. APT query, parsing, and
dpkg comparison failures also return errors, not compliance.

`latestPackageVersion` defaults to false and is supported only for dpkg (including
autodetection). RPM requests with it enabled return an error. It can be combined
with `minPackageVersion`; both requirements must pass. Existing presence and
minimum-version checks are otherwise unchanged. APT candidate comparisons use
dpkg's native version ordering, including epochs, revisions, and pre-releases.
As with other built-in procedure arguments, encode the boolean as a JSON string.
