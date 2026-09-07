# Validating a Module Interface Model (MIM) JSON

[`jsonschema`](https://github.com/Julian/jsonschema) can be run to validate a MIM JSON against the [mim.schema.json](./mim.schema.json) via the command line.

`jsonschema` is available on [PyPI](https://pypi.org/project/jsonschema/). You can install using [pip](https://pip.pypa.io/en/stable/):
```bash
$ pip install jsonschema
```

To validate a MIM JSON, run the following command:

```bash
$ jsonschema --instance my-new-mim.json mim.schema.json
```

## Status of the files in this directory

- **`mim.schema.json`** — active. Validates each module's MIM (e.g.
  `../mim/complianceengine.json`) at configure time (see `add_module()` in
  `../CMakeLists.txt`).
- **`mmi-get-info.schema.json`** — active (documentation only, not wired into
  the build). Describes the `MmiGetInfo` payload, which is a real, implemented,
  tested call (`ComplianceEngineMmiGetInfo` in `ComplianceEngineInterface.cpp`).
- **`mim.object.schema.json`** and **`rcdc.schema.json`** — orphaned. Neither
  is referenced by any code or build step; `mim.object.schema.json`'s only
  consumer is `rcdc.schema.json` itself. RC/DC files were part of the OSConfig
  local-management-authority MPI exchange format (see
  [docs/architecture.md](../../../docs/architecture.md) §3), which has no
  platform daemon to produce them in this fork. Left in place for now (not
  deleted) as a candidate for a future cleanup pass.
