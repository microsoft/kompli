#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Convert ComplianceEngine MOF benchmarks to/from a human-readable JSON format.

Anything that does not match the generation rules is preserved in a per-rule
``overrides`` object, so ``mof -> json -> mof`` is always the identity transform.

    mof  -> json : decode and strip regenerable fields into a compact document.
    json -> mof  : regenerate every field, producing the original MOF byte-exact.

Usage:
    mof_json.py to-json  INPUT.mof  [-o OUTPUT.json]
    mof_json.py to-mof   INPUT.json [-o OUTPUT.mof]
    mof_json.py verify   INPUT.mof            # assert mof->json->mof is identity

If ``-o`` is omitted the result is written to stdout.

NOTICE: THIS TOOL IS FOR DEVELOPMENT PURPOSES ONLY, THE JSON FORMAT MAY, CAN, AND
WILL CHANGE AT ANY TIME, WITHOUT PRIOR NOTICE.

"""

import argparse
import base64
import json
import re
import sys

NOTICE = (
    "NOTICE: THIS TOOL IS FOR DEVELOPMENT PURPOSES ONLY, THE JSON FORMAT MAY, "
    "CAN, AND WILL CHANGE AT ANY TIME, WITHOUT PRIOR NOTICE."
)

# Fields whose MOF string value is base64-encoded compact JSON.
BASE64_JSON_FIELDS = {"ProcedureObjectValue"}
# Fields whose MOF string value is an (escaped) compact JSON string.
EMBEDDED_JSON_FIELDS = {"DesiredObjectValue"}

# The exact order in which properties appear inside an OsConfigResource block.
RESOURCE_FIELD_ORDER = [
    "ResourceID",
    "PayloadKey",
    "RuleId",
    "ComponentName",
    "ProcedureObjectName",
    "ProcedureObjectValue",
    "InitObjectName",
    "ReportedObjectName",
    "ExpectedObjectValue",
    "DesiredObjectName",
    "DesiredObjectValue",
    "ModuleName",
    "ModuleVersion",
    "ConfigurationName",
    "SourceInfo",
]

# Object-name field -> prefix prepended to the PascalCase ResourceID description.
GENERATED_NAME_FIELDS = {
    "ProcedureObjectName": "procedure",
    "InitObjectName": "init",
    "ReportedObjectName": "audit",
    "DesiredObjectName": "remediate",
}

# Constant fields shared by every resource. These are hardcoded rather than
# stored in the JSON; a rule only carries an override if it ever deviates.
COMMON_VALUES = {
    "ComponentName": "ComplianceEngine",
    "ExpectedObjectValue": "PASS",
    "ModuleName": "GuestConfiguration",
    "ModuleVersion": "1.0.0",
    "ConfigurationName": "ComplianceEngine",
    "SourceInfo": "::4::5::OsConfigResource",
}

# Per-rule fields kept verbatim (regeneration handles everything else).
RESOURCE_CLASS = "OsConfigResource"
CONFIG_DOCUMENT_CLASS = "OMI_ConfigurationDocument"

_INSTANCE_RE = re.compile(r"^instance of (\w+)(?: as \$(\w+))?\s*$")
_PROPERTY_RE = re.compile(r"^\s+(\w+)\s*=\s*(.*);\s*$")

_MOF_UNESCAPE = {
    "\\": "\\",
    '"': '"',
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "b": "\b",
    "f": "\f",
}
_MOF_ESCAPE = {
    "\\": "\\\\",
    '"': '\\"',
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
    "\b": "\\b",
    "\f": "\\f",
}


class MofError(ValueError):
    """Raised when a MOF or JSON document cannot be parsed."""


def _unescape_mof_string(text):
    out = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\" and i + 1 < n:
            nxt = text[i + 1]
            out.append(_MOF_UNESCAPE.get(nxt, "\\" + nxt))
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _escape_mof_string(text):
    return "".join(_MOF_ESCAPE.get(ch, ch) for ch in text)


def _parse_string_list(inner):
    """Parse the body of a MOF array literal: ``"a","b",...`` -> [a, b, ...]."""
    items = []
    i = 0
    n = len(inner)
    while i < n:
        while i < n and inner[i] in " \t":
            i += 1
        if i >= n:
            break
        if inner[i] != '"':
            raise MofError(f"expected '\"' in array literal: {inner!r}")
        i += 1
        start = i
        buf = []
        while i < n:
            ch = inner[i]
            if ch == "\\" and i + 1 < n:
                buf.append(inner[i : i + 2])
                i += 2
                continue
            if ch == '"':
                break
            buf.append(ch)
            i += 1
        if i >= n:
            raise MofError(f"unterminated string in array literal: {inner!r}")
        items.append(_unescape_mof_string("".join(buf)))
        i += 1  # closing quote
        while i < n and inner[i] in " \t":
            i += 1
        if i < n and inner[i] == ",":
            i += 1
    return items


def _compact_json(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def _decode_embedded(text, original_compact):
    """Decode a compact-JSON string into an object only if it round-trips.

    Returns the decoded object when re-encoding reproduces ``original_compact``
    exactly, otherwise ``None`` so the caller keeps the raw representation and
    identity is preserved.
    """
    try:
        obj = json.loads(text)
    except (ValueError, TypeError):
        return None
    if _compact_json(obj) == original_compact:
        return obj
    return None


def _parse_property_value(key, raw):
    raw = raw.strip()
    if raw.startswith('"'):
        if not raw.endswith('"') or len(raw) < 2:
            raise MofError(f"malformed string value for {key}: {raw!r}")
        value = _unescape_mof_string(raw[1:-1])
        if key in BASE64_JSON_FIELDS and value:
            try:
                decoded = base64.b64decode(value, validate=True).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                return value
            obj = _decode_embedded(decoded, decoded)
            return obj if obj is not None else value
        if key in EMBEDDED_JSON_FIELDS and value:
            obj = _decode_embedded(value, value)
            return obj if obj is not None else value
        return value
    if raw.startswith("{") and raw.endswith("}"):
        return _parse_string_list(raw[1:-1])
    raise MofError(f"unsupported value literal for {key}: {raw!r}")


def parse_mof(text):
    """Parse a MOF document into a list of instance dicts."""
    lines = text.split("\n")
    instances = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if line.strip() == "":
            i += 1
            continue
        m = _INSTANCE_RE.match(line)
        if not m:
            raise MofError(f"line {i + 1}: expected 'instance of': {line!r}")
        class_name, alias = m.group(1), m.group(2)
        i += 1
        if i >= n or lines[i].strip() != "{":
            raise MofError(f"line {i + 1}: expected '{{' after instance header")
        i += 1
        properties = {}
        while i < n and lines[i].strip() != "};":
            pm = _PROPERTY_RE.match(lines[i])
            if not pm:
                raise MofError(f"line {i + 1}: malformed property: {lines[i]!r}")
            properties[pm.group(1)] = _parse_property_value(
                pm.group(1), pm.group(2)
            )
            i += 1
        if i >= n:
            raise MofError("unexpected end of file: missing '};'")
        i += 1  # consume '};'
        instances.append(
            {"class": class_name, "alias": alias, "properties": properties}
        )
    return {"instances": instances}


def _serialize_property_value(key, value):
    if isinstance(value, list):
        return "{" + ",".join('"' + _escape_mof_string(v) + '"' for v in value) + "}"
    if isinstance(value, dict):
        compact = _compact_json(value)
        if key in BASE64_JSON_FIELDS:
            compact = base64.b64encode(compact.encode("utf-8")).decode("ascii")
        return '"' + _escape_mof_string(compact) + '"'
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if value is None:
        return "null"
    return '"' + _escape_mof_string(str(value)) + '"'


def serialize_mof(document):
    """Render the JSON document model back into MOF text."""
    out = []
    for inst in document["instances"]:
        header = "instance of " + inst["class"]
        if inst.get("alias"):
            header += " as $" + inst["alias"]
        out.append(header + "\n{\n")
        for key, value in inst["properties"].items():
            out.append("    " + key + " = " + _serialize_property_value(key, value) + ";\n")
        out.append("};\n")
    return "".join(out)


def _read(path):
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _write(path, text):
    if path is None or path == "-":
        sys.stdout.write(text)
        return
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


# --------------------------------------------------------------------------- #
# Compaction: full MOF instance model  <->  compact rule document
# --------------------------------------------------------------------------- #

_RESOURCE_ID_RE = re.compile(r"^([0-9]+(?:\.[0-9]+)*)\s+(.*)$", re.DOTALL)


def _split_resource_id(resource_id):
    """Split ``"1.1.1 Ensure ..."`` into ``("1.1.1", "Ensure ...")``."""
    m = _RESOURCE_ID_RE.match(resource_id)
    if not m:
        return None, None
    return m.group(1), m.group(2)


def _pascal_case(text):
    return "".join(w.capitalize() for w in re.split(r"[^A-Za-z0-9]+", text) if w)


def _generate_fields(resource_id, payload_prefix):
    """Return the fields derivable from a ResourceID, or ``None`` if it does not
    follow the ``<number> <description>`` convention."""
    number, description = _split_resource_id(resource_id)
    if number is None:
        return None
    name = _pascal_case(description)
    generated = {
        "PayloadKey": payload_prefix + "/" + number.replace(".", "/"),
    }
    for field, prefix in GENERATED_NAME_FIELDS.items():
        generated[field] = prefix + name
    return generated


def _most_common(values):
    counts = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return max(counts, key=counts.get)


def _infer_payload_prefix(resources):
    candidates = []
    for inst in resources:
        props = inst["properties"]
        number, _ = _split_resource_id(props.get("ResourceID", ""))
        payload = props.get("PayloadKey")
        if number is None or not isinstance(payload, str):
            continue
        suffix = "/" + number.replace(".", "/")
        if payload.endswith(suffix):
            candidates.append(payload[: -len(suffix)])
    return _most_common(candidates) if candidates else ""


def compact_document(model):
    """Turn the verbose instance model into the compact rule document."""
    resources = [i for i in model["instances"] if i["class"] == RESOURCE_CLASS]
    config_docs = [
        i for i in model["instances"] if i["class"] == CONFIG_DOCUMENT_CLASS
    ]

    payload_prefix = _infer_payload_prefix(resources)

    rules = []
    for inst in resources:
        props = inst["properties"]
        generated = _generate_fields(props.get("ResourceID", ""), payload_prefix)
        rule = {
            "ResourceID": props.get("ResourceID"),
            "RuleId": props.get("RuleId"),
            "Procedure": props.get("ProcedureObjectValue"),
        }

        desired = props.get("DesiredObjectValue", "")
        if desired != "":
            rule["DesiredObjectValue"] = desired

        overrides = {}
        for field, value in props.items():
            if field in ("ResourceID", "RuleId", "ProcedureObjectValue",
                         "DesiredObjectValue"):
                continue
            if field in GENERATED_NAME_FIELDS or field == "PayloadKey":
                if generated is not None and generated.get(field) == value:
                    continue
            elif field in COMMON_VALUES and COMMON_VALUES[field] == value:
                continue
            overrides[field] = value
        if overrides:
            rule["overrides"] = overrides
        rules.append(rule)

    document = {
        "payloadKeyPrefix": payload_prefix,
        "configurationDocument": config_docs[0]["properties"] if config_docs else None,
        "rules": rules,
    }
    return document


def expand_document(document):
    """Rebuild the verbose instance model from the compact rule document."""
    payload_prefix = document.get("payloadKeyPrefix", "")
    instances = []

    for index, rule in enumerate(document.get("rules", [])):
        overrides = rule.get("overrides", {})
        resource_id = rule["ResourceID"]
        generated = _generate_fields(resource_id, payload_prefix) or {}

        def value_for(field):
            if field in overrides:
                return overrides[field]
            if field == "ResourceID":
                return resource_id
            if field == "RuleId":
                return rule["RuleId"]
            if field == "ProcedureObjectValue":
                return rule["Procedure"]
            if field == "DesiredObjectValue":
                return rule.get("DesiredObjectValue", "")
            if field == "PayloadKey" or field in GENERATED_NAME_FIELDS:
                return generated[field]
            if field in COMMON_VALUES:
                return COMMON_VALUES[field]
            raise MofError(f"cannot determine value for field {field!r}")

        properties = {f: value_for(f) for f in RESOURCE_FIELD_ORDER}
        instances.append(
            {
                "class": RESOURCE_CLASS,
                "alias": f"{RESOURCE_CLASS}{index}ref",
                "properties": properties,
            }
        )

    config_doc = document.get("configurationDocument")
    if config_doc is not None:
        instances.append(
            {
                "class": CONFIG_DOCUMENT_CLASS,
                "alias": None,
                "properties": config_doc,
            }
        )
    return {"instances": instances}


def cmd_to_json(args):
    document = compact_document(parse_mof(_read(args.input)))
    _write(args.output, json.dumps(document, indent=2, ensure_ascii=False) + "\n")
    return 0


def cmd_to_mof(args):
    document = expand_document(json.loads(_read(args.input)))
    _write(args.output, serialize_mof(document))
    return 0


def cmd_verify(args):
    original = _read(args.input)
    rebuilt = serialize_mof(expand_document(compact_document(parse_mof(original))))
    if rebuilt == original:
        print(f"OK: {args.input} round-trips identically")
        return 0
    print(f"FAIL: {args.input} does not round-trip", file=sys.stderr)
    orig_lines = original.split("\n")
    new_lines = rebuilt.split("\n")
    for idx, (a, b) in enumerate(zip(orig_lines, new_lines), start=1):
        if a != b:
            print(f"  first diff at line {idx}:", file=sys.stderr)
            print(f"    original: {a!r}", file=sys.stderr)
            print(f"    rebuilt:  {b!r}", file=sys.stderr)
            break
    else:
        if len(orig_lines) != len(new_lines):
            print(
                f"  line count differs: {len(orig_lines)} vs {len(new_lines)}",
                file=sys.stderr,
            )
    return 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        epilog=NOTICE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_json = sub.add_parser("to-json", help="convert a MOF document to JSON")
    p_json.add_argument("input", help="input .mof file ('-' for stdin)")
    p_json.add_argument("-o", "--output", help="output .json file ('-' for stdout)")
    p_json.set_defaults(func=cmd_to_json)

    p_mof = sub.add_parser("to-mof", help="convert a JSON document to MOF")
    p_mof.add_argument("input", help="input .json file ('-' for stdin)")
    p_mof.add_argument("-o", "--output", help="output .mof file ('-' for stdout)")
    p_mof.set_defaults(func=cmd_to_mof)

    p_verify = sub.add_parser(
        "verify", help="check that mof->json->mof reproduces the input exactly"
    )
    p_verify.add_argument("input", help="input .mof file ('-' for stdin)")
    p_verify.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except MofError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
