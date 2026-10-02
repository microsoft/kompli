#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

"""TM-17: Parse the CLI's JUnit output for a canonical result with Python's XML parser."""

import json
import subprocess
import sys
import xml.etree.ElementTree as ET


result = {
    "timestamp": "2026-10-01T00:00:00Z",
    "host": {"arch": "x86_64", "distribution": "ubuntu", "distributionVersion": "22.04"},
    "durationMs": 1,
    "status": "NonCompliant",
    "rules": [
        {
            "id": "1.1",
            "ruleId": "rule-1",
            "title": "Pass & verify",
            "ruleName": "PassRule",
            "status": "Compliant",
            "tags": ["level:l1", "owner:Ops & Sec"],
            "metadata": {},
            "parameters": {},
            "indicators": [],
        },
        {
            "id": "1.2",
            "ruleId": "rule-2",
            "title": "Fail",
            "ruleName": "FailRule",
            "status": "NonCompliant",
            "tags": ["severity:critical"],
            "metadata": {},
            "parameters": {},
            "indicators": [{"message": "Failure <detail>", "status": "NonCompliant"}],
        },
        {
            "id": "1.3",
            "ruleId": "rule-3",
            "title": "Skipped",
            "ruleName": "SkipRule",
            "status": "Skipped",
            "tags": [],
            "metadata": {},
            "parameters": {},
            "indicators": [],
        },
    ],
}

completed = subprocess.run(
    [sys.argv[1], "-f", "junit", "render"],
    input=json.dumps(result),
    text=True,
    capture_output=True,
    check=True,
)
root = ET.fromstring(completed.stdout)
suite = root.find("testsuite")
if suite is None or suite.attrib["tests"] != "3" or suite.attrib["failures"] != "1" or suite.attrib["skipped"] != "1":
    raise AssertionError("Unexpected JUnit suite counts")
cases = suite.findall("testcase")
if len(cases) != 3 or cases[0].attrib["name"] != "Pass & verify":
    raise AssertionError("Testcase names were not preserved")
if [tag.attrib["value"] for tag in cases[0].findall("tags/tag")] != ["level:l1", "owner:Ops & Sec"]:
    raise AssertionError("Tags were not preserved")
if cases[1].find("failure") is None or cases[2].find("skipped") is None:
    raise AssertionError("Failure or skipped status was not preserved")
