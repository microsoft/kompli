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
    "action": "Audit",
    "host": {"arch": "x86_64", "distribution": "ubuntu", "distributionVersion": "22.04"},
    "durationMs": 1,
    "status": "NonCompliant",
    "rules": [
        {
            "id": "1.1\tid",
            "ruleId": "rule-1",
            "title": "Pass\tand\nverify\ragain",
            "ruleName": "PassRule",
            "status": "Compliant",
            "action": "Audit",
            "tags": ["level:l1", "owner:Ops\t&\nSec\rteam"],
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
            "action": "Audit",
            "tags": ["severity:critical"],
            "metadata": {},
            "parameters": {},
            "indicators": [{"message": "Failure <detail>", "status": "NonCompliant"}],
        },
    ],
}

suite_name = "Suite\twith\nlines\rtoo"
completed = subprocess.run(
    [sys.argv[1], "-f", "junit", "--suite-name", suite_name, "render"],
    input=json.dumps(result),
    universal_newlines=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    check=True,
)
root = ET.fromstring(completed.stdout)
suite = root.find("testsuite")
if suite is None or suite.attrib["tests"] != "2" or suite.attrib["failures"] != "1" or suite.attrib["skipped"] != "0":
    raise AssertionError("Unexpected JUnit suite counts")
if suite.attrib["name"] != suite_name:
    raise AssertionError("Suite name whitespace was not preserved")
cases = suite.findall("testcase")
if len(cases) != 2 or cases[0].attrib["name"] != "Pass\tand\nverify\ragain" or cases[0].attrib["classname"] != "1.1\tid":
    raise AssertionError("Testcase attributes were not preserved")
if [tag.attrib["value"] for tag in cases[0].findall("tags/tag")] != ["level:l1", "owner:Ops\t&\nSec\rteam"]:
    raise AssertionError("Tag whitespace was not preserved")
if cases[1].find("failure") is None:
    raise AssertionError("Failure status was not preserved")

skipped_rule = dict(result["rules"][0])
skipped_rule.pop("action")
skipped_rule.update({"id": "1.3", "title": "Skipped", "status": "Skipped", "tags": [], "indicators": []})
skipped_result = {**result, "status": "NotApplicable", "rules": [skipped_rule]}
skipped_output = subprocess.run(
    [sys.argv[1], "-f", "junit", "--suite-name", suite_name, "render"],
    input=json.dumps(skipped_result),
    universal_newlines=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    check=True,
)
skipped_suite = ET.fromstring(skipped_output.stdout).find("testsuite")
if skipped_suite is None or skipped_suite.attrib["tests"] != "1" or skipped_suite.attrib["skipped"] != "1":
    raise AssertionError("Forward-compatible Skipped suite counts were not preserved")
skipped_case = skipped_suite.find("testcase")
if skipped_case is None or skipped_case.find("skipped") is None:
    raise AssertionError("Forward-compatible Skipped status was not preserved")
