// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef COMPLIANCE_ENGINE_CLI_JUNIT_RENDERER_HPP
#define COMPLIANCE_ENGINE_CLI_JUNIT_RENDERER_HPP

#include <Result.h>
#include <string>

namespace ComplianceEngine
{
namespace Kompli
{
// Renders a canonical kompli result JSON (as emitted by `audit` / `remediate`)
// into a JUnit XML document.
//
// - one <testcase classname=<id> name=<title>> per rule (`ruleName`, the
//   PascalCase engine name, moves into the failure/skipped body instead),
// - a <failure> only for NonCompliant rules (Compliant rules are bare
//   passing <testcase/>, unless they carry `tags` - see below),
// - `NotApplicable`/`Skipped` rules render as <skipped>,
// - a <tags> block (one <tag value=.../> per entry) mirrors the rule's
//   `tags` array verbatim when non-empty; severity already travels as a
//   `severity:<value>` tag, so no separate metadata-derived property is
//   rendered,
// - the failure/skipped body carries the rule's `ruleName`, Parameters, and
//   Indicators, modelled on the augmentation engine's
//   tests/reporting/junit.py.
//
// `id` is used verbatim as the classname; it is framework-agnostic (a
// dotted CIS number or a STIG id), so the renderer makes no CIS-specific
// assumptions. `suiteName` names the <testsuite>; the CLI does not know
// which benchmark package it came from, so the caller supplies it.
Result<std::string> RenderJUnit(const std::string& canonicalJson, const std::string& suiteName);

} // namespace Kompli
} // namespace ComplianceEngine

#endif // COMPLIANCE_ENGINE_CLI_JUNIT_RENDERER_HPP
