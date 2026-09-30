// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef COMPLIANCE_ENGINE_CLI_TEXT_RENDERERS_HPP
#define COMPLIANCE_ENGINE_CLI_TEXT_RENDERERS_HPP

#include <Result.h>
#include <string>

namespace ComplianceEngine
{
namespace Kompli
{
// Human-readable text presentations produced by the `render` subcommand from a
// canonical result JSON (emitted by `audit` / `remediate`).
enum class TextStyle
{
    // Per-rule header line plus an indented indicator tree.
    NestedList,
    // One line per rule: status + id + name (no indicators).
    CompactList,
    // Verbose: identity, title, parameters, and the full indicator tree.
    Debug
};

Result<std::string> RenderText(const std::string& canonicalJson, TextStyle style);

} // namespace Kompli
} // namespace ComplianceEngine

#endif // COMPLIANCE_ENGINE_CLI_TEXT_RENDERERS_HPP
