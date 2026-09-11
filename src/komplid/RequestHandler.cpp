// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "RequestHandler.hpp"

#include <RuleResult.hpp>
#include <utility>

namespace Komplid
{
using ComplianceEngine::BenchmarkDefinition::ParseFile;
using ComplianceEngine::BenchmarkIO::BuildRuleResultJson;
using ComplianceEngine::BenchmarkIO::Resource;
using ComplianceEngine::Status;
using std::string;

RequestHandler::RequestHandler(ComplianceEngine::Engine& engine, ComplianceEngine::DistributionInfo distributionInfo, string definitionsDir)
    : mEngine(engine),
      mDistributionInfo(std::move(distributionInfo)),
      mDefinitionsDir(std::move(definitionsDir))
{
}

RequestHandler::ResolveOutcome RequestHandler::ResolveBenchmark(const string& benchmark)
{
    const auto cachedIt = mCache.find(benchmark);
    if (mCache.end() != cachedIt)
    {
        return ResolveOutcome(&cachedIt->second, ErrorCode::InternalError, string());
    }

    // ParseFile applies the full input-hardening posture (path-traversal
    // rejection, root-owned non-writable parent directory, O_NOFOLLOW open,
    // regular-file/ownership/mode checks) - `benchmark` was already validated
    // by ParseRequest to be a bare name with no '/'.
    const string path = mDefinitionsDir + "/" + benchmark + ".benchmark.json";
    auto docResult = ParseFile(path, nullptr);
    if (!docResult.HasValue())
    {
        return ResolveOutcome(nullptr, ErrorCode::UnknownBenchmark, "failed to load benchmark '" + benchmark + "': " + docResult.Error().message);
    }

    const bool applicable = docResult.Value().benchmarkInfo.Match(mDistributionInfo);
    auto inserted = mCache.emplace(benchmark, CachedBenchmark(std::move(docResult.Value()), applicable));
    return ResolveOutcome(&inserted.first->second, ErrorCode::InternalError, string());
}

string RequestHandler::BuildError(const string& requestId, ErrorCode code, const string& message)
{
    auto responseResult = BuildErrorResponse(requestId, code, message);
    if (!responseResult.HasValue())
    {
        // Pathological (out-of-memory territory): fall back to a fixed
        // literal line rather than propagate, so the connection always gets
        // exactly one response line per request.
        return "{\"type\":\"error\",\"requestId\":\"\",\"code\":\"internal_error\",\"message\":\"failed to build response\"}";
    }
    return responseResult.Value();
}

string RequestHandler::Dispatch(const Request& request)
{
    if (RequestMode::Enforce == request.mode)
    {
        return BuildError(request.requestId, ErrorCode::UnsupportedMode, "mode 'enforce' is reserved and not implemented yet");
    }

    const auto resolved = ResolveBenchmark(request.benchmark);
    if (nullptr == resolved.benchmark)
    {
        return BuildError(request.requestId, resolved.errorCode, resolved.errorMessage);
    }
    const auto& cached = *resolved.benchmark;

    if (!cached.applicable)
    {
        return BuildError(
            request.requestId, ErrorCode::BenchmarkNotApplicable, "benchmark '" + request.benchmark + "' is not applicable to the current host");
    }

    const Resource* entry = nullptr;
    for (const auto& resource : cached.document.resources)
    {
        if (resource.id == request.id)
        {
            entry = &resource;
            break;
        }
    }
    if (nullptr == entry)
    {
        return BuildError(request.requestId, ErrorCode::UnknownRule, "benchmark '" + request.benchmark + "' has no rule with id '" + request.id + "'");
    }

    auto procedureResult = mEngine.MmiSet((string("procedure") + entry->ruleName).c_str(), entry->procedure);
    if (!procedureResult.HasValue())
    {
        return BuildError(request.requestId, ErrorCode::InternalError, "failed to set procedure: " + procedureResult.Error().message);
    }

    Status status;
    string indicators;
    if (RequestMode::Audit == request.mode)
    {
        if (entry->hasInitAudit)
        {
            const string initPayload = entry->payload.HasValue() ? entry->payload.Value() : string("{}");
            auto initResult = mEngine.MmiSet((string("init") + entry->ruleName).c_str(), initPayload);
            if (!initResult.HasValue())
            {
                return BuildError(request.requestId, ErrorCode::InternalError, "failed to init audit: " + initResult.Error().message);
            }
        }

        auto auditResult = mEngine.MmiGet((string("audit") + entry->ruleName).c_str());
        if (!auditResult.HasValue())
        {
            return BuildError(request.requestId, ErrorCode::InternalError, "failed to perform audit: " + auditResult.Error().message);
        }
        status = auditResult.Value().status;
        indicators = auditResult.Value().payload;
    }
    else // RequestMode::Remediate
    {
        const string remediatePayload = entry->payload.HasValue() ? entry->payload.Value() : string("{}");
        auto remediateResult = mEngine.MmiSet((string("remediate") + entry->ruleName).c_str(), remediatePayload);
        if (!remediateResult.HasValue())
        {
            return BuildError(request.requestId, ErrorCode::InternalError, "failed to remediate: " + remediateResult.Error().message);
        }
        status = remediateResult.Value();
        indicators = "[]";
    }

    auto ruleJsonResult = BuildRuleResultJson(*entry, status, indicators, mEngine.GetParameters(entry->ruleName));
    if (!ruleJsonResult.HasValue())
    {
        return BuildError(request.requestId, ErrorCode::InternalError, "failed to build result: " + ruleJsonResult.Error().message);
    }

    auto responseResult = BuildResultResponse(request.requestId, std::move(ruleJsonResult.Value()));
    if (!responseResult.HasValue())
    {
        return BuildError(request.requestId, ErrorCode::InternalError, "failed to build response: " + responseResult.Error().message);
    }
    return responseResult.Value();
}

string RequestHandler::HandleLine(const string& line)
{
    const string requestId = ExtractRequestId(line);
    auto parseResult = ParseRequest(line);
    if (!parseResult.HasValue())
    {
        return BuildError(requestId, ErrorCode::InvalidRequest, parseResult.Error().message);
    }
    return Dispatch(parseResult.Value());
}

} // namespace Komplid
