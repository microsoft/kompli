// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "RequestHandler.hpp"

#include "BackgroundWorker.hpp"

#include <FileLock.hpp>
#include <RuleResult.hpp>
#include <utility>

namespace Komplid
{
using ComplianceEngine::Action;
using ComplianceEngine::BenchmarkDefinition::ParseFile;
using ComplianceEngine::BenchmarkIO::BuildRuleResultJson;
using ComplianceEngine::BenchmarkIO::Resource;
using ComplianceEngine::FileLock;
using ComplianceEngine::JsonWrapper;
using ComplianceEngine::Optional;
using ComplianceEngine::Status;
using std::string;

namespace
{
RequestHandler::DispatchOutcome MakeFailure(ErrorCode code, string message)
{
    RequestHandler::DispatchOutcome outcome;
    outcome.errorCode = code;
    outcome.errorMessage = std::move(message);
    return outcome;
}

RequestHandler::DispatchOutcome MakeSuccess(JsonWrapper result)
{
    RequestHandler::DispatchOutcome outcome;
    outcome.result = Optional<JsonWrapper>(std::move(result));
    return outcome;
}

const char* ModeToString(RequestMode mode)
{
    return (RequestMode::Audit == mode) ? "audit" : "remediate";
}
} // namespace

RequestHandler::RequestHandler(ComplianceEngine::Engine& engine, ComplianceEngine::DistributionInfo distributionInfo, string definitionsDir,
    KompliConfig config, TaskRegistry* registry, string registryPath, string remediationLockPath)
    : mEngine(engine),
      mDistributionInfo(std::move(distributionInfo)),
      mDefinitionsDir(std::move(definitionsDir)),
      mConfig(std::move(config)),
      mRegistry(registry),
      mRegistryPath(std::move(registryPath)),
      mRemediationLockPath(std::move(remediationLockPath))
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

RequestHandler::DispatchOutcome RequestHandler::DispatchCore(const Request& request)
{
    if (RequestMode::Enforce == request.mode)
    {
        return MakeFailure(ErrorCode::UnsupportedMode, "mode 'enforce' is reserved and not implemented yet");
    }

    const auto resolved = ResolveBenchmark(request.benchmark);
    if (nullptr == resolved.benchmark)
    {
        return MakeFailure(resolved.errorCode, resolved.errorMessage);
    }
    const auto& cached = *resolved.benchmark;

    if (!cached.applicable)
    {
        return MakeFailure(ErrorCode::BenchmarkNotApplicable, "benchmark '" + request.benchmark + "' is not applicable to the current host");
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
        return MakeFailure(ErrorCode::UnknownRule, "benchmark '" + request.benchmark + "' has no rule with id '" + request.id + "'");
    }

    auto procedureResult = mEngine.MmiSet((string("procedure") + entry->ruleName).c_str(), entry->procedure);
    if (!procedureResult.HasValue())
    {
        return MakeFailure(ErrorCode::InternalError, "failed to set procedure: " + procedureResult.Error().message);
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
                return MakeFailure(ErrorCode::InternalError, "failed to init audit: " + initResult.Error().message);
            }
        }

        auto auditResult = mEngine.MmiGet((string("audit") + entry->ruleName).c_str());
        if (!auditResult.HasValue())
        {
            return MakeFailure(ErrorCode::InternalError, "failed to perform audit: " + auditResult.Error().message);
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
            return MakeFailure(ErrorCode::InternalError, "failed to remediate: " + remediateResult.Error().message);
        }
        status = remediateResult.Value();
        indicators = "[]";
    }

    auto ruleJsonResult = BuildRuleResultJson(*entry, status, indicators, mEngine.GetParameters(entry->ruleName),
        (RequestMode::Audit == request.mode) ? ComplianceEngine::Action::Audit : ComplianceEngine::Action::Remediate);
    if (!ruleJsonResult.HasValue())
    {
        return MakeFailure(ErrorCode::InternalError, "failed to build result: " + ruleJsonResult.Error().message);
    }

    return MakeSuccess(std::move(ruleJsonResult.Value()));
}

string RequestHandler::BuildResponseFromOutcome(const string& requestId, DispatchOutcome outcome)
{
    if (outcome.result.HasValue())
    {
        auto responseResult = BuildResultResponse(requestId, std::move(outcome.result.Value()));
        if (!responseResult.HasValue())
        {
            return BuildError(requestId, ErrorCode::InternalError, "failed to build response: " + responseResult.Error().message);
        }
        return responseResult.Value();
    }
    return BuildError(requestId, outcome.errorCode, outcome.errorMessage);
}

string RequestHandler::DispatchSynchronously(const Request& request)
{
    // Serialize remediation across every komplid process (Accept=yes means
    // each connection - and each background task - is its own process); see
    // README.md "Remediation locking still applies". Non-blocking here: a
    // synchronous caller is waiting on this response (BackgroundWorker
    // acquires the same lock file, blockingly, before calling DispatchCore
    // in its own forked child instead - never both in the same process).
    Optional<FileLock> remediationLock;
    if (RequestMode::Remediate == request.mode && !mRemediationLockPath.empty())
    {
        auto lockResult = FileLock::Make(mRemediationLockPath, /*blocking=*/false);
        if (!lockResult.HasValue())
        {
            return BuildError(request.requestId, ErrorCode::RemediationInProgress, "another remediation is already in progress");
        }
        remediationLock = Optional<FileLock>(std::move(lockResult.Value()));
    }

    auto outcome = DispatchCore(request);
    UpdateCacheAfterDispatch(request, outcome);
    return BuildResponseFromOutcome(request.requestId, std::move(outcome));
}

Optional<string> RequestHandler::TryServeCachedAudit(const Request& request)
{
    if (nullptr == mRegistry || RequestMode::Audit != request.mode || request.forceRefresh || mConfig.auditCacheTtlSeconds <= 0)
    {
        return Optional<string>();
    }

    const string parametersKey = SerializeParametersKey(request.parameters);
    auto cachedResult = mRegistry->GetCachedAudit(request.benchmark, request.id, parametersKey, mConfig.auditCacheTtlSeconds);
    if (!cachedResult.HasValue() || !cachedResult.Value().HasValue())
    {
        return Optional<string>();
    }

    auto jsonResult = JsonWrapper::FromString(cachedResult.Value().Value());
    if (!jsonResult.HasValue())
    {
        // Somehow-corrupt cache entry: treat as a miss rather than fail the
        // request over a caching problem.
        return Optional<string>();
    }
    auto responseResult = BuildResultResponse(request.requestId, std::move(jsonResult.Value()));
    if (!responseResult.HasValue())
    {
        return Optional<string>();
    }
    return Optional<string>(responseResult.Value());
}

Optional<string> RequestHandler::TryDispatchInBackground(const Request& request)
{
    if (nullptr == mRegistry || RequestMode::Enforce == request.mode || 0 == mConfig.backgroundTaskRules.count(request.id))
    {
        return Optional<string>();
    }

    const string modeStr = ModeToString(request.mode);
    const string parametersKey = SerializeParametersKey(request.parameters);

    // Attach to an in-flight task for the exact same (benchmark, id, mode,
    // parameters) rather than starting a redundant duplicate - see README.md
    // "Duplicate concurrent requests".
    auto inFlightResult = mRegistry->FindInFlightTask(request.benchmark, request.id, modeStr, parametersKey);
    if (inFlightResult.HasValue() && inFlightResult.Value().HasValue())
    {
        auto responseResult = BuildTaskResponse(request.requestId, inFlightResult.Value().Value());
        return responseResult.HasValue() ? Optional<string>(responseResult.Value()) : Optional<string>();
    }

    auto taskIdResult = mRegistry->CreateTask(request.benchmark, request.id, modeStr, parametersKey);
    if (!taskIdResult.HasValue())
    {
        // Couldn't even create the task row (registry trouble) - fall back
        // to running it synchronously rather than failing the request.
        return Optional<string>();
    }
    const string taskId = taskIdResult.Value();

    const pid_t pid = SpawnBackgroundTask(*this, mRegistryPath, taskId, request, mRemediationLockPath);
    if (pid > 0)
    {
        SpawnedTask spawned;
        spawned.pid = pid;
        spawned.taskId = taskId;
        spawned.requestId = request.requestId;
        mLastSpawned = Optional<SpawnedTask>(spawned);
    }
    // pid <= 0 (fork failed): the task row is left Running - rare (fork()
    // failing), and not yet handled beyond what CleanupOldTasks eventually
    // does (see README.md "Not yet decided": task expiry/cleanup policy).

    auto responseResult = BuildTaskResponse(request.requestId, taskId);
    return responseResult.HasValue() ? Optional<string>(responseResult.Value()) : Optional<string>();
}

void RequestHandler::UpdateCacheAfterDispatch(const Request& request, const DispatchOutcome& outcome)
{
    if (nullptr == mRegistry || !outcome.result.HasValue())
    {
        return;
    }

    if (RequestMode::Audit == request.mode && mConfig.auditCacheTtlSeconds > 0)
    {
        auto serializedResult = SerializeJson(outcome.result.Value());
        if (serializedResult.HasValue())
        {
            const string parametersKey = SerializeParametersKey(request.parameters);
            mRegistry->UpsertCachedAudit(request.benchmark, request.id, parametersKey, serializedResult.Value());
        }
    }
    else if (RequestMode::Remediate == request.mode)
    {
        // A successful remediate can affect any parameterization of this
        // rule's audit result - see README.md "Invalidation on remediation".
        mRegistry->InvalidateCachedAudits(request.benchmark, request.id);
    }
}

string RequestHandler::HandleTaskQuery(const string& line)
{
    auto parseResult = ParseTaskQuery(line);
    if (!parseResult.HasValue())
    {
        return BuildError(string(), ErrorCode::InvalidRequest, parseResult.Error().message);
    }
    const auto& query = parseResult.Value();

    if (nullptr == mRegistry)
    {
        return BuildError(query.requestId, ErrorCode::UnknownTask, "no task registry configured");
    }

    auto taskResult = mRegistry->GetTask(query.taskId);
    if (!taskResult.HasValue())
    {
        return BuildError(query.requestId, ErrorCode::InternalError, "failed to query task: " + taskResult.Error().message);
    }
    if (!taskResult.Value().HasValue())
    {
        return BuildError(query.requestId, ErrorCode::UnknownTask, "no such task '" + query.taskId + "'");
    }

    const auto& record = taskResult.Value().Value();
    if (TaskStatus::Done == record.status)
    {
        auto jsonResult = JsonWrapper::FromString(record.resultJson);
        if (!jsonResult.HasValue())
        {
            return BuildError(query.requestId, ErrorCode::InternalError, "task result is corrupt");
        }
        auto responseResult = BuildTaskResultResponse(query.requestId, query.taskId, std::move(jsonResult.Value()));
        if (!responseResult.HasValue())
        {
            return BuildError(query.requestId, ErrorCode::InternalError, "failed to build taskResult response");
        }
        return responseResult.Value();
    }
    if (TaskStatus::Failed == record.status)
    {
        return BuildError(query.requestId, ErrorCode::InternalError, record.errorMessage);
    }

    auto responseResult = BuildTaskStatusResponse(query.requestId, query.taskId, "running");
    if (!responseResult.HasValue())
    {
        return BuildError(query.requestId, ErrorCode::InternalError, "failed to build taskStatus response");
    }
    return responseResult.Value();
}

string RequestHandler::HandleLine(const string& line)
{
    if (IsTaskQuery(line))
    {
        return HandleTaskQuery(line);
    }

    const string requestId = ExtractRequestId(line);
    auto parseResult = ParseRequest(line);
    if (!parseResult.HasValue())
    {
        return BuildError(requestId, ErrorCode::InvalidRequest, parseResult.Error().message);
    }
    const Request& request = parseResult.Value();

    auto cached = TryServeCachedAudit(request);
    if (cached.HasValue())
    {
        return cached.Value();
    }

    auto backgrounded = TryDispatchInBackground(request);
    if (backgrounded.HasValue())
    {
        return backgrounded.Value();
    }

    return DispatchSynchronously(request);
}

Optional<RequestHandler::SpawnedTask> RequestHandler::TakeLastSpawnedTask()
{
    Optional<SpawnedTask> result = std::move(mLastSpawned);
    mLastSpawned = Optional<SpawnedTask>();
    return result;
}

} // namespace Komplid
