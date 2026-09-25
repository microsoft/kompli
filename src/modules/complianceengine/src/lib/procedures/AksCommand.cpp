// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <AksCommand.h>
#include <JsonWrapper.h>
#include <Regex.h>
#include <sstream>

namespace ComplianceEngine
{
namespace
{
constexpr size_t MaxPatternLength = 1024;

bool IsAzureIdentifier(const std::string& value)
{
    static const regex identifier("[A-Za-z0-9][A-Za-z0-9_.-]{0,89}");
    return regex_match(value, identifier);
}

bool IsNodeName(const std::string& value)
{
    static const regex label("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?");
    if (value.empty() || value.size() > 253)
    {
        return false;
    }

    std::istringstream labels(value);
    std::string current;
    while (std::getline(labels, current, '.'))
    {
        if (!regex_match(current, label))
        {
            return false;
        }
    }
    return value.back() != '.';
}

Result<std::string> AzCommand(const AksCommandParams& params, const std::string& query)
{
    if (!params.clusterName.HasValue() || !params.resourceGroup.HasValue())
    {
        return Error("clusterName and resourceGroup are required for this operation", EINVAL);
    }
    if (!IsAzureIdentifier(params.clusterName.Value()) || !IsAzureIdentifier(params.resourceGroup.Value()))
    {
        return Error("clusterName or resourceGroup contains unsupported characters", EINVAL);
    }

    return "az aks show --resource-group " + params.resourceGroup.Value() + " --name " + params.clusterName.Value() + " --output json --query '" +
           query + "'";
}

Result<std::string> BuildCommand(const AksCommandParams& params)
{
    switch (params.operation)
    {
        case AksCommandOperation::CniPlugin:
            return AzCommand(params,
                "{networkPlugin:networkProfile.networkPlugin, networkPluginMode:networkProfile.networkPluginMode, "
                "networkDataplane:networkProfile.networkDataplane}");
        case AksCommandOperation::ControlPlaneEndpoint:
        case AksCommandOperation::PublicPrivateEndpointAccess:
            return AzCommand(params,
                "{enablePrivateCluster:apiServerAccessProfile.enablePrivateCluster, enablePublicFqdn:apiServerAccessProfile.enablePublicFqdn, "
                "authorizedIpRanges:apiServerAccessProfile.authorizedIpRanges}");
        case AksCommandOperation::NetworkPolicy:
            return AzCommand(params, "networkProfile.networkPolicy");
        case AksCommandOperation::GeneralPolicies:
            return std::string("kubectl get namespaces -o jsonpath='{range .items[*]}{.metadata.name}{\"\\n\"}{end}'");
        case AksCommandOperation::PodSecurityStandards:
            return std::string("kubectl get pods --all-namespaces -o json");
        case AksCommandOperation::Kubelet:
            if (!params.nodeName.HasValue())
            {
                return Error("nodeName is required for the kubelet operation", EINVAL);
            }
            if (!IsNodeName(params.nodeName.Value()))
            {
                return Error("nodeName contains unsupported characters", EINVAL);
            }
            return "kubectl get --raw '/api/v1/nodes/" + params.nodeName.Value() + "/proxy/configz'";
    }
    return Error("Unsupported AKS command operation", EINVAL);
}

bool IsExcludedNamespace(const std::string& namespaceName)
{
    return namespaceName == "kube-system" || namespaceName == "gatekeeper-system" || namespaceName == "azure-arc" ||
           namespaceName == "azure-extensions-usage-system";
}

Result<bool> GetOptionalBoolean(const JSON_Object* object, const char* path)
{
    if (!json_object_dothas_value(object, path))
    {
        return false;
    }
    if (!json_object_dothas_value_of_type(object, path, JSONBoolean))
    {
        return Error(std::string("AKS response field is not a boolean: ") + path, EINVAL);
    }
    return json_object_dotget_boolean(object, path) == 1;
}

struct PodParams
{
    std::string namespaceName;
    std::string podName;
    std::string containerName;
    bool hostNetwork;
    bool hostIPC;
    bool hostPID;
    bool privileged;
    bool allowPrivilegeEscalation;
};

void AppendPodSecurityFinding(std::ostringstream& findings, const struct PodParams& podParams)
{
    findings << podParams.namespaceName << '\t' << podParams.podName << '\t' << podParams.containerName << "\thostNetwork=" << std::boolalpha
             << podParams.hostNetwork << "\thostIPC=" << podParams.hostIPC << "\thostPID=" << podParams.hostPID
             << "\tprivileged=" << podParams.privileged << "\tallowPrivilegeEscalation=" << podParams.allowPrivilegeEscalation << '\n';
}

Result<std::string> FilterPodSecurityOutput(const std::string& output)
{
    auto document = JsonWrapper::FromString(output);
    if (!document.HasValue())
    {
        return Error("Failed to parse kubectl pod response", EINVAL);
    }

    const auto* root = json_value_get_object(document.Value().get());
    const auto* items = (root == nullptr) ? nullptr : json_object_get_array(root, "items");
    if (items == nullptr)
    {
        return Error("kubectl pod response does not contain an items array", EINVAL);
    }

    std::ostringstream findings;
    for (size_t itemIndex = 0; itemIndex < json_array_get_count(items); ++itemIndex)
    {
        const auto* pod = json_array_get_object(items, itemIndex);
        const char* namespaceValue = (pod == nullptr) ? nullptr : json_object_dotget_string(pod, "metadata.namespace");
        const char* podValue = pod == nullptr ? nullptr : json_object_dotget_string(pod, "metadata.name");
        if (namespaceValue == nullptr || podValue == nullptr)
        {
            return Error("kubectl pod response contains invalid metadata", EINVAL);
        }

        const std::string namespaceName(namespaceValue);
        if (IsExcludedNamespace(namespaceName))
        {
            continue;
        }

        auto hostNetwork = GetOptionalBoolean(pod, "spec.hostNetwork");
        auto hostIPC = GetOptionalBoolean(pod, "spec.hostIPC");
        auto hostPID = GetOptionalBoolean(pod, "spec.hostPID");
        if (!hostNetwork.HasValue() || !hostIPC.HasValue() || !hostPID.HasValue())
        {
            return Error("kubectl pod response contains an invalid host namespace setting", EINVAL);
        }

        const std::string podName(podValue);
        if (hostNetwork.Value() || hostIPC.Value() || hostPID.Value())
        {
            PodParams podParams;
            podParams.namespaceName = namespaceName;
            podParams.podName = podName;
            podParams.containerName = "-";
            podParams.hostNetwork = hostNetwork.Value();
            podParams.hostIPC = hostIPC.Value();
            podParams.hostPID = hostPID.Value();
            podParams.privileged = false;
            podParams.allowPrivilegeEscalation = false;
            AppendPodSecurityFinding(findings, podParams);
        }

        const auto* containers = json_object_dotget_array(pod, "spec.containers");
        if (containers == nullptr)
        {
            return Error("kubectl pod response contains invalid containers", EINVAL);
        }
        for (size_t containerIndex = 0; containerIndex < json_array_get_count(containers); ++containerIndex)
        {
            const auto* container = json_array_get_object(containers, containerIndex);
            const char* containerValue = container == nullptr ? nullptr : json_object_get_string(container, "name");
            if (containerValue == nullptr)
            {
                return Error("kubectl pod response contains invalid container metadata", EINVAL);
            }

            auto privileged = GetOptionalBoolean(container, "securityContext.privileged");
            auto allowPrivilegeEscalation = GetOptionalBoolean(container, "securityContext.allowPrivilegeEscalation");
            if (!privileged.HasValue() || !allowPrivilegeEscalation.HasValue())
            {
                return Error("kubectl pod response contains an invalid container security setting", EINVAL);
            }
            if (privileged.Value() || allowPrivilegeEscalation.Value())
            {
                PodParams podParams;
                podParams.namespaceName = namespaceName;
                podParams.podName = podName;
                podParams.containerName = containerValue;
                podParams.hostNetwork = hostNetwork.Value();
                podParams.hostIPC = hostIPC.Value();
                podParams.hostPID = hostPID.Value();
                podParams.privileged = privileged.Value();
                podParams.allowPrivilegeEscalation = allowPrivilegeEscalation.Value();
                AppendPodSecurityFinding(findings, podParams);
            }
        }
    }
    return findings.str();
}

bool OutputMatches(const std::string& output, const regex& pattern)
{
    std::istringstream lines(output);
    std::string line;
    while (std::getline(lines, line))
    {
        if (regex_search(line, pattern))
        {
            return true;
        }
    }
    return false;
}
} // namespace

Result<Status> AuditAksCommand(const AksCommandParams& params, IndicatorsTree& indicators, ContextInterface& context)
{
    if (params.pattern.size() > MaxPatternLength)
    {
        return Error("Output pattern is too long", EINVAL);
    }

    auto command = BuildCommand(params);
    if (!command.HasValue())
    {
        return command.Error();
    }

    regex outputPattern;
    try
    {
        outputPattern = regex(params.pattern, std::regex_constants::extended);
    }
    catch (const regex_error& error)
    {
        return Error("Invalid output pattern: " + std::string(error.what()), EINVAL);
    }

    auto output = context.ExecuteCommand(command.Value());
    if (!output.HasValue())
    {
        return indicators.NonCompliant(output.Error().message);
    }

    std::string matchingOutput = output.Value();
    if (params.operation == AksCommandOperation::PodSecurityStandards)
    {
        auto filteredOutput = FilterPodSecurityOutput(matchingOutput);
        if (!filteredOutput.HasValue())
        {
            return indicators.NonCompliant(filteredOutput.Error().message);
        }
        matchingOutput = filteredOutput.Value();
    }

    const bool matched = OutputMatches(matchingOutput, outputPattern);
    const bool compliant = matched == params.matchMeansCompliant.ValueOr(true);
    return compliant ? indicators.Compliant("AKS query output matched the expected state") :
                       indicators.NonCompliant("AKS query output did not match the expected state");
}
} // namespace ComplianceEngine
