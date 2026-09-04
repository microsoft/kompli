// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <AksCommand.h>
#include <Regex.h>
#include <sstream>

namespace ComplianceEngine
{
namespace
{
bool IsAzureIdentifier(const std::string& value)
{
    static const regex identifier("[A-Za-z0-9][A-Za-z0-9_.-]{0,89}");
    return regex_match(value, identifier);
}

bool IsNodeName(const std::string& value)
{
    static const regex nodeName("[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?");
    return regex_match(value, nodeName);
}

Result<std::string> AzureCommand(const AksCommandParams& params, const std::string& query)
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
            return AzureCommand(params, "{fullCluster: @}");
        case AksCommandOperation::ControlPlaneEndpoint:
        case AksCommandOperation::PublicPrivateEndpointAccess:
            return AzureCommand(params,
                "{enablePrivateCluster:apiServerAccessProfile.enablePrivateCluster, enablePublicFqdn:apiServerAccessProfile.enablePublicFqdn, "
                "authorizedIpRanges:apiServerAccessProfile.authorizedIpRanges}");
        case AksCommandOperation::NetworkPolicy:
            return AzureCommand(params, "networkProfile.networkPolicy");
        case AksCommandOperation::GeneralPolicies:
            return std::string("kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}{\"\\n\"}{end}' | sort -u");
        case AksCommandOperation::PodSecurityStandards:
            return std::string(
                "kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.metadata.namespace | "
                "IN(\"kube-system\",\"gatekeeper-system\",\"azure-arc\",\"azure-extensions-usage-system\") | not) | "
                ".metadata.namespace as $ns | .metadata.name as $pod | (.spec.hostNetwork // false) as $hn | "
                "(.spec.hostIPC // false) as $hi | (.spec.hostPID // false) as $hp | if ($hn or $hi or $hp) then "
                "[$ns,$pod,\"-\",\"hostNetwork=\\($hn)\",\"hostIPC=\\($hi)\",\"hostPID=\\($hp)\",\"privileged=false\","
                "\"allowPrivilegeEscalation=false\"] | @tsv else empty end, (.spec.containers[]? | .securityContext as $sc | "
                "select(($sc.privileged // false) or ($sc.allowPrivilegeEscalation // false)) | "
                "[$ns,$pod,.name,\"hostNetwork=\\($hn)\",\"hostIPC=\\($hi)\",\"hostPID=\\($hp)\","
                "\"privileged=\\($sc.privileged // false)\",\"allowPrivilegeEscalation=\\($sc.allowPrivilegeEscalation // false)\"] | @tsv)'");
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

    const bool matched = OutputMatches(output.Value(), outputPattern);
    const bool compliant = matched == params.matchMeansCompliant.ValueOr(true);
    return compliant ? indicators.Compliant("AKS query output matched the expected state") :
                       indicators.NonCompliant("AKS query output did not match the expected state");
}
} // namespace ComplianceEngine
