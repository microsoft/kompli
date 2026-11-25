// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_AKS_COMMAND_H
#define KOMPLI_PROCEDURES_AKS_COMMAND_H

#include <Evaluator.h>

namespace Kompli
{
enum class AksCommandOperation
{
    CniPlugin,
    ControlPlaneEndpoint,
    PublicPrivateEndpointAccess,
    NetworkPolicy,
    GeneralPolicies,
    PodSecurityStandards,
    Kubelet,
    ServiceAccount,
    Pod,
    SecretsEnvironmentVariables,
    PrivateNodes,
};

struct AksCommandParams
{
    AksCommandOperation operation;
    Optional<std::string> clusterName;
    Optional<std::string> resourceGroup;
    Optional<std::string> nodeName;
    Optional<std::string> namespaceName;
    Optional<std::string> serviceAccountName;
    Optional<std::string> podName;
    std::string pattern;
    Optional<bool> matchMeansCompliant = true;
};

Result<Status> AuditAksCommand(const AksCommandParams& params, IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // KOMPLI_PROCEDURES_AKS_COMMAND_H
