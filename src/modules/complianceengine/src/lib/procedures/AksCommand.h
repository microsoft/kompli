// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_PROCEDURES_AKS_COMMAND_H
#define COMPLIANCEENGINE_PROCEDURES_AKS_COMMAND_H

#include <Evaluator.h>

namespace ComplianceEngine
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
};

struct AksCommandParams
{
    AksCommandOperation operation;
    Optional<std::string> clusterName;
    Optional<std::string> resourceGroup;
    Optional<std::string> nodeName;
    std::string pattern;
    Optional<bool> matchMeansCompliant = true;
};

Result<Status> AuditAksCommand(const AksCommandParams& params, IndicatorsTree& indicators, ContextInterface& context);
} // namespace ComplianceEngine
#endif // COMPLIANCEENGINE_PROCEDURES_AKS_COMMAND_H
