// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_PASSWORD_CREDIT_UNION_EVIDENCE_H
#define COMPLIANCEENGINE_PASSWORD_CREDIT_UNION_EVIDENCE_H

#include <MmiResults.h>
#include <Optional.h>
#include <Result.h>
#include <functional>
#include <string>
#include <vector>

namespace ComplianceEngine
{
struct PasswordCreditItem
{
    std::string identity;
    Optional<long long> value; // Missing typed value is a selected, failing capture.
};

struct PasswordCreditRoot
{
    enum class Outcome
    {
        Complete,
        Absent,
        Stopped,
    };

    Outcome outcome;
    std::vector<PasswordCreditItem> selected;
    std::vector<std::string> exclusions;
    std::string stopReason;
};

struct PasswordCreditAssessment
{
    Result<PasswordCreditRoot> result;
    // The producer charges retained identities to its collection budget.
    std::vector<std::string> observed;
};

enum class CreditRootLocation
{
    Main,
    DropIn,
};

enum class CreditEvidenceKind
{
    Selected,
    Excluded,
    Observed,
};

using CreditDiagnosticReporter = std::function<void(CreditRootLocation, CreditEvidenceKind, const std::string&)>;

// The reporter must emit incrementally or charge any retained copies to the producer's budget.
Result<Status> EvaluatePasswordCreditUnion(const PasswordCreditAssessment& mainRoot, const PasswordCreditAssessment& dropInRoot,
    const CreditDiagnosticReporter& reportDiagnostic);
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_PASSWORD_CREDIT_UNION_EVIDENCE_H
