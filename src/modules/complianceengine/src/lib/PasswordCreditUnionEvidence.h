// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_PASSWORD_CREDIT_UNION_EVIDENCE_H
#define COMPLIANCEENGINE_PASSWORD_CREDIT_UNION_EVIDENCE_H

#include <MmiResults.h>
#include <Optional.h>
#include <Result.h>
#include <functional>
#include <string>
#include <utility>
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
        Unspecified,
        Complete,
        Absent,
        Stopped,
    };

    PasswordCreditRoot()
        : outcome(Outcome::Unspecified)
    {
    }
    PasswordCreditRoot(Outcome outcome, std::vector<PasswordCreditItem> selected, std::vector<std::string> exclusions, std::string stopReason)
        : outcome(outcome),
          selected(std::move(selected)),
          exclusions(std::move(exclusions)),
          stopReason(std::move(stopReason))
    {
    }

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

// The reporter must emit incrementally or charge retained copies to the producer's budget.
// Reporter exceptions become evaluation errors; an already-reached assessment error takes precedence.
Result<Status> EvaluatePasswordCreditUnion(const PasswordCreditAssessment& mainRoot, const PasswordCreditAssessment& dropInRoot,
    const CreditDiagnosticReporter& reportDiagnostic);
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_PASSWORD_CREDIT_UNION_EVIDENCE_H
