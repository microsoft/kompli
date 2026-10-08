// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <PasswordCreditUnionEvidence.h>
#include <ResultEvidence.h>
#include <TypedComparison.h>
#include <cerrno>
#include <initializer_list>

namespace ComplianceEngine
{
namespace
{
void ReportEvidence(const PasswordCreditAssessment& root, CreditRootLocation location, const CreditDiagnosticReporter& reportDiagnostic)
{
    if (root.result.HasValue())
    {
        for (const auto& item : root.result.Value().selected)
        {
            reportDiagnostic(location, CreditEvidenceKind::Selected, item.identity);
        }
        for (const auto& exclusion : root.result.Value().exclusions)
        {
            reportDiagnostic(location, CreditEvidenceKind::Excluded, exclusion);
        }
    }
    for (const auto& identity : root.observed)
    {
        reportDiagnostic(location, CreditEvidenceKind::Observed, identity);
    }
}

Result<Status> ValidateRoot(const PasswordCreditAssessment& root, const char* name)
{
    const auto& evidence = root.result.Value();
    if (evidence.outcome == PasswordCreditRoot::Outcome::Stopped)
    {
        if (evidence.stopReason.empty())
        {
            return Error(std::string("Stopped password credit root lacks a reason: ") + name, EINVAL);
        }
        return Error(std::string("Insufficient stop in ") + name + " password credit root: " + evidence.stopReason, EINVAL);
    }
    if ((evidence.outcome != PasswordCreditRoot::Outcome::Complete) && (evidence.outcome != PasswordCreditRoot::Outcome::Absent))
    {
        return Error(std::string("Invalid password credit root outcome: ") + name, EINVAL);
    }
    if ((evidence.outcome == PasswordCreditRoot::Outcome::Absent) && ((!evidence.selected.empty()) || (!evidence.exclusions.empty())))
    {
        return Error(std::string("Absent password credit root contains items: ") + name, EINVAL);
    }
    if ((!evidence.stopReason.empty()) && (evidence.outcome != PasswordCreditRoot::Outcome::Stopped))
    {
        return Error(std::string("Completed password credit root contains a stop reason: ") + name, EINVAL);
    }
    return Status::Compliant;
}
} // anonymous namespace

Result<Status> EvaluatePasswordCreditUnion(const PasswordCreditAssessment& mainRoot, const PasswordCreditAssessment& dropInRoot,
    const CreditDiagnosticReporter& reportDiagnostic)
{
    if (!reportDiagnostic)
    {
        return Error("Missing password credit diagnostic reporter", EINVAL);
    }
    if ((!mainRoot.result.HasValue()) || (!dropInRoot.result.HasValue()))
    {
        ReportEvidence(mainRoot, CreditRootLocation::Main, reportDiagnostic);
        ReportEvidence(dropInRoot, CreditRootLocation::DropIn, reportDiagnostic);
        return !mainRoot.result.HasValue() ? mainRoot.result.Error() : dropInRoot.result.Error();
    }
    const auto main = ValidateRoot(mainRoot, "main");
    if (!main.HasValue())
    {
        ReportEvidence(mainRoot, CreditRootLocation::Main, reportDiagnostic);
        ReportEvidence(dropInRoot, CreditRootLocation::DropIn, reportDiagnostic);
        return main.Error();
    }
    const auto dropIn = ValidateRoot(dropInRoot, "drop-in");
    if (!dropIn.HasValue())
    {
        ReportEvidence(mainRoot, CreditRootLocation::Main, reportDiagnostic);
        ReportEvidence(dropInRoot, CreditRootLocation::DropIn, reportDiagnostic);
        return dropIn.Error();
    }

    CompletedItemEvidence combined;
    for (const auto* root : {&mainRoot.result.Value(), &dropInRoot.result.Value()})
    {
        for (const auto& item : root->selected)
        {
            if (!item.value.HasValue())
            {
                combined.AddSelected(false);
                continue;
            }
            const auto matches = CompareTyped(item.value.Value(), 0LL, TypedComparisonOperation::LessThan);
            if (!matches.HasValue())
            {
                ReportEvidence(mainRoot, CreditRootLocation::Main, reportDiagnostic);
                ReportEvidence(dropInRoot, CreditRootLocation::DropIn, reportDiagnostic);
                return matches.Error();
            }
            combined.AddSelected(matches.Value());
        }
    }
    const auto result = combined.EvaluateAtLeastOneAll();
    ReportEvidence(mainRoot, CreditRootLocation::Main, reportDiagnostic);
    ReportEvidence(dropInRoot, CreditRootLocation::DropIn, reportDiagnostic);
    return result;
}
} // namespace ComplianceEngine
