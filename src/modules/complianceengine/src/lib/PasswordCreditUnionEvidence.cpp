// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <PasswordCreditUnionEvidence.h>
#include <ResultEvidence.h>
#include <TypedComparison.h>
#include <cerrno>
#include <exception>
#include <initializer_list>

namespace ComplianceEngine
{
namespace
{
Result<bool> ReportOne(CreditRootLocation location, CreditEvidenceKind kind, const std::string& identity, const CreditDiagnosticReporter& reportDiagnostic)
{
    try
    {
        reportDiagnostic(location, kind, identity);
        return true;
    }
    catch (const std::exception&)
    {
        return Error("Password credit diagnostic reporter threw an exception", EIO);
    }
    catch (...)
    {
        return Error("Password credit diagnostic reporter threw an unknown exception", EIO);
    }
}

Result<bool> ReportEvidence(const PasswordCreditAssessment& root, CreditRootLocation location, const CreditDiagnosticReporter& reportDiagnostic)
{
    if (root.result.HasValue())
    {
        for (const auto& item : root.result.Value().selected)
        {
            const auto reported = ReportOne(location, CreditEvidenceKind::Selected, item.identity, reportDiagnostic);
            if (!reported.HasValue())
            {
                return reported.Error();
            }
        }
        for (const auto& exclusion : root.result.Value().exclusions)
        {
            const auto reported = ReportOne(location, CreditEvidenceKind::Excluded, exclusion, reportDiagnostic);
            if (!reported.HasValue())
            {
                return reported.Error();
            }
        }
    }
    for (const auto& identity : root.observed)
    {
        const auto reported = ReportOne(location, CreditEvidenceKind::Observed, identity, reportDiagnostic);
        if (!reported.HasValue())
        {
            return reported.Error();
        }
    }
    return true;
}

Result<bool> ReportAllEvidence(const PasswordCreditAssessment& mainRoot, const PasswordCreditAssessment& dropInRoot, const CreditDiagnosticReporter& reportDiagnostic)
{
    const auto main = ReportEvidence(mainRoot, CreditRootLocation::Main, reportDiagnostic);
    if (!main.HasValue())
    {
        return main.Error();
    }
    return ReportEvidence(dropInRoot, CreditRootLocation::DropIn, reportDiagnostic);
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
        return Error(std::string("Non-stopped password credit root contains a stop reason: ") + name, EINVAL);
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
    const auto evaluation = [&]() -> Result<Status> {
        if ((!mainRoot.result.HasValue()) || (!dropInRoot.result.HasValue()))
        {
            return !mainRoot.result.HasValue() ? mainRoot.result.Error() : dropInRoot.result.Error();
        }
        const auto main = ValidateRoot(mainRoot, "main");
        if (!main.HasValue())
        {
            return main.Error();
        }
        const auto dropIn = ValidateRoot(dropInRoot, "drop-in");
        if (!dropIn.HasValue())
        {
            return dropIn.Error();
        }

        CompletedItemEvidence combined;
        for (const auto* root : {&mainRoot.result.Value(), &dropInRoot.result.Value()})
        {
            for (const auto& item : root->selected)
            {
                if (!item.value.HasValue())
                {
                    combined.AddSelected(StateSatisfaction::NotSatisfied);
                    continue;
                }
                const auto matches = CompareTyped(item.value.Value(), 0LL, TypedComparisonOperation::LessThan);
                combined.AddSelected(!matches.HasValue() ?
                                         Result<StateSatisfaction>(matches.Error()) :
                                         Result<StateSatisfaction>(matches.Value() ? StateSatisfaction::Satisfied : StateSatisfaction::NotSatisfied));
            }
        }
        const auto state = combined.AllSelectedStatesSatisfied();
        if (!state.HasValue())
        {
            return state.Error();
        }
        return (combined.HasSelectedItems() && state.Value() == StateSatisfaction::Satisfied) ? Status::Compliant : Status::NonCompliant;
    }();

    const auto reported = ReportAllEvidence(mainRoot, dropInRoot, reportDiagnostic);
    if (!evaluation.HasValue())
    {
        return evaluation.Error();
    }
    if (!reported.HasValue())
    {
        return reported.Error();
    }
    return evaluation.Value();
}
} // namespace ComplianceEngine
