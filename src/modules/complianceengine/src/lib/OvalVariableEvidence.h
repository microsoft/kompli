// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_OVAL_VARIABLE_EVIDENCE_H
#define COMPLIANCEENGINE_OVAL_VARIABLE_EVIDENCE_H

#include <OvalVariableResolver.h>
#include <cerrno>
#include <string>
#include <utility>
#include <vector>

namespace ComplianceEngine
{
namespace OvalVariable
{
inline bool IsSupportedComparisonOperation(TypedComparisonOperation operation)
{
    switch (operation)
    {
        case TypedComparisonOperation::Equal:
        case TypedComparisonOperation::NotEqual:
        case TypedComparisonOperation::LessThan:
        case TypedComparisonOperation::LessOrEqual:
        case TypedComparisonOperation::GreaterThan:
        case TypedComparisonOperation::GreaterOrEqual:
            return true;
    }
    return false;
}

enum class EvidenceState
{
    Complete,
    Incomplete,
    DoesNotExist,
};

enum class VariableDatatype
{
    String,
    Integer,
};

template <typename T>
struct ValueEvidence
{
    EvidenceState state = EvidenceState::Complete;
    std::vector<T> values;
    std::string source;
    std::string diagnostic;

    ValueEvidence() = default;

    ValueEvidence(EvidenceState evidenceState, std::vector<T> evidenceValues, std::string evidenceSource, std::string evidenceDiagnostic)
        : state(evidenceState),
          values(std::move(evidenceValues)),
          source(std::move(evidenceSource)),
          diagnostic(std::move(evidenceDiagnostic))
    {
    }
};

template <typename T>
ValueEvidence<T> IncompleteEvidence(std::string source, std::string diagnostic)
{
    return {EvidenceState::Incomplete, {}, std::move(source), std::move(diagnostic)};
}

template <typename T>
ValueEvidence<T> DoesNotExistEvidence(std::string source)
{
    return {EvidenceState::DoesNotExist, {}, std::move(source), {}};
}

inline Result<ValueEvidence<std::string>> ResolveStringEvidence(const std::string& objectRef, const std::string& itemField, const CollectObject& collect)
{
    if (objectRef.empty() || itemField.empty() || !collect)
    {
        return Error("Invalid object_component reference, field or collector", EINVAL);
    }

    auto collected = collect(objectRef);
    if (!collected.HasValue())
    {
        return collected.Error();
    }
    if (!collected.Value().complete)
    {
        return IncompleteEvidence<std::string>(objectRef, "Incomplete object collection: " + objectRef);
    }

    auto values = ExtractObjectFields(collected.Value(), objectRef, itemField);
    if (!values.HasValue())
    {
        return values.Error();
    }

    return ValueEvidence<std::string>{EvidenceState::Complete, std::move(values).Value(), objectRef + ":" + itemField, {}};
}

inline Result<ValueEvidence<long long>> ResolveIntegerEvidence(const std::string& objectRef, const std::string& itemField, const CollectObject& collect)
{
    auto strings = ResolveStringEvidence(objectRef, itemField, collect);
    if (!strings.HasValue())
    {
        return strings.Error();
    }
    if (strings.Value().state == EvidenceState::Incomplete)
    {
        return IncompleteEvidence<long long>(strings.Value().source, strings.Value().diagnostic);
    }
    if (strings.Value().state == EvidenceState::DoesNotExist)
    {
        return DoesNotExistEvidence<long long>(strings.Value().source);
    }

    auto values = IntegerValues(strings.Value().values);
    if (!values.HasValue())
    {
        return values.Error();
    }
    return ValueEvidence<long long>{EvidenceState::Complete, std::move(values).Value(), strings.Value().source, {}};
}

inline Result<ValueEvidence<std::string>> ResolveEvidence(const std::string& objectRef, const std::string& itemField, VariableDatatype datatype,
    const CollectObject& collect)
{
    if (datatype != VariableDatatype::String)
    {
        return Error("Requested non-string OVAL variable from string resolver", EINVAL);
    }
    return ResolveStringEvidence(objectRef, itemField, collect);
}

inline Result<ValueEvidence<long long>> ResolveIntegerEvidence(const std::string& objectRef, const std::string& itemField, VariableDatatype datatype,
    const CollectObject& collect)
{
    if (datatype != VariableDatatype::Integer)
    {
        return Error("Requested non-integer OVAL variable from integer resolver", EINVAL);
    }
    return ResolveIntegerEvidence(objectRef, itemField, collect);
}

inline Result<ValueEvidence<std::string>> UniqueEvidence(const ValueEvidence<std::string>& evidence)
{
    if (evidence.state == EvidenceState::Incomplete)
    {
        return IncompleteEvidence<std::string>(evidence.source, evidence.diagnostic);
    }
    if (evidence.state == EvidenceState::DoesNotExist)
    {
        return Error("Cannot evaluate unique from a nonexistent variable: " + evidence.source, ENODATA);
    }
    return ValueEvidence<std::string>{EvidenceState::Complete, Unique(evidence.values), evidence.source, {}};
}

inline Result<ValueEvidence<std::string>> SplitEvidence(const ValueEvidence<std::string>& evidence, const std::string& delimiter)
{
    if (delimiter.empty())
    {
        return Error("Empty OVAL split delimiter", EINVAL);
    }
    if (evidence.state == EvidenceState::Incomplete)
    {
        return IncompleteEvidence<std::string>(evidence.source, evidence.diagnostic);
    }
    if (evidence.state == EvidenceState::DoesNotExist)
    {
        return Error("Cannot evaluate split from a nonexistent variable: " + evidence.source, ENODATA);
    }

    auto values = Split(evidence.values, delimiter);
    if (!values.HasValue())
    {
        return values.Error();
    }
    return ValueEvidence<std::string>{EvidenceState::Complete, std::move(values).Value(), evidence.source, {}};
}

template <typename T>
Result<ValueEvidence<long long>> CountEvidence(const ValueEvidence<T>& evidence)
{
    if (evidence.state == EvidenceState::Incomplete)
    {
        return IncompleteEvidence<long long>(evidence.source, evidence.diagnostic);
    }
    if (evidence.state == EvidenceState::DoesNotExist)
    {
        return Error("Cannot evaluate count from a nonexistent variable: " + evidence.source, ENODATA);
    }

    auto value = Count(evidence.values);
    if (!value.HasValue())
    {
        return value.Error();
    }
    return ValueEvidence<long long>{EvidenceState::Complete, {value.Value()}, evidence.source, {}};
}

template <typename T>
Result<ValueEvidence<bool>> CompareStateValues(const ValueEvidence<T>& evidence, const T& expected, TypedComparisonOperation operation)
{
    if (!IsSupportedComparisonOperation(operation))
    {
        return Error("Unsupported typed comparison operation", EINVAL);
    }
    if (evidence.state == EvidenceState::Incomplete)
    {
        return IncompleteEvidence<bool>(evidence.source, evidence.diagnostic);
    }
    if (evidence.state == EvidenceState::DoesNotExist)
    {
        return Error("Cannot compare a nonexistent state variable: " + evidence.source, ENODATA);
    }
    if (evidence.values.empty())
    {
        return Error("Cannot compare an empty state variable: " + evidence.source, ENODATA);
    }

    std::vector<bool> results;
    results.reserve(evidence.values.size());
    for (const auto& value : evidence.values)
    {
        auto result = CompareTyped(value, expected, operation);
        if (!result.HasValue())
        {
            return result.Error();
        }
        results.push_back(result.Value());
    }
    return ValueEvidence<bool>{EvidenceState::Complete, std::move(results), evidence.source, {}};
}

template <typename T>
Result<ValueEvidence<bool>> CompareScalarEvidence(const ValueEvidence<T>& lhs, const ValueEvidence<T>& rhs, TypedComparisonOperation operation)
{
    if (!IsSupportedComparisonOperation(operation))
    {
        return Error("Unsupported typed comparison operation", EINVAL);
    }
    if (lhs.state == EvidenceState::DoesNotExist || rhs.state == EvidenceState::DoesNotExist)
    {
        return Error("Cannot compare a nonexistent scalar variable: " + lhs.source + " and " + rhs.source, ENODATA);
    }
    if (lhs.state == EvidenceState::Incomplete)
    {
        return IncompleteEvidence<bool>(lhs.source, lhs.diagnostic);
    }
    if (rhs.state == EvidenceState::Incomplete)
    {
        return IncompleteEvidence<bool>(rhs.source, rhs.diagnostic);
    }
    if (lhs.values.size() != 1 || rhs.values.size() != 1)
    {
        return Error("Scalar comparison requires exactly one value from each variable: " + lhs.source + " and " + rhs.source, EINVAL);
    }

    auto result = CompareTyped(lhs.values.front(), rhs.values.front(), operation);
    if (!result.HasValue())
    {
        return result.Error();
    }
    return ValueEvidence<bool>{EvidenceState::Complete, {result.Value()}, lhs.source + " compared with " + rhs.source, {}};
}
} // namespace OvalVariable
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_OVAL_VARIABLE_EVIDENCE_H
