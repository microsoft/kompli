// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPLIANCEENGINE_TYPED_COMPARISON_H
#define COMPLIANCEENGINE_TYPED_COMPARISON_H

#include <Result.h>
#include <cerrno>
#include <string>

namespace ComplianceEngine
{
enum class TypedComparisonOperation
{
    Equal,
    NotEqual,
    LessThan,
    LessOrEqual,
    GreaterThan,
    GreaterOrEqual,
};

template <typename T>
Result<bool> CompareTyped(const T& lhs, const T& rhs, TypedComparisonOperation operation)
{
    switch (operation)
    {
        case TypedComparisonOperation::Equal:
            return lhs == rhs;
        case TypedComparisonOperation::NotEqual:
            return lhs != rhs;
        case TypedComparisonOperation::LessThan:
            return lhs < rhs;
        case TypedComparisonOperation::LessOrEqual:
            return lhs <= rhs;
        case TypedComparisonOperation::GreaterThan:
            return lhs > rhs;
        case TypedComparisonOperation::GreaterOrEqual:
            return lhs >= rhs;
    }
    return Error("Unsupported typed comparison operation " + std::to_string(static_cast<int>(operation)), EINVAL);
}
} // namespace ComplianceEngine

#endif // COMPLIANCEENGINE_TYPED_COMPARISON_H
