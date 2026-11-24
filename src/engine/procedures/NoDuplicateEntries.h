// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_NO_DUPLICATE_ENTRIES_H
#define KOMPLI_PROCEDURES_NO_DUPLICATE_ENTRIES_H

#include <Evaluator.h>

namespace Kompli
{
struct NoDuplicateEntriesParams
{
    /// The file to be checked for duplicate entries
    std::string filename;

    /// A single character used to separate entries
    std::string delimiter;

    /// Column index to check for duplicates
    int column = 0;

    /// Context for the entries used in the messages
    Optional<std::string> context;
};

Result<Status> AuditNoDuplicateEntries(const NoDuplicateEntriesParams& params, IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // KOMPLI_PROCEDURES_NO_DUPLICATE_ENTRIES_H
