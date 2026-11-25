// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#ifndef KOMPLI_PROCEDURES_FILE_EXISTS_H
#define KOMPLI_PROCEDURES_FILE_EXISTS_H

#include <Evaluator.h>

namespace Kompli
{
// Parameters used by the EnsureFileExists procedure.
struct FileExistsParams
{
    /// Path to the file to check for existence
    std::string filename;
};

Result<Status> AuditFileExists(const FileExistsParams& params, IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli

#endif // KOMPLI_PROCEDURES_FILE_EXISTS_H
