// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef KOMPLI_PROCEDURES_WIRELESS_DISABLED_H
#define KOMPLI_PROCEDURES_WIRELESS_DISABLED_H

#include <Evaluator.h>

namespace Kompli
{
Result<Status> AuditWirelessDisabled(IndicatorsTree& indicators, ContextInterface& context);
} // namespace Kompli
#endif // KOMPLI_PROCEDURES_WIRELESS_DISABLED_H
