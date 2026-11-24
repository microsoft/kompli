// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef KOMPLI_SYSTEMD_CAT_CONFIG_H
#define KOMPLI_SYSTEMD_CAT_CONFIG_H

#include <ContextInterface.h>
#include <Result.h>

namespace Kompli
{
Result<std::string> SystemdCatConfig(const std::string& filename, ContextInterface& context);
} // namespace Kompli

#endif // KOMPLI_SYSTEMD_CAT_CONFIG_H
