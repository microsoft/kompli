#ifndef COMPLIANCEENGINE_PROCEDURES_AIDE_ATTRIBUTES_H
#define COMPLIANCEENGINE_PROCEDURES_AIDE_ATTRIBUTES_H

#include <Evaluator.h>

namespace ComplianceEngine
{
struct AideAttributesParams
{
    /// AIDE configuration file used to resolve effective selection rules
    std::string configPath;

    /// File whose canonical path is queried in the AIDE configuration
    std::string filename;

    /// Plus-separated attribute names that must all be enabled for the file
    std::string attributes;
};

Result<Status> AuditAideAttributes(const AideAttributesParams& params, IndicatorsTree& indicators, ContextInterface& context);
} // namespace ComplianceEngine

#endif
