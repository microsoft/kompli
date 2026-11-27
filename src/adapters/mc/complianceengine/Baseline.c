// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "../Common.h"
#include "MCInterface.h"

#include <stdbool.h>

static MMI_HANDLE gComplianceEngine = NULL;
static bool gIsMmiLoaded = false;
static const char gComponentName[] = "ComplianceEngine";

int BaselineIsValidResourceIdRuleId(const char* resourceId, const char* ruleId, const char* payloadKey, OsConfigLogHandle log)
{
    UNUSED(resourceId);
    UNUSED(ruleId);
    UNUSED(payloadKey);
    UNUSED(log);
    return 0;
}

int BaselineIsCorrectDistribution(const char* payloadKey, OsConfigLogHandle log)
{
    return KompliCheckApplicability(gComplianceEngine, payloadKey, log);
}

// This function is called in library constructor in OsConfigResource.c
// once per Baseline lifetime
void BaselineInitialize(OsConfigLogHandle log)
{
    KompliInitialize(log);
    gComplianceEngine = KompliMmiOpen(gComponentName, -1);
}

// This function is called in library destructor in OsConfigResource.c
// once per Baseline lifetime
void BaselineShutdown(OsConfigLogHandle log)
{
    UNUSED(log);
    if (NULL == gComplianceEngine)
    {
        gIsMmiLoaded = false;
        return;
    }

    KompliMmiClose(gComplianceEngine);
    KompliShutdown();
    gComplianceEngine = NULL;
    gIsMmiLoaded = false;
}

// This function is called after BaselineInitialize and before BaselineMmiUnload
// may be called many times per Baseline lifetime
void BaselineMmiLoad(OsConfigLogHandle log)
{
    if (NULL == gComplianceEngine)
    {
        OsConfigLogError(log, "BaselineMmiLoad called before BaselineInitialize");
        return;
    }

    if (gIsMmiLoaded)
    {
        OsConfigLogError(log, "BaselineMmiLoad called without a matching BaselineMmiUnload");
        return;
    }

    KompliLoad(gComplianceEngine, gComponentName);
    gIsMmiLoaded = true;
}
// This function is called in after BaselineMmiLoad and before BaselineShutdown
// may be called many times per Baseline lifetime
void BaselineMmiUnload(OsConfigLogHandle log)
{
    if (NULL == gComplianceEngine)
    {
        OsConfigLogError(log, "BaselineMmiUnload called before BaselineInitialize");
        return;
    }

    if (!gIsMmiLoaded)
    {
        OsConfigLogError(log, "BaselineMmiUnload called without a matching BaselineMmiLoad");
        return;
    }

    KompliUnload(gComplianceEngine, gComponentName);
    gIsMmiLoaded = false;
}

int BaselineMmiGet(const char* componentName, const char* objectName, char** payload, int* payloadSizeBytes, unsigned int maxPayloadSizeBytes, OsConfigLogHandle log)
{
    if ((NULL == componentName) || (NULL == objectName))
    {
        OsConfigLogError(log, "BaselineMmiGet called with invalid arguments");
        return EINVAL;
    }

    int result = KompliMmiGet(gComplianceEngine, componentName, objectName, payload, payloadSizeBytes);
    if (MMI_OK != result)
    {
        OsConfigLogError(log, "BaselineMmiGet(%s, %s) failed: %d", componentName, objectName, result);
        return result;
    }

    if ((NULL != *payload) && (*payloadSizeBytes > 0) & (maxPayloadSizeBytes > 0) && ((unsigned)*payloadSizeBytes > maxPayloadSizeBytes))
    {
        OsConfigLogInfo(log, "BaselineMmiGet(%s, %s) payload truncated from %d to %u bytes", componentName, objectName, *payloadSizeBytes, maxPayloadSizeBytes);
        *payloadSizeBytes = (int)maxPayloadSizeBytes;
        *payload[*payloadSizeBytes] = '\0';
    }

    return MMI_OK;
}

int BaselineMmiSet(const char* componentName, const char* objectName, const char* payload, const int payloadSizeBytes, OsConfigLogHandle log)
{
    UNUSED(log);
    return KompliMmiSet(gComplianceEngine, componentName, objectName, payload, payloadSizeBytes);
}
