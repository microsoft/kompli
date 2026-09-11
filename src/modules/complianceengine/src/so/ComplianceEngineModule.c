// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ComplianceEngineInterface.h"
#include "Logging.h"

#include <Mmi.h>
#include <stddef.h>

static const char* gComplianceEngineModuleName = "OSConfig ComplianceEngine module";

// Loaded in-process by the configuration agent, so this module's own stderr
// is the agent's, not an independent channel: log to syslog(3) instead of
// opening a log file by path (see docs/logging.md in this repo).
void __attribute__((constructor)) InitModule(void)
{
    OpenSyslog("kompli");
    ComplianceEngineInitialize(NULL);
    OsConfigLogInfo(NULL, "%s initialized", gComplianceEngineModuleName);
}

void __attribute__((destructor)) DestroyModule(void)
{
    ComplianceEngineShutdown();
    CloseSyslog();
}

int MmiGetInfo(const char* clientName, MMI_JSON_STRING* payload, int* payloadSizeBytes)
{
    return ComplianceEngineMmiGetInfo(clientName, payload, payloadSizeBytes);
}

MMI_HANDLE MmiOpen(const char* clientName, const unsigned int maxPayloadSizeBytes)
{
    return ComplianceEngineMmiOpen(clientName, maxPayloadSizeBytes);
}

void MmiClose(MMI_HANDLE clientSession)
{
    return ComplianceEngineMmiClose(clientSession);
}

int MmiSet(MMI_HANDLE clientSession, const char* componentName, const char* objectName, const MMI_JSON_STRING payload, const int payloadSizeBytes)
{
    return ComplianceEngineMmiSet(clientSession, componentName, objectName, payload, payloadSizeBytes);
}

int MmiGet(MMI_HANDLE clientSession, const char* componentName, const char* objectName, MMI_JSON_STRING* payload, int* payloadSizeBytes)
{
    return ComplianceEngineMmiGet(clientSession, componentName, objectName, payload, payloadSizeBytes);
}

void MmiFree(MMI_JSON_STRING payload)
{
    return ComplianceEngineMmiFree(payload);
}
