// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "MCInterface.h"
#include "Logging.h"

#include <Mmi.h>
#include <assert.h>
#include <stddef.h>

static OsConfigLogHandle gLog = NULL;
static const char* gLogFile = "/var/log/kompli.log";
static const char* gRolledLogFile = "/var/log/kompli.bak";
static const char* gComplianceEngineModuleName = "OSConfig ComplianceEngine module";

void __attribute__((constructor)) InitModule(void)
{
    gLog = OpenLog(gLogFile, gRolledLogFile);
    assert(NULL != gLog);
    KompliInitialize(gLog);
    OsConfigLogInfo(gLog, "%s initialized", gComplianceEngineModuleName);
}

void __attribute__((destructor)) DestroyModule(void)
{
    KompliShutdown();
    CloseLog(&gLog);
}

int MmiGetInfo(const char* clientName, MMI_JSON_STRING* payload, int* payloadSizeBytes)
{
    return KompliMmiGetInfo(clientName, payload, payloadSizeBytes);
}

MMI_HANDLE MmiOpen(const char* clientName, const unsigned int maxPayloadSizeBytes)
{
    return KompliMmiOpen(clientName, maxPayloadSizeBytes);
}

void MmiClose(MMI_HANDLE clientSession)
{
    return KompliMmiClose(clientSession);
}

int MmiSet(MMI_HANDLE clientSession, const char* componentName, const char* objectName, const MMI_JSON_STRING payload, const int payloadSizeBytes)
{
    return KompliMmiSet(clientSession, componentName, objectName, payload, payloadSizeBytes);
}

int MmiGet(MMI_HANDLE clientSession, const char* componentName, const char* objectName, MMI_JSON_STRING* payload, int* payloadSizeBytes)
{
    return KompliMmiGet(clientSession, componentName, objectName, payload, payloadSizeBytes);
}

void MmiFree(MMI_JSON_STRING payload)
{
    return KompliMmiFree(payload);
}
