// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef KOMPLI_MC_INTERFACE_H
#define KOMPLI_MC_INTERFACE_H

#include "../inc/Mmi.h"

#include <Logging.h>

#ifdef __cplusplus
extern "C"
{
#endif

void KompliInitialize(OsConfigLogHandle);
void KompliShutdown();

void KompliLoad(MMI_HANDLE clientSession, const char* componentName);
void KompliUnload(MMI_HANDLE clientSession, const char* componentName);

MMI_HANDLE KompliMmiOpen(const char* clientName, const unsigned int maxPayloadSizeBytes);
void KompliMmiClose(MMI_HANDLE clientSession);
int KompliMmiGetInfo(const char* clientName, char** payload, int* payloadSizeBytes);
int KompliMmiGet(MMI_HANDLE clientSession, const char* componentName, const char* objectName, char** payload, int* payloadSizeBytes);
int KompliMmiSet(MMI_HANDLE clientSession, const char* componentName, const char* objectName, const char* payload, const int payloadSizeBytes);
void KompliMmiFree(char* payload);

int KompliCheckApplicability(MMI_HANDLE clientSession, const char* payloadKey, OsConfigLogHandle log);

#ifdef __cplusplus
}
#endif

#endif // KOMPLI_MC_INTERFACE_H
