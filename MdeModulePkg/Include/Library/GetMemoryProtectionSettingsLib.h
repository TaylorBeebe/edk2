/** @file
Library for accessing the platform memory protection settings.

Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef GET_MEMORY_PROTECTION_SETTINGS_LIB_H_
#define GET_MEMORY_PROTECTION_SETTINGS_LIB_H_

#include <Guid/MemoryProtectionSettings.h>

// The global used to access current Memory Protection Settings
extern MEMORY_PROTECTION_SETTINGS  *gMps;

// Check if gMps is non-NULL and the version numbers are valid
#define MPS_VALID  ((gMps != NULL)                                                              && \
                    (gMps->Mm.StructVersion == MM_MEMORY_PROTECTION_SETTINGS_CURRENT_VERSION)   && \
                    (gMps->Dxe.StructVersion == DXE_MEMORY_PROTECTION_SETTINGS_CURRENT_VERSION))

/**
  Returns TRUE if gMps->Dxe.HeapGuard.PageGuardEnabled is TRUE and
  any memory type is enabled in gMps->Dxe.PageGuard.EnabledForType[].

  @retval TRUE   Page guards are enabled for at least one memory type.
  @retval FALSE  Page guards are not enabled for any memory type.
**/
BOOLEAN
EFIAPI
IsDxePageGuardActive (
  VOID
  );

/**
  Returns TRUE if gMps->Dxe.HeapGuard.PoolGuardEnabled is TRUE and
  any memory type is enabled in gMps->Dxe.PoolGuard.EnabledForType[].

  @retval TRUE   Pool guards are enabled for at least one memory type.
  @retval FALSE  Pool guards are not enabled for any memory type.
**/
BOOLEAN
EFIAPI
IsDxePoolGuardActive (
  VOID
  );

/**
  Returns TRUE if any memory type is enabled in
  gMps->Dxe.ExecutionProtection.EnabledForType[].

  @retval TRUE   Execution protection is enabled for at least one memory type.
  @retval FALSE  Execution protection is not enabled for any memory type.
**/
BOOLEAN
EFIAPI
IsDxeExecutionProtectionActive (
  VOID
  );

/**
  Returns TRUE if gMps->Dxe.ImageProtection.ProtectImageFromFv is TRUE or
  gMps->Dxe.ImageProtection.ProtectImageFromUnknown is TRUE.

  @retval TRUE   Image protection is enabled.
  @retval FALSE  Image protection is not enabled.
**/
BOOLEAN
EFIAPI
IsDxeImageProtectionActive (
  VOID
  );

/**
  Returns TRUE any form of memory protection is active in DXE.

  @retval TRUE   Memory protection is active.
  @retval FALSE  Memory protection is not active.
**/
BOOLEAN
EFIAPI
IsDxeMemoryProtectionActive (
  VOID
  );

/**
  Returns TRUE if gMps->Mm.HeapGuard.PageGuardEnabled is TRUE and
  any memory type is enabled in gMps->Mm.PageGuard.EnabledForType[].

  @retval TRUE   Page guards are enabled for at least one memory type.
  @retval FALSE  Page guards are not enabled for any memory type.
**/
BOOLEAN
EFIAPI
IsMmPageGuardActive (
  VOID
  );

/**
  Returns TRUE if gMps->Mm.HeapGuard.PoolGuardEnabled is TRUE and
  any memory type is enabled in gMps->Mm.PoolGuard.EnabledForType[].

  @retval TRUE   Pool guards are enabled for at least one memory type.
  @retval FALSE  Pool guards are not enabled for any memory type.
**/
BOOLEAN
EFIAPI
IsMmPoolGuardActive (
  VOID
  );

/**
  Returns TRUE any form of memory protection is active in MM.

  @retval TRUE   Memory protection is active.
  @retval FALSE  Memory protection is not active.
**/
BOOLEAN
EFIAPI
IsMmMemoryProtectionActive (
  VOID
  );

/**
  Populates gMps global. This function is invoked by the library constructor and only needs to be
  called if library contructors have not yet been invoked (usually very early DXE).

  @retval EFI_SUCCESS       gMps global was populated.
  @retval EFI_NOT_FOUND     The gMemoryProtectionSettingsGuid HOB was not found.
  @retval EFI_ABORTED       The version number of the DXE or MM memory protection settings was invalid.
  @retval EFI_UNSUPPORTED   NULL implementation called.
**/
EFI_STATUS
EFIAPI
PopulateMpsGlobal (
  VOID
  );

#endif
