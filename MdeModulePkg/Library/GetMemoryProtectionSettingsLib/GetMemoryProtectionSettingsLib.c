/** @file
Library fills out gMps global for accessing the platform memory protection settings

Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiDxe.h>

#include <Library/GetMemoryProtectionSettingsLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/BaseMemoryLib.h>

MEMORY_PROTECTION_SETTINGS  *gMps = NULL;

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
  )
{
  return (MPS_VALID &&
          !IsZeroBuffer (&gMps->Dxe.PageGuard.EnabledForType, MPS_MEMORY_TYPE_BUFFER_SIZE)) &&
         gMps->Dxe.HeapGuard.PageGuardEnabled;
}

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
  )
{
  return (MPS_VALID &&
          !IsZeroBuffer (&gMps->Dxe.PoolGuard.EnabledForType, MPS_MEMORY_TYPE_BUFFER_SIZE)) &&
         gMps->Dxe.HeapGuard.PoolGuardEnabled;
}

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
  )
{
  return MPS_VALID &&
         !IsZeroBuffer (&gMps->Dxe.ExecutionProtection.EnabledForType, MPS_MEMORY_TYPE_BUFFER_SIZE);
}

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
  )
{
  return MPS_VALID &&
         (gMps->Dxe.ImageProtection.ProtectImageFromFv ||
          gMps->Dxe.ImageProtection.ProtectImageFromUnknown);
}

/**
  Returns TRUE any form of memory protection is active in DXE.

  @retval TRUE   Memory protection is active.
  @retval FALSE  Memory protection is not active.
**/
BOOLEAN
EFIAPI
IsDxeMemoryProtectionActive (
  VOID
  )
{
  return MPS_VALID &&
         (gMps->Dxe.CpuStackGuardEnabled                  ||
          gMps->Dxe.StackExecutionProtectionEnabled       ||
          gMps->Dxe.NullPointerDetection.Enabled          ||
          gMps->Dxe.HeapGuard.FreedMemoryGuardEnabled     ||
          IsDxeImageProtectionActive ()                   ||
          IsDxeExecutionProtectionActive ()               ||
          IsDxePageGuardActive ()                         ||
          IsDxePoolGuardActive ());
}

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
  )
{
  return (MPS_VALID &&
          !IsZeroBuffer (&gMps->Mm.PageGuard.EnabledForType, MPS_MEMORY_TYPE_BUFFER_SIZE)) &&
         gMps->Mm.HeapGuard.PageGuardEnabled;
}

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
  )
{
  return (MPS_VALID &&
          !IsZeroBuffer (&gMps->Mm.PoolGuard.EnabledForType, MPS_MEMORY_TYPE_BUFFER_SIZE)) &&
         gMps->Mm.HeapGuard.PoolGuardEnabled;
}

/**
  Returns TRUE any form of memory protection is active in MM.

  @retval TRUE   Memory protection is active.
  @retval FALSE  Memory protection is not active.
**/
BOOLEAN
EFIAPI
IsMmMemoryProtectionActive (
  VOID
  )
{
  return MPS_VALID                                                                  &&
         (gMps->Mm.NullPointerDetection.Enabled                                     ||
          IsMmPageGuardActive ()                                                    ||
          IsMmPoolGuardActive ());
}

/**
  This function checks the memory protection settings for conflicts.
**/
STATIC
EFI_STATUS
DxeMemoryProtectionSettingsConsistencyCheck (
  IN MEMORY_PROTECTION_SETTINGS  *Mps
  )
{
  if ((Mps->Dxe.HeapGuard.PoolGuardEnabled || Mps->Dxe.HeapGuard.PageGuardEnabled) &&
      Mps->Dxe.HeapGuard.FreedMemoryGuardEnabled)
  {
    DEBUG ((
      DEBUG_WARN,
      "%a: - HeapGuard.FreedMemoryGuardEnabled and "
      "UEFI HeapGuard.PoolGuardEnabled/HeapGuard.PageGuardEnabled "
      "cannot be active at the same time. Setting all three to ZERO in "
      "the memory protection settings global.\n",
      __func__
      ));
    ASSERT (
      !(Mps->Dxe.HeapGuard.FreedMemoryGuardEnabled &&
        (Mps->Dxe.HeapGuard.PoolGuardEnabled || Mps->Dxe.HeapGuard.PageGuardEnabled))
      );
    return EFI_INVALID_PARAMETER;
  }

  if (!IsZeroBuffer (&Mps->Dxe.PoolGuard, MPS_MEMORY_TYPE_BUFFER_SIZE) &&
      (!(Mps->Dxe.HeapGuard.PoolGuardEnabled)))
  {
    DEBUG ((
      DEBUG_WARN,
      "%a: - PoolGuard protections are active "
      "but HeapGuard.PoolGuardEnabled is inactive.\n",
      __func__
      ));
  }

  if (!IsZeroBuffer (&Mps->Dxe.PageGuard, MPS_MEMORY_TYPE_BUFFER_SIZE) &&
      (!(Mps->Dxe.HeapGuard.PageGuardEnabled)))
  {
    DEBUG ((
      DEBUG_WARN,
      "%a: - PageGuard protections are active "
      "but HeapGuard.PageGuardEnabled is inactive\n",
      __func__
      ));
  }

  if (Mps->Dxe.ExecutionProtection.EnabledForType[EfiBootServicesData] !=
      Mps->Dxe.ExecutionProtection.EnabledForType[EfiConventionalMemory])
  {
    DEBUG ((
      DEBUG_WARN,
      "%a: - EfiBootServicesData and EfiConventionalMemory must have the same "
      "ExecutionProtection value. Setting both to ZERO in the memory protection "
      "settings global.\n",
      __func__
      ));
    ASSERT (
      Mps->Dxe.ExecutionProtection.EnabledForType[EfiBootServicesData] ==
      Mps->Dxe.ExecutionProtection.EnabledForType[EfiConventionalMemory]
      );
    return EFI_INVALID_PARAMETER;
  }

  return EFI_SUCCESS;
}

/**
  This function checks the memory protection settings and provides warnings of settings conflicts.
  For compatibility, this logic will only ever turn off protections to create consistency,
  never turn others on.
**/
STATIC
EFI_STATUS
MmMemoryProtectionSettingsConsistencyCheck (
  IN MEMORY_PROTECTION_SETTINGS  *Mps
  )
{
  if (!IsZeroBuffer (&Mps->Mm.PoolGuard, MPS_MEMORY_TYPE_BUFFER_SIZE) &&
      (!Mps->Mm.HeapGuard.PoolGuardEnabled))
  {
    DEBUG ((
      DEBUG_WARN,
      "%a: - PoolGuard protections are active "
      "but HeapGuard.PoolGuardEnabled is inactive.\n",
      __func__
      ));
  }

  if (!IsZeroBuffer (&Mps->Mm.PageGuard, MPS_MEMORY_TYPE_BUFFER_SIZE) &&
      (!Mps->Mm.HeapGuard.PageGuardEnabled))
  {
    DEBUG ((
      DEBUG_WARN,
      "%a: - PageGuard protections are active "
      "but HeapGuard.PageGuardEnabled is inactive\n",
      __func__
      ));
  }

  return EFI_SUCCESS;
}

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
  )
{
  VOID                        *Ptr;
  MEMORY_PROTECTION_SETTINGS  *Mps;

  Ptr = GetFirstGuidHob (&gMemoryProtectionSettingsGuid);

  if (Ptr != NULL) {
    Mps = (MEMORY_PROTECTION_SETTINGS *)*((EFI_PHYSICAL_ADDRESS *)GET_GUID_HOB_DATA (Ptr));
    if (Mps->Dxe.StructVersion != DXE_MEMORY_PROTECTION_SETTINGS_CURRENT_VERSION) {
      DEBUG ((
        DEBUG_ERROR,
        "%a: - Version number of the DXE Memory Protection Settings is invalid!\n",
        __func__
        ));
      ASSERT (Mps->Dxe.StructVersion == DXE_MEMORY_PROTECTION_SETTINGS_CURRENT_VERSION);
      return EFI_ABORTED;
    }

    if (Mps->Mm.StructVersion != MM_MEMORY_PROTECTION_SETTINGS_CURRENT_VERSION) {
      DEBUG ((
        DEBUG_ERROR,
        "%a: - Version number of the MM Memory Protection Settings is invalid!\n",
        __func__
        ));
      ASSERT (Mps->Mm.StructVersion == MM_MEMORY_PROTECTION_SETTINGS_CURRENT_VERSION);
      return EFI_ABORTED;
    }

    if (!EFI_ERROR (DxeMemoryProtectionSettingsConsistencyCheck (Mps)) &&
        !EFI_ERROR (MmMemoryProtectionSettingsConsistencyCheck (Mps)))
    {
      gMps = Mps;
    }
  } else {
    DEBUG ((
      DEBUG_WARN,
      "%a: - Memory Protection Settings not found!\n",
      __func__
      ));
    return EFI_NOT_FOUND;
  }

  return EFI_SUCCESS;
}

/**
  Library constructor used to populate gMps global.

  @retval EFI_SUCCESS   Constructor always returns success;
**/
EFI_STATUS
EFIAPI
GetMemoryProtectionSettingsConstructor (
  VOID
  )
{
  PopulateMpsGlobal ();
  return EFI_SUCCESS;
}
