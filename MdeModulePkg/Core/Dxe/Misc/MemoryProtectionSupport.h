/** @file
  Functionality supporting the updated Project Mu memory protections

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _MEMORY_PROTECTION_SUPPORT_H_
#define _MEMORY_PROTECTION_SUPPORT_H_

#include "DxeMain.h"
#include "Mem/HeapGuard.h"
#include <Protocol/MemoryProtectionSpecialRegionProtocol.h>

#define DO_NOT_PROTECT                 0x00000000
#define PROTECT_IF_ALIGNED_ELSE_ALLOW  0x00000001
#define PROTECT_ELSE_RAISE_ERROR       0x00000002

#define PROTECTED_IMAGE_PRIVATE_DATA_SIGNATURE                 SIGNATURE_32 ('P','I','P','D')
#define NONPROTECTED_IMAGE_PRIVATE_DATA_SIGNATURE              SIGNATURE_32 ('N','I','P','D')
#define MEMORY_PROTECTION_SPECIAL_REGION_LIST_ENTRY_SIGNATURE  SIGNATURE_32 ('M','P','S','R')

typedef struct {
  UINT32        Signature;
  UINTN         NonProtectedImageCount;
  LIST_ENTRY    NonProtectedImageList;
} NONPROTECTED_IMAGES_PRIVATE_DATA;

#define PREVIOUS_MEMORY_DESCRIPTOR(MemoryDescriptor, Size) \
  ((EFI_MEMORY_DESCRIPTOR *)((UINT8 *)(MemoryDescriptor) - (Size)))

#define IsCodeType(a)  ((a == EfiLoaderCode) || (a == EfiBootServicesCode) || (a == EfiRuntimeServicesCode))
#define IsDataType(a)  ((a == EfiLoaderData) || (a == EfiBootServicesData) || (a == EfiRuntimeServicesData))

typedef struct {
  UINT32        Signature;
  UINTN         ImageRecordCount;
  UINTN         CodeSegmentCountMax;
  LIST_ENTRY    ImageRecordList;
} PROTECTED_IMAGES_PRIVATE_DATA;

typedef struct {
  UINT32                              Signature;
  MEMORY_PROTECTION_SPECIAL_REGION    SpecialRegion;
  LIST_ENTRY                          Link;
} MEMORY_PROTECTION_SPECIAL_REGION_LIST_ENTRY;

typedef struct {
  UINTN         Count;
  LIST_ENTRY    SpecialRegionList;
} MEMORY_PROTECTION_SPECIAL_REGION_PRIVATE_LIST_HEAD;

/**
  A notification for CPU_ARCH protocol.

  @param[in]  Event                 Event whose notification function is being invoked.
  @param[in]  Context               Pointer to the notification function's context,
                                    which is implementation-dependent.
**/
VOID
EFIAPI
MemoryProtectionCpuArchProtocolNotify (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  );

/**
  Sets the NX compatibility global to FALSE so future checks to
  IsSystemNxCompatible() will return FALSE.
**/
VOID
EFIAPI
TurnOffNxCompatibility (
  VOID
  );

/**
  Returns TRUE if TurnOffNxCompatibility() has never been called.
**/
BOOLEAN
EFIAPI
IsSystemNxCompatible (
  VOID
  );

#endif
