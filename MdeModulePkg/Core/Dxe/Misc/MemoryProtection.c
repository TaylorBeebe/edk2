/** @file
  UEFI Memory Protection support.

  If the UEFI image is page aligned, the image code section is set to read only
  and the image data section is set to non-executable.

  1) This policy is applied for all UEFI image including boot service driver,
     runtime driver or application.
  2) This policy is applied only if the UEFI image meets the page alignment
     requirement.
  3) This policy is applied only if the Source UEFI image matches the
     Image Protection Policy definition.
  4) This policy is not applied to the non-PE image region.

  The DxeCore calls CpuArchProtocol->SetMemoryAttributes() to protect
  the image. If the CpuArch protocol is not installed yet, the DxeCore
  enqueues the protection request. Once the CpuArch is installed, the
  DxeCore dequeues the protection request and applies policy.

  Once the image is unloaded, the protection is removed automatically.

Copyright (c) 2017 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiDxe.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiLib.h>

#include <Guid/EventGroup.h>
#include <Guid/MemoryAttributesTable.h>

#include <Protocol/FirmwareVolume2.h>
#include <Protocol/SimpleFileSystem.h>

#include "DxeMain.h"
#include "Mem/HeapGuard.h"
#include "MemoryProtectionSupport.h"

//
// Image type definitions
//
#define IMAGE_UNKNOWN  0x00000001
#define IMAGE_FROM_FV  0x00000002

#define MEMORY_TYPE_OS_RESERVED_MIN   0x80000000
#define MEMORY_TYPE_OEM_RESERVED_MIN  0x70000000

#define PREVIOUS_MEMORY_DESCRIPTOR(MemoryDescriptor, Size) \
  ((EFI_MEMORY_DESCRIPTOR *)((UINT8 *)(MemoryDescriptor) - (Size)))

extern LIST_ENTRY  mGcdMemorySpaceMap;

/**
  Check if code section in image record is valid.

  @param  ImageRecord    image record to be checked

  @retval TRUE  image record is valid
  @retval FALSE image record is invalid
**/
BOOLEAN
IsImageRecordCodeSectionValid (
  IN IMAGE_PROPERTIES_RECORD  *ImageRecord
  );

/**
  Get the image type.

  @param[in]    File       This is a pointer to the device path of the file that is
                           being dispatched.

  @return UINT32           Image Type
**/
UINT32
GetImageType (
  IN  CONST EFI_DEVICE_PATH_PROTOCOL  *File
  )
{
  EFI_STATUS                Status;
  EFI_HANDLE                DeviceHandle;
  EFI_DEVICE_PATH_PROTOCOL  *TempDevicePath;

  if (File == NULL) {
    return IMAGE_UNKNOWN;
  }

  //
  // First check to see if File is from a Firmware Volume
  //
  DeviceHandle   = NULL;
  TempDevicePath = (EFI_DEVICE_PATH_PROTOCOL *)File;
  Status         = gBS->LocateDevicePath (
                          &gEfiFirmwareVolume2ProtocolGuid,
                          &TempDevicePath,
                          &DeviceHandle
                          );
  if (!EFI_ERROR (Status)) {
    Status = gBS->OpenProtocol (
                    DeviceHandle,
                    &gEfiFirmwareVolume2ProtocolGuid,
                    NULL,
                    NULL,
                    NULL,
                    EFI_OPEN_PROTOCOL_TEST_PROTOCOL
                    );
    if (!EFI_ERROR (Status)) {
      return IMAGE_FROM_FV;
    }
  }

  return IMAGE_UNKNOWN;
}

/**
  Get UEFI image protection policy based upon image type.

  @param[in]  ImageType    The UEFI image type

  @return UEFI image protection policy
**/
UINT32
GetProtectionPolicyFromImageType (
  IN UINT32  ImageType
  )
{
  if (((ImageType == IMAGE_UNKNOWN) && gDxeMps.ImageProtectionPolicy.Fields.ProtectImageFromUnknown) ||
      ((ImageType == IMAGE_FROM_FV) && gDxeMps.ImageProtectionPolicy.Fields.ProtectImageFromFv))
  {
    if (gDxeMps.ImageProtectionPolicy.Fields.RaiseErrorIfProtectionFails) {
      return PROTECT_ELSE_RAISE_ERROR;
    }

    return PROTECT_IF_ALIGNED_ELSE_ALLOW;
  } else {
    return DO_NOT_PROTECT;
  }
}

/**
  Fetches a pointer to the DXE memory protection settings HOB.
**/
DXE_MEMORY_PROTECTION_SETTINGS *
EFIAPI
GetDxeMemoryProtectionSettings (
  VOID
  )
{
  VOID  *Ptr;

  Ptr = GetFirstGuidHob (&gDxeMemoryProtectionSettingsGuid);
  if (Ptr != NULL) {
    if (*((UINT8 *)GET_GUID_HOB_DATA (Ptr)) == (UINT8)DXE_MEMORY_PROTECTION_SETTINGS_CURRENT_VERSION) {
      return (DXE_MEMORY_PROTECTION_SETTINGS *)GET_GUID_HOB_DATA (Ptr);
    }
  }

  return NULL;
}

/**
  Get UEFI image protection policy based upon loaded image device path.

  @param[in]  LoadedImage              The loaded image protocol
  @param[in]  LoadedImageDevicePath    The loaded image device path protocol

  @return UEFI image protection policy
**/
UINT32
GetUefiImageProtectionPolicy (
  IN EFI_LOADED_IMAGE_PROTOCOL  *LoadedImage,
  IN EFI_DEVICE_PATH_PROTOCOL   *LoadedImageDevicePath
  )
{
  BOOLEAN                         InSmm;
  UINT32                          ImageType;
  UINT32                          ProtectionPolicy;
  DXE_MEMORY_PROTECTION_SETTINGS  *Settings = NULL;

  //
  // Check SMM
  //
  InSmm = FALSE;
  if (gSmmBase2 != NULL) {
    gSmmBase2->InSmm (gSmmBase2, &InSmm);
  }

  if (InSmm) {
    return FALSE;
  }

  //
  // Check DevicePath
  //
  if (LoadedImage == gDxeCoreLoadedImage) {
    // If the image is DxeCore, DxeMemoryProtectionHobLib entry point has not
    // yet executed and so gDxeMps is not yet valid. Get the memory protection
    // HOB directly and check if DxeCore should be protected.
    Settings = GetDxeMemoryProtectionSettings ();

    if (Settings != NULL) {
      if (Settings->ImageProtectionPolicy.Fields.ProtectImageFromFv == 1) {
        if (Settings->ImageProtectionPolicy.Fields.RaiseErrorIfProtectionFails == 1) {
          return PROTECT_ELSE_RAISE_ERROR;
        }

        return PROTECT_IF_ALIGNED_ELSE_ALLOW;
      }
    }

    ImageType = IMAGE_FROM_FV;
  } else {
    ImageType = GetImageType (LoadedImageDevicePath);
  }

  ProtectionPolicy = GetProtectionPolicyFromImageType (ImageType);
  return ProtectionPolicy;
}

/**
  Set UEFI image memory attributes.

  @param[in]  BaseAddress            Specified start address
  @param[in]  Length                 Specified length
  @param[in]  Attributes             Specified attributes
**/
VOID
SetUefiImageMemoryAttributes (
  IN UINT64  BaseAddress,
  IN UINT64  Length,
  IN UINT64  Attributes
  )
{
  EFI_STATUS                       Status;
  EFI_GCD_MEMORY_SPACE_DESCRIPTOR  Descriptor;
  UINT64                           FinalAttributes;

  Status = CoreGetMemorySpaceDescriptor (BaseAddress, &Descriptor);
  ASSERT_EFI_ERROR (Status);

  FinalAttributes = (Descriptor.Attributes & EFI_CACHE_ATTRIBUTE_MASK) | (Attributes & EFI_MEMORY_ATTRIBUTE_MASK);

  DEBUG ((DEBUG_INFO, "SetUefiImageMemoryAttributes - 0x%016lx - 0x%016lx (0x%016lx)\n", BaseAddress, Length, FinalAttributes));

  ASSERT (gCpu != NULL);
  gCpu->SetMemoryAttributes (gCpu, BaseAddress, Length, FinalAttributes);
}

/**
  Set UEFI image protection attributes.

  @param[in]  ImageRecord    A UEFI image record
**/
VOID
SetUefiImageProtectionAttributes (
  IN IMAGE_PROPERTIES_RECORD  *ImageRecord
  )
{
  IMAGE_PROPERTIES_RECORD_CODE_SECTION  *ImageRecordCodeSection;
  LIST_ENTRY                            *ImageRecordCodeSectionLink;
  LIST_ENTRY                            *ImageRecordCodeSectionEndLink;
  LIST_ENTRY                            *ImageRecordCodeSectionList;
  UINT64                                CurrentBase;
  UINT64                                ImageEnd;

  ImageRecordCodeSectionList = &ImageRecord->CodeSegmentList;

  CurrentBase = ImageRecord->ImageBase;
  ImageEnd    = ImageRecord->ImageBase + ImageRecord->ImageSize;

  ImageRecordCodeSectionLink    = ImageRecordCodeSectionList->ForwardLink;
  ImageRecordCodeSectionEndLink = ImageRecordCodeSectionList;
  while (ImageRecordCodeSectionLink != ImageRecordCodeSectionEndLink) {
    ImageRecordCodeSection = CR (
                               ImageRecordCodeSectionLink,
                               IMAGE_PROPERTIES_RECORD_CODE_SECTION,
                               Link,
                               IMAGE_PROPERTIES_RECORD_CODE_SECTION_SIGNATURE
                               );
    ImageRecordCodeSectionLink = ImageRecordCodeSectionLink->ForwardLink;

    ASSERT (CurrentBase <= ImageRecordCodeSection->CodeSegmentBase);
    if (CurrentBase < ImageRecordCodeSection->CodeSegmentBase) {
      //
      // DATA
      //
      SetUefiImageMemoryAttributes (
        CurrentBase,
        ImageRecordCodeSection->CodeSegmentBase - CurrentBase,
        EFI_MEMORY_XP
        );
    }

    //
    // CODE
    //
    SetUefiImageMemoryAttributes (
      ImageRecordCodeSection->CodeSegmentBase,
      ImageRecordCodeSection->CodeSegmentSize,
      EFI_MEMORY_RO
      );
    CurrentBase = ImageRecordCodeSection->CodeSegmentBase + ImageRecordCodeSection->CodeSegmentSize;
  }

  //
  // Last DATA
  //
  ASSERT (CurrentBase <= ImageEnd);
  if (CurrentBase < ImageEnd) {
    //
    // DATA
    //
    SetUefiImageMemoryAttributes (
      CurrentBase,
      ImageEnd - CurrentBase,
      EFI_MEMORY_XP
      );
  }

  return;
}

/**
  Return if the PE image section is aligned.

  @param[in]  SectionAlignment    PE/COFF section alignment
  @param[in]  MemoryType          PE/COFF image memory type

  @retval TRUE  The PE image section is aligned.
  @retval FALSE The PE image section is not aligned.
**/
BOOLEAN
IsMemoryProtectionSectionAligned (
  IN UINT32           SectionAlignment,
  IN EFI_MEMORY_TYPE  MemoryType
  )
{
  UINT32  PageAlignment;

  switch (MemoryType) {
    case EfiRuntimeServicesCode:
    case EfiACPIMemoryNVS:
      PageAlignment = RUNTIME_PAGE_ALLOCATION_GRANULARITY;
      break;
    case EfiRuntimeServicesData:
    case EfiACPIReclaimMemory:
      ASSERT (FALSE);
      PageAlignment = RUNTIME_PAGE_ALLOCATION_GRANULARITY;
      break;
    case EfiBootServicesCode:
    case EfiLoaderCode:
    case EfiReservedMemoryType:
      PageAlignment = EFI_PAGE_SIZE;
      break;
    default:
      ASSERT (FALSE);
      PageAlignment = EFI_PAGE_SIZE;
      break;
  }

  if ((SectionAlignment & (PageAlignment - 1)) != 0) {
    return FALSE;
  } else {
    return TRUE;
  }
}

/**
  Free Image record.

  @param[in]  ImageRecord    A UEFI image record
**/
VOID
FreeImageRecord (
  IN IMAGE_PROPERTIES_RECORD  *ImageRecord
  )
{
  LIST_ENTRY                            *CodeSegmentListHead;
  IMAGE_PROPERTIES_RECORD_CODE_SECTION  *ImageRecordCodeSection;

  CodeSegmentListHead = &ImageRecord->CodeSegmentList;
  while (!IsListEmpty (CodeSegmentListHead)) {
    ImageRecordCodeSection = CR (
                               CodeSegmentListHead->ForwardLink,
                               IMAGE_PROPERTIES_RECORD_CODE_SECTION,
                               Link,
                               IMAGE_PROPERTIES_RECORD_CODE_SECTION_SIGNATURE
                               );
    RemoveEntryList (&ImageRecordCodeSection->Link);
    FreePool (ImageRecordCodeSection);
  }

  if (ImageRecord->Link.ForwardLink != NULL) {
    RemoveEntryList (&ImageRecord->Link);
  }

  FreePool (ImageRecord);
}

/**
  Return the EFI memory permission attribute associated with memory
  type 'MemoryType' under the configured DXE memory protection policy.

  @param MemoryType       Memory type.
**/
UINT64
GetPermissionAttributeForMemoryType (
  IN EFI_MEMORY_TYPE  MemoryType
  )
{
  // Handle code allocations according to the NX_COMPAT DLL flag. If the flag is
  // set, the image should update the attributes of code type allocates when it's ready to execute them.
  if (IsCodeType (MemoryType) && !IsSystemNxCompatible ()) {
    return 0;
  } else if (GetDxeMemoryTypeSettingFromBitfield (MemoryType, gDxeMps.NxProtectionPolicy)) {
    return EFI_MEMORY_XP;
  }

  return 0;
}

/**
  Sort memory map entries based upon PhysicalStart, from low to high.

  @param  MemoryMap              A pointer to the buffer in which firmware places
                                 the current memory map.
  @param  MemoryMapSize          Size, in bytes, of the MemoryMap buffer.
  @param  DescriptorSize         Size, in bytes, of an individual EFI_MEMORY_DESCRIPTOR.
**/
VOID
SortMemoryMap (
  IN OUT EFI_MEMORY_DESCRIPTOR  *MemoryMap,
  IN UINTN                      MemoryMapSize,
  IN UINTN                      DescriptorSize
  )
{
  EFI_MEMORY_DESCRIPTOR  *MemoryMapEntry;
  EFI_MEMORY_DESCRIPTOR  *NextMemoryMapEntry;
  EFI_MEMORY_DESCRIPTOR  *MemoryMapEnd;
  EFI_MEMORY_DESCRIPTOR  TempMemoryMap;

  MemoryMapEntry     = MemoryMap;
  NextMemoryMapEntry = NEXT_MEMORY_DESCRIPTOR (MemoryMapEntry, DescriptorSize);
  MemoryMapEnd       = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)MemoryMap + MemoryMapSize);
  while (MemoryMapEntry < MemoryMapEnd) {
    while (NextMemoryMapEntry < MemoryMapEnd) {
      if (MemoryMapEntry->PhysicalStart > NextMemoryMapEntry->PhysicalStart) {
        CopyMem (&TempMemoryMap, MemoryMapEntry, sizeof (EFI_MEMORY_DESCRIPTOR));
        CopyMem (MemoryMapEntry, NextMemoryMapEntry, sizeof (EFI_MEMORY_DESCRIPTOR));
        CopyMem (NextMemoryMapEntry, &TempMemoryMap, sizeof (EFI_MEMORY_DESCRIPTOR));
      }

      NextMemoryMapEntry = NEXT_MEMORY_DESCRIPTOR (NextMemoryMapEntry, DescriptorSize);
    }

    MemoryMapEntry     = NEXT_MEMORY_DESCRIPTOR (MemoryMapEntry, DescriptorSize);
    NextMemoryMapEntry = NEXT_MEMORY_DESCRIPTOR (MemoryMapEntry, DescriptorSize);
  }
}

/**
  Merge adjacent memory map entries if they use the same memory protection policy

  @param[in, out]  MemoryMap              A pointer to the buffer in which firmware places
                                          the current memory map.
  @param[in, out]  MemoryMapSize          A pointer to the size, in bytes, of the
                                          MemoryMap buffer. On input, this is the size of
                                          the current memory map.  On output,
                                          it is the size of new memory map after merge.
  @param[in]       DescriptorSize         Size, in bytes, of an individual EFI_MEMORY_DESCRIPTOR.
**/
VOID
MergeMemoryMapForProtectionPolicy (
  IN OUT EFI_MEMORY_DESCRIPTOR  *MemoryMap,
  IN OUT UINTN                  *MemoryMapSize,
  IN UINTN                      DescriptorSize
  )
{
  EFI_MEMORY_DESCRIPTOR  *MemoryMapEntry;
  EFI_MEMORY_DESCRIPTOR  *MemoryMapEnd;
  UINT64                 MemoryBlockLength;
  EFI_MEMORY_DESCRIPTOR  *NewMemoryMapEntry;
  EFI_MEMORY_DESCRIPTOR  *NextMemoryMapEntry;
  UINT64                 Attributes;

  SortMemoryMap (MemoryMap, *MemoryMapSize, DescriptorSize);

  MemoryMapEntry    = MemoryMap;
  NewMemoryMapEntry = MemoryMap;
  MemoryMapEnd      = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)MemoryMap + *MemoryMapSize);
  while ((UINTN)MemoryMapEntry < (UINTN)MemoryMapEnd) {
    CopyMem (NewMemoryMapEntry, MemoryMapEntry, sizeof (EFI_MEMORY_DESCRIPTOR));
    NextMemoryMapEntry = NEXT_MEMORY_DESCRIPTOR (MemoryMapEntry, DescriptorSize);

    do {
      MemoryBlockLength = (UINT64)(EFI_PAGES_TO_SIZE ((UINTN)MemoryMapEntry->NumberOfPages));
      Attributes        = GetPermissionAttributeForMemoryType (MemoryMapEntry->Type);

      if (((UINTN)NextMemoryMapEntry < (UINTN)MemoryMapEnd) &&
          (Attributes == GetPermissionAttributeForMemoryType (NextMemoryMapEntry->Type)) &&
          ((MemoryMapEntry->PhysicalStart + MemoryBlockLength) == NextMemoryMapEntry->PhysicalStart))
      {
        MemoryMapEntry->NumberOfPages += NextMemoryMapEntry->NumberOfPages;
        if (NewMemoryMapEntry != MemoryMapEntry) {
          NewMemoryMapEntry->NumberOfPages += NextMemoryMapEntry->NumberOfPages;
        }

        NextMemoryMapEntry = NEXT_MEMORY_DESCRIPTOR (NextMemoryMapEntry, DescriptorSize);
        continue;
      } else {
        MemoryMapEntry = PREVIOUS_MEMORY_DESCRIPTOR (NextMemoryMapEntry, DescriptorSize);
        break;
      }
    } while (TRUE);

    MemoryMapEntry    = NEXT_MEMORY_DESCRIPTOR (MemoryMapEntry, DescriptorSize);
    NewMemoryMapEntry = NEXT_MEMORY_DESCRIPTOR (NewMemoryMapEntry, DescriptorSize);
  }

  *MemoryMapSize = (UINTN)NewMemoryMapEntry - (UINTN)MemoryMap;

  return;
}

/**
  ExitBootServices Callback function for memory protection.
**/
VOID
MemoryProtectionExitBootServicesCallback (
  VOID
  )
{
  EFI_RUNTIME_IMAGE_ENTRY  *RuntimeImage;
  LIST_ENTRY               *Link;

  //
  // We need remove the RT protection, because RT relocation need write code segment
  // at SetVirtualAddressMap(). We cannot assume OS/Loader has taken over page table at that time.
  //
  // Firmware does not own page tables after ExitBootServices(), so the OS would
  // have to relax protection of RT code pages across SetVirtualAddressMap(), or
  // delay setting protections on RT code pages until after SetVirtualAddressMap().
  // OS may set protection on RT based upon EFI_MEMORY_ATTRIBUTES_TABLE later.
  //
  if (gDxeMps.ImageProtectionPolicy.Data) {
    for (Link = gRuntime->ImageHead.ForwardLink; Link != &gRuntime->ImageHead; Link = Link->ForwardLink) {
      RuntimeImage = BASE_CR (Link, EFI_RUNTIME_IMAGE_ENTRY, Link);
      SetUefiImageMemoryAttributes ((UINT64)(UINTN)RuntimeImage->ImageBase, ALIGN_VALUE (RuntimeImage->ImageSize, EFI_PAGE_SIZE), 0);
    }
  }
}

/**
  Initialize Memory Protection support.
**/
VOID
EFIAPI
CoreInitializeMemoryProtection (
  VOID
  )
{
  EFI_STATUS  Status;
  EFI_EVENT   Event;
  VOID        *Registration;

  //
  // Sanity check the Image Protection Policy setting:
  // - EfiConventionalMemory and EfiBootServicesData should use the
  //   same attribute
  //
  ASSERT (
    GetPermissionAttributeForMemoryType (EfiBootServicesData) ==
    GetPermissionAttributeForMemoryType (EfiConventionalMemory)
    );

  Status = CoreCreateEvent (
             EVT_NOTIFY_SIGNAL,
             TPL_CALLBACK,
             MemoryProtectionCpuArchProtocolNotify,
             NULL,
             &Event
             );
  ASSERT_EFI_ERROR (Status);

  //
  // Register for protocol notifactions on this event
  //
  Status = CoreRegisterProtocolNotify (
             &gEfiCpuArchProtocolGuid,
             Event,
             &Registration
             );
  ASSERT_EFI_ERROR (Status);

  return;
}

/**
  Returns whether we are currently executing in SMM mode.
**/
STATIC
BOOLEAN
IsInSmm (
  VOID
  )
{
  BOOLEAN  InSmm;

  InSmm = FALSE;
  if (gSmmBase2 != NULL) {
    gSmmBase2->InSmm (gSmmBase2, &InSmm);
  }

  return InSmm;
}

/**
  Manage memory permission attributes on a memory range, according to the
  configured DXE memory protection policy.

  @param  OldType           The old memory type of the range
  @param  NewType           The new memory type of the range
  @param  Memory            The base address of the range
  @param  Length            The size of the range (in bytes)

  @return EFI_SUCCESS       If we are executing in SMM mode. No permission attributes
                            are updated in this case
  @return EFI_SUCCESS       If the the CPU arch protocol is not installed yet
  @return EFI_SUCCESS       If no DXE memory protection policy has been configured
  @return EFI_SUCCESS       If OldType and NewType use the same permission attributes
  @return other             Return value of gCpu->SetMemoryAttributes()

**/
EFI_STATUS
EFIAPI
ApplyMemoryProtectionPolicy (
  IN  EFI_MEMORY_TYPE       OldType,
  IN  EFI_MEMORY_TYPE       NewType,
  IN  EFI_PHYSICAL_ADDRESS  Memory,
  IN  UINT64                Length
  )
{
  UINT64  OldAttributes;
  UINT64  NewAttributes;

  //
  // The policy configured in DXE NX Protection Policy
  // does not apply to allocations performed in SMM mode.
  //
  if (IsInSmm ()) {
    return EFI_SUCCESS;
  }

  //
  // If the CPU arch protocol is not installed yet, we cannot manage memory
  // permission attributes, and it is the job of the driver that installs this
  // protocol to set the permissions on existing allocations.
  //
  if (gCpu == NULL) {
    return EFI_SUCCESS;
  }

  //
  // Check if a DXE memory protection policy has been configured
  //
  if (!gDxeMps.NxProtectionPolicy.Data) {
    return EFI_SUCCESS;
  }

  //
  // Don't overwrite Guard pages, which should be the first and/or last page,
  // if any.
  //
  if (IsHeapGuardEnabled (GUARD_HEAP_TYPE_PAGE|GUARD_HEAP_TYPE_POOL)) {
    if (IsGuardPage (Memory)) {
      Memory += EFI_PAGE_SIZE;
      Length -= EFI_PAGE_SIZE;
      if (Length == 0) {
        return EFI_SUCCESS;
      }
    }

    if (IsGuardPage (Memory + Length - EFI_PAGE_SIZE)) {
      Length -= EFI_PAGE_SIZE;
      if (Length == 0) {
        return EFI_SUCCESS;
      }
    }
  }

  //
  // Update the executable permissions according to the DXE memory
  // protection policy, but only if
  // - the policy is different between the old and the new type, or
  // - this is a newly added region (OldType == EfiMaxMemoryType)
  //
  NewAttributes = GetPermissionAttributeForMemoryType (NewType);

  if (OldType != EfiMaxMemoryType) {
    OldAttributes = GetPermissionAttributeForMemoryType (OldType);
    if (OldAttributes == NewAttributes) {
      // policy is the same between OldType and NewType
      return EFI_SUCCESS;
    }
  } else if (NewAttributes == 0) {
    // newly added region of a type that does not require protection
    return EFI_SUCCESS;
  }

  return gCpu->SetMemoryAttributes (gCpu, Memory, Length, NewAttributes);
}
