/* TODO:
 *  - no variable values are cached; can we do better?
 *  - bs-only varibles should not be enumerated at runtime
 *    - confirmed by looking at FindVariableEx() in MdeModulePkg/Universal/Variable/RuntimeDxe/VariableParsing.c
 *    - on real BIOSes they are enumerated, though
 *  - OVMF fails to return attributes in response to GetVariable()
 *  - add signature to runtime driver list
 *    - also, get rid of linked list
 *  - other options to enumerate runtime drivers
 *    - scan EfiRuntimeServicesCode memory regions
 *    - utilize PI 2.0 gEfiRuntimeArchProtocolGuid
 */
#include <Uefi.h>

#include <Pi/PiFirmwareVolume.h>
#include <Pi/PiFirmwareFile.h>
#include <Protocol/FirmwareVolume2.h>

#include <Protocol/LoadedImage.h>
#include <Protocol/DevicePath.h>
#include <Protocol/SerialIo.h>
#include <Protocol/DriverBinding.h>

#include <Library/BaseLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/DevicePathLib.h>
#include <Library/UefiRuntimeLib.h>
#include <Library/MemoryAllocationLib.h>

#include <Guid/EventGroup.h>

/* 36367830-00f2-40fe-ad6f-2dd73c64a646 */
static EFI_GUID MyProtocolGuid = {
  0x36367830,
  0x00f2,
  0x40fe,
  { 0xad, 0x6f, 0x2d, 0xd7, 0x3c, 0x64, 0xa6, 0x46 }
};

/* f08ae394-4e98-46e6-b3b0-1bb940ac663d */
static EFI_GUID MyVendorGuid = {
  0xf08ae394,
  0x4e98,
  0x46e6,
  { 0xb3, 0xb0, 0x1b, 0xb9, 0x40, 0xac, 0x66, 0x3d }
};

typedef struct _LOADED_IMAGE LOADED_IMAGE, *PLOADED_IMAGE;

/* 'RTModule' */
#define RTMODULE_SIGNATURE \
  SIGNATURE_64('R', 'T', 'M', 'o', 'd', 'u', 'l', 'e')

#pragma pack(push, 1)

struct _LOADED_IMAGE {
  UINT64 Signature;
  PLOADED_IMAGE Next;
  VOID *ImageBase;
  VOID *ImageBaseVirtual;
  UINT64 ImageSize;
  EFI_MEMORY_TYPE ImageCodeType;
  EFI_MEMORY_TYPE ImageDataType;
  CHAR16 DevicePath[256];
  CHAR16 ModuleName[256];
};

#pragma pack(pop)

static PLOADED_IMAGE LoadedImages = NULL;

static EFI_SET_VARIABLE OriginalSetVariable = NULL;

#define MAX_VAR_NAME 2048

#pragma pack(push, 1)

typedef struct _FW_VAR FW_VAR, *PFW_VAR;

struct _FW_VAR {
  EFI_GUID  Guid;
  UINT32    Attributes;
  CHAR16    Name[MAX_VAR_NAME];
};

typedef struct _FW_VAR_POOL FW_VAR_POOL, *PFW_VAR_POOL;

/* 'FWVARPOO' */
#define FW_VAR_POOL_SIGNATURE \
  SIGNATURE_64('F', 'W', 'V', 'A', 'R', 'P', 'O', 'O')

struct _FW_VAR_POOL {
  UINT64    Signature;
  UINT64    Count;
  FW_VAR    Objects[2048];
};

#pragma pack(pop)

//
// Virtual pointers to variable storage
//
static PFW_VAR_POOL FwVars = NULL;
static PFW_VAR_POOL FwVars2 = NULL;

#define MAX_MEMORY_MAP 256

/* 'FWMEMMAP' */
#define FW_MMAP_SIGNATURE \
  SIGNATURE_64('F', 'W', 'M', 'E', 'M', 'M', 'A', 'P')

#pragma pack (push, 1)

typedef struct _FW_MMAPE {
  UINT32 Type;
  UINT64 PhysicalStart;
  UINT64 VirtualStart;
  UINT64 NumberOf4KPages;
  UINT64 Attributes;
} FW_MMAPE, *PFW_MMAPE;

typedef struct _FW_MMAP {
  UINT64    Signature;
  UINT64    Count;
  FW_MMAPE  MMap[MAX_MEMORY_MAP];
} FW_MMAP, *PFW_MMAP;

#pragma pack (pop)

static PFW_MMAP FwMemoryMap = NULL;
static EFI_MEMORY_DESCRIPTOR FwMemoryMapScratchBuffer[1024];

EFI_STATUS
EFIAPI
Supported (
  IN EFI_DRIVER_BINDING_PROTOCOL   *This,
  IN EFI_HANDLE                    Controller,
  IN EFI_DEVICE_PATH_PROTOCOL      *RemainingDevicePath
  );

EFI_STATUS
EFIAPI
Start (
  IN EFI_DRIVER_BINDING_PROTOCOL   *This,
  IN EFI_HANDLE                    Controller,
  IN EFI_DEVICE_PATH_PROTOCOL      *RemainingDevicePath
  );

EFI_STATUS
EFIAPI
Stop (
  IN  EFI_DRIVER_BINDING_PROTOCOL     *This,
  IN  EFI_HANDLE                      Controller,
  IN  UINTN                           NumberOfChildren,
  IN  EFI_HANDLE                      *ChildHandleBuffer
  );

static EFI_DRIVER_BINDING_PROTOCOL DriverBinding = {
  Supported,
  Start,
  Stop,
  0xa,
  NULL,
  NULL
};

EFI_STATUS
AllocateFwMemoryMap (PFW_MMAP *MemoryMap)
{
  EFI_STATUS Status;
  EFI_PHYSICAL_ADDRESS PoolAddress = 0;

  Status = gBS->AllocatePages(
                  AllocateAnyPages,
                  EfiRuntimeServicesData,
                  EFI_SIZE_TO_PAGES(sizeof(FW_MMAP)),
                  &PoolAddress
                  );
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "AllocatePages(FwMmap) returned %r\n", Status));
    return Status;
  }

  *MemoryMap = (PFW_MMAP)(UINTN)PoolAddress;
  ZeroMem(*MemoryMap, sizeof(FW_MMAP));
  (*MemoryMap)->Signature = FW_MMAP_SIGNATURE;
  return EFI_SUCCESS;
}

EFI_STATUS
CopyMemoryMap (PFW_MMAP MemoryMap)
{
  EFI_STATUS            Status;
  UINTN                 MemoryMapSize = sizeof(FwMemoryMapScratchBuffer);
  UINTN                 MapKey;
  UINTN                 DescriptorSize = 0;
  UINT32                DescriptorVersion = 0;
  UINTN                 Index;
  EFI_MEMORY_DESCRIPTOR *Descriptor;
  UINT8                 *ScratchPointer = (UINT8 *) FwMemoryMapScratchBuffer;
  PFW_MMAPE             MapEntry;

  MemoryMapSize = 0;
  Status = gBS->GetMemoryMap (
                  &MemoryMapSize,
                  NULL,
                  &MapKey,
                  &DescriptorSize,
                  &DescriptorVersion
                  );
  if (EFI_ERROR(Status)) {
    if (Status != EFI_BUFFER_TOO_SMALL) {
      return Status;
    }
  }

  if (MemoryMapSize > sizeof(FwMemoryMapScratchBuffer)) {
    return EFI_UNSUPPORTED;
  }

  Status = gBS->GetMemoryMap (
                  &MemoryMapSize,
                  FwMemoryMapScratchBuffer,
                  &MapKey,
                  &DescriptorSize,
                  &DescriptorVersion
                  );
  if (EFI_ERROR(Status)) {
    return Status;
  }

  for (Index = 0; Index < MAX_MEMORY_MAP; ScratchPointer += DescriptorSize) {
    Descriptor = (EFI_MEMORY_DESCRIPTOR *) ScratchPointer;
    if (ScratchPointer >= (UINT8 *) FwMemoryMapScratchBuffer + MemoryMapSize) {
      break;
    }
    switch (Descriptor->Type) {
      case EfiReservedMemoryType:
      case EfiRuntimeServicesData:
      case EfiRuntimeServicesCode:
      case EfiMemoryMappedIO:
      case EfiACPIMemoryNVS:
        MapEntry = &MemoryMap->MMap[Index];
        MapEntry->Type              = Descriptor->Type;
        MapEntry->Attributes        = Descriptor->Attribute;
        MapEntry->PhysicalStart     = Descriptor->PhysicalStart;
        MapEntry->VirtualStart      = Descriptor->VirtualStart;
        MapEntry->NumberOf4KPages   = Descriptor->NumberOfPages;
        Index++;
        break;
    }
  }

  MemoryMap->Count = Index;

  return EFI_SUCCESS;
}

EFI_STATUS
AllocateFwVarsPool (PFW_VAR_POOL *Pool)
{
  EFI_STATUS Status;
  EFI_PHYSICAL_ADDRESS PoolAddress = 0;

  Status = gBS->AllocatePages(
                  AllocateAnyPages,
                  EfiRuntimeServicesData,
                  EFI_SIZE_TO_PAGES(sizeof(FW_VAR_POOL)),
                  &PoolAddress
                  );
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "AllocatePages(FwVars) returned %r\n", Status));
    return Status;
  }

  *Pool = (PFW_VAR_POOL)(UINTN)PoolAddress;
  ZeroMem(*Pool, sizeof(FW_VAR_POOL));
  (*Pool)->Signature = FW_VAR_POOL_SIGNATURE;
  return EFI_SUCCESS;
}

PFW_VAR
AllocateFwVarFromPool (PFW_VAR_POOL Pool)
{
  PFW_VAR FwVar;

  if (Pool == NULL) {
    return NULL;
  }

  if (Pool->Count == ARRAY_SIZE(Pool->Objects)) {
    return NULL;
  }

  FwVar = &Pool->Objects[Pool->Count];
  Pool->Count += 1;
  return FwVar;
}

EFI_STATUS
FreeFwVar (PFW_VAR_POOL Pool, PFW_VAR FwVar)
{
  UINTN Index;
  UINTN RetainCount = 0;

  for (Index = 0; Index < Pool->Count; ++Index) {
    if (&Pool->Objects[Index] != FwVar) {
      if (Index != RetainCount) {
        Pool->Objects[RetainCount] = Pool->Objects[Index];
      }
      ++RetainCount;
    }
  }

  Pool->Count = RetainCount;

  return EFI_SUCCESS;
}

EFI_STATUS
UpdateVariableInVariableList (
  IN  PFW_VAR_POOL                 Pool,
  IN  CHAR16                       *VariableName,
  IN  EFI_GUID                     *VendorGuid,
  IN  UINT32                       Attributes,
  IN  UINTN                        DataSize
  )
{
  EFI_STATUS    Status;
  PFW_VAR       FwVar;
  UINTN         Index;
  BOOLEAN       Delete = FALSE;
  UINT32        UpdateAttributes =
    EFI_VARIABLE_APPEND_WRITE |
    EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS |
    EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;

  if (VariableName == NULL || VendorGuid == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Unless EFI_VARIABLE_APPEND_WRITE,
  // EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS, or
  // EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS is set,
  // using SetVariable() with a DataSize of zero will cause
  // the entire variable to be deleted.
  //
  if (DataSize == 0 && ((Attributes & UpdateAttributes) == 0)) {
    Delete = TRUE;
  }

  //
  // If a preexisting variable is rewritten with different
  // attributes, SetVariable() shall not modify the variable
  // and shall return EFI_INVALID_PARAMETER. Two exceptions
  // to this rule:
  // * No access attributes specified
  // * The only attribute differing is EFI_VARIABLE_APPEND_WRITE
  //

  if (Attributes == 0) {
    Delete = TRUE;
  }

  for (Index = 0; Index < Pool->Count; ++Index) {
    FwVar = &Pool->Objects[Index];
    if (CompareGuid(&FwVar->Guid, VendorGuid)) {
      if (StrCmp(FwVar->Name, VariableName) == 0) {
        break;
      }
    }
  }

  if (Delete) {
    if (Index < Pool->Count) {
      FreeFwVar(Pool, FwVar);
    }
  } else if (Index >= Pool->Count) {
    FwVar = AllocateFwVarFromPool(Pool);
    if (FwVar == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }
    ZeroMem(FwVar, sizeof(FW_VAR));
    Status = StrCpyS(FwVar->Name, MAX_VAR_NAME, VariableName);
    if (EFI_ERROR(Status)) {
      FreeFwVar(Pool, FwVar);
      return EFI_UNSUPPORTED;
    }
    FwVar->Guid = *VendorGuid;
    FwVar->Attributes = Attributes;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
RebuildVariableList (PFW_VAR_POOL Pool)
{
  EFI_STATUS    Status = EFI_SUCCESS;
  CHAR16        Name[MAX_VAR_NAME] = { CHAR_NULL };
  UINTN         NameSize;
  EFI_GUID      Guid;
  PFW_VAR       FwVar;
  UINTN         DataSize = 0;
  UINT32        Attributes = 0;
  UINT8         Data[1];

  if (Pool == NULL) {
    return EFI_UNSUPPORTED;
  }

  Pool->Count = 0;

  //
  // Note: Calls to SetVariable() between calls to
  // GetNextVariableName() may produce unpredictable results
  //
  for (;;) {
    DataSize = 0;
    Attributes = 0;
    NameSize = MAX_VAR_NAME;
    Status = gRT->GetNextVariableName (&NameSize, Name, &Guid);
    if (EFI_ERROR(Status)) {
      if (Status == EFI_NOT_FOUND) {
        break;
      } else {
        return Status;
      }
    }
    FwVar = AllocateFwVarFromPool(Pool);
    if (FwVar == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }
    ZeroMem(FwVar, sizeof(FW_VAR));
    FwVar->Guid = Guid;
    Status = StrCpyS (FwVar->Name, MAX_VAR_NAME, Name);
    ASSERT_EFI_ERROR(Status);
    Status = gRT->GetVariable (
                    Name,
                    &Guid,
                    &Attributes,
                    &DataSize,
                    Data
                    );
    if (!EFI_ERROR(Status) || EFI_BUFFER_TOO_SMALL == Status) {
      FwVar->Attributes = Attributes;
    }
  }
  return EFI_SUCCESS;
}

PLOADED_IMAGE
PushLoadedImage (VOID)
{
  EFI_STATUS            Status;
  PLOADED_IMAGE         Elem;
  EFI_PHYSICAL_ADDRESS  ElemAddress;

  Status = gBS->AllocatePages (
                  AllocateAnyPages,
                  EfiRuntimeServicesData,
                  EFI_SIZE_TO_PAGES(sizeof(LOADED_IMAGE)),
                  &ElemAddress
                  );
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "AllocatePages(LoadedImage) returned %r\n", Status));
    return NULL;
  }

  Elem = (PLOADED_IMAGE)(UINTN)ElemAddress;
  ZeroMem(Elem, sizeof(LOADED_IMAGE));
  Elem->Next = LoadedImages;
  Elem->Signature = RTMODULE_SIGNATURE;
  LoadedImages = Elem;

  return Elem;
}

VOID
RemoveLoadedImage (
  IN  PLOADED_IMAGE LoadedImage
  )
{
  PLOADED_IMAGE Elem = LoadedImages;
  PLOADED_IMAGE *Prev = &LoadedImages;
  while (Elem) {
    if (Elem == LoadedImage) {
      *Prev = Elem->Next;
      gBS->FreePages(
        (EFI_PHYSICAL_ADDRESS) LoadedImage,
        EFI_SIZE_TO_PAGES(sizeof(LOADED_IMAGE)));
      break;
    }
    Prev = &(Elem->Next);
    Elem = Elem->Next;
  }
}

EFI_STATUS
GatherDevicePath (
  IN  EFI_LOADED_IMAGE_PROTOCOL *LoadedImage,
  OUT PLOADED_IMAGE             TargetElem
  )
{
  EFI_STATUS                Status;
  EFI_DEVICE_PATH_PROTOCOL  *FullPath = NULL;
  CHAR16                    *Text = NULL;
  EFI_DEVICE_PATH_PROTOCOL  *ParentPath = NULL;

  Status = gBS->HandleProtocol (
                  LoadedImage->DeviceHandle,
                  &gEfiDevicePathProtocolGuid,
                  (VOID **) &ParentPath
                  );
  if (EFI_ERROR(Status)) {
    DEBUG((
      EFI_D_WARN,
      "HandleProtocol (DeviceHandle, DevicePath) returned %r\n",
      Status
      ));
  }

  FullPath = AppendDevicePath(ParentPath, LoadedImage->FilePath);
  if (!FullPath) {
    Status = EFI_OUT_OF_RESOURCES;
    DEBUG((EFI_D_ERROR, "AppendDevicePath returned %r\n", Status));
    goto Exit;
  }

  Text = ConvertDevicePathToText(FullPath, FALSE, FALSE);
  if (!Text) {
    Status = EFI_OUT_OF_RESOURCES;
    DEBUG((EFI_D_ERROR, "ConvertDevicePathToText returned NULL\n"));
    goto Exit;
  }

  Status = StrCpyS(TargetElem->DevicePath, 256, Text);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "StrCpyS returned %r\n", Status));
    goto Exit;
  }

Exit:
  if (Text) {
    FreePool(Text);
  }

  if (FullPath) {
    FreePool(FullPath);
  }

  return Status;
}

EFI_STATUS
GatherModuleName (
  IN  EFI_LOADED_IMAGE_PROTOCOL *LoadedImage,
  OUT PLOADED_IMAGE             TargetElem
  )
{
  EFI_STATUS                        Status;
  EFI_GUID                          *NameGuid;
  CHAR16                            *ImageName = NULL;
  UINT32                            AuthenticationStatus;
  UINTN                             BufferSize;
  EFI_DEVICE_PATH_PROTOCOL          *PathNode = NULL;
  EFI_FIRMWARE_VOLUME2_PROTOCOL     *Fv2;

  PathNode = LoadedImage->FilePath;
  if (PathNode == NULL)
    return EFI_UNSUPPORTED;

  for (; !IsDevicePathEnd(PathNode);
       PathNode = NextDevicePathNode (PathNode)) {
    NameGuid = EfiGetNameGuidFromFwVolDevicePathNode (
      (MEDIA_FW_VOL_FILEPATH_DEVICE_PATH *)PathNode
      );
    if (NameGuid != NULL) {
      Status = gBS->HandleProtocol (
                      LoadedImage->DeviceHandle,
                      &gEfiFirmwareVolume2ProtocolGuid,
                      (VOID **) &Fv2
                      );
      if (EFI_ERROR(Status)) {
        continue;
      }
      Status = Fv2->ReadSection (
                      Fv2,
                      NameGuid,
                      EFI_SECTION_USER_INTERFACE,
                      0,
                      (VOID **) &ImageName,
                      &BufferSize,
                      &AuthenticationStatus
                      );
      if (EFI_ERROR(Status)) {
        continue;
      }
    }
  }

  if (ImageName == NULL) {
    return EFI_UNSUPPORTED;
  }

  Status = StrCpyS(TargetElem->ModuleName, 256, ImageName);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  return EFI_SUCCESS;
}

PLOADED_IMAGE
CreateLoadedImageStruct (
  IN  EFI_HANDLE                    Handle,
  IN  EFI_LOADED_IMAGE_PROTOCOL     *LoadedImage
  )
{
  EFI_STATUS        Status;
  PLOADED_IMAGE     NewElem;

  if (LoadedImage->ImageCodeType != EfiRuntimeServicesCode &&
      LoadedImage->ImageDataType != EfiRuntimeServicesData)
  {
    return NULL;
  }
  NewElem = PushLoadedImage();
  if (NewElem == NULL) {
    DEBUG((EFI_D_WARN, "Skip %p handle because of memory error\n", Handle));
    return NULL;
  }
  NewElem->ImageBase = LoadedImage->ImageBase;
  NewElem->ImageSize = LoadedImage->ImageSize;
  NewElem->ImageCodeType = LoadedImage->ImageCodeType;
  NewElem->ImageDataType = LoadedImage->ImageDataType;
  Status = GatherDevicePath(LoadedImage, NewElem);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_WARN, "Skip device path for %p: %r\n", Handle, Status));
  }
  Status = GatherModuleName(LoadedImage, NewElem);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_WARN, "Skip module name for %p: %r\n", Handle, Status));
  }
  return NewElem;
}

EFI_STATUS
EFIAPI
Start (
  IN  EFI_DRIVER_BINDING_PROTOCOL   *This,
  IN  EFI_HANDLE                    Controller,
  IN  EFI_DEVICE_PATH_PROTOCOL      *RemainingDevicePath
  )
{
  EFI_STATUS                    Status;
  EFI_LOADED_IMAGE_PROTOCOL     *LoadedImage;
  PLOADED_IMAGE                 Protocol;

  Status = gBS->HandleProtocol (
                  Controller,
                  &gEfiLoadedImageProtocolGuid,
                  (VOID **) &LoadedImage
                  );
  if (EFI_ERROR(Status)) {
    return Status;
  }

  Status = gBS->HandleProtocol (
                  Controller,
                  &MyProtocolGuid,
                  (VOID **) &Protocol
                  );
  if (!EFI_ERROR(Status)) {
    return EFI_ALREADY_STARTED;
  }

  Protocol = CreateLoadedImageStruct(Controller, LoadedImage);
  if (!Protocol) {
    return EFI_UNSUPPORTED;
  }

  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Controller,
                  &MyProtocolGuid,
                  Protocol,
                  NULL
                  );
  if (EFI_ERROR(Status)) {
    RemoveLoadedImage(Protocol);
    return Status;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
Supported (
  IN  EFI_DRIVER_BINDING_PROTOCOL   *This,
  IN  EFI_HANDLE                    Controller,
  IN  EFI_DEVICE_PATH_PROTOCOL      *RemainingDevicePath
  )
{
  EFI_STATUS                    Status;
  EFI_LOADED_IMAGE_PROTOCOL     *LoadedImage;

  Status = gBS->HandleProtocol (
                  Controller,
                  &gEfiLoadedImageProtocolGuid,
                  (VOID **) &LoadedImage
                  );
  if (EFI_ERROR(Status)) {
    return Status;
  }

  if (LoadedImage->ImageCodeType != EfiRuntimeServicesCode &&
      LoadedImage->ImageDataType != EfiRuntimeServicesData)
  {
    return EFI_UNSUPPORTED;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
Stop (
  IN  EFI_DRIVER_BINDING_PROTOCOL     *This,
  IN  EFI_HANDLE                      Controller,
  IN  UINTN                           NumberOfChildren,
  IN  EFI_HANDLE                      *ChildHandleBuffer
  )
{
  EFI_STATUS        Status;
  PLOADED_IMAGE     Protocol;

  Status = gBS->HandleProtocol (
                  Controller,
                  &MyProtocolGuid,
                  (VOID **) &Protocol
                  );
  if (EFI_ERROR(Status)) {
    return EFI_SUCCESS;
  }

  Status = gBS->UninstallMultipleProtocolInterfaces (
                  Controller,
                  &MyProtocolGuid,
                  NULL
                  );

  RemoveLoadedImage(Protocol);

  return Status;
}

VOID
EFIAPI
OnExitBootServices (
  IN  EFI_EVENT     Event,
  IN  VOID          *Context
  )
{
  EFI_STATUS    Status;
  UINT64        PageAddress64 = (UINT64)(UINTN)LoadedImages;
  UINT32        Attributes = EFI_VARIABLE_BOOTSERVICE_ACCESS |
                             EFI_VARIABLE_RUNTIME_ACCESS;

  Status = gRT->SetVariable (
                  L"RuntimeListHead",
                  &MyVendorGuid,
                  Attributes,
                  sizeof(UINT64),
                  &PageAddress64
                  );
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "SetVariable(1) returned %r\n", Status));
    return;
  }

  Status = CopyMemoryMap(FwMemoryMap);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "CopyMemoryMap returned %r\n", Status));
  }
}

EFI_STATUS
EFIAPI
SetVariable (
  IN  CHAR16                       *VariableName,
  IN  EFI_GUID                     *VendorGuid,
  IN  UINT32                       Attributes,
  IN  UINTN                        DataSize,
  IN  VOID                         *Data
  )
{
  EFI_STATUS Status;
  if (OriginalSetVariable) {
    Status = OriginalSetVariable(
      VariableName,
      VendorGuid,
      Attributes,
      DataSize,
      Data
      );
    if (!EFI_ERROR(Status)) {
      UpdateVariableInVariableList(
        FwVars,
        VariableName,
        VendorGuid,
        Attributes,
        DataSize
        );
      RebuildVariableList (FwVars2);
    }
    return Status;
  }
  return EFI_UNSUPPORTED;
}

VOID
EFIAPI
OnSetVirtualAddressMapEvent (
  IN  EFI_EVENT     Event,
  IN  VOID          *Context
  )
{
  PLOADED_IMAGE Next = LoadedImages;
  UINTN Index;
  PFW_MMAPE MapEntry;
  EFI_STATUS Status;
  while (Next) {
    Next->ImageBaseVirtual = Next->ImageBase;
    gRT->ConvertPointer(0, (VOID **) &Next->ImageBaseVirtual);
    Next = Next->Next;
  }
  for (Index = 0; Index < FwMemoryMap->Count; ++Index) {
    MapEntry = &FwMemoryMap->MMap[Index];
    MapEntry->VirtualStart = MapEntry->PhysicalStart;
    Status = gRT->ConvertPointer(0, (VOID **) &MapEntry->VirtualStart);
    if (EFI_ERROR(Status)) {
      //
      // Some of the conversions are expected to fail
      //
      MapEntry->VirtualStart = 0;
    }
  }
  gRT->ConvertPointer(0, (VOID **) &OriginalSetVariable);
  gRT->ConvertPointer(0, (VOID **) &FwVars);
  gRT->ConvertPointer(0, (VOID **) &FwVars2);
  gRT->ConvertPointer(0, (VOID **) &gRT);
}

EFI_STATUS
HookRuntimeVariableServices (VOID)
{
  EFI_TPL OldTpl;

  OldTpl = gBS->RaiseTPL(TPL_HIGH_LEVEL);
  OriginalSetVariable = gRT->SetVariable;
  gRT->SetVariable = SetVariable;
  gRT->Hdr.CRC32 = 0;
  gBS->CalculateCrc32(&gRT->Hdr, gRT->Hdr.HeaderSize, &gRT->Hdr.CRC32);
  gBS->RestoreTPL(OldTpl);
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
UefiMain (
  IN  EFI_HANDLE        ImageHandle,
  IN  EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS    Status;
  UINTN         HandleCount = 0;
  EFI_HANDLE    *HandleBuffer = NULL;
  UINTN         Index;
  EFI_EVENT     ExitBootServiceEvent;
  EFI_EVENT     SetVirtualAddressMapEvent;
  UINT64        FwVarsBase;
  UINT64        FwVarsBase2;
  UINT64        FwMemoryMapBase;

  AllocateFwMemoryMap(&FwMemoryMap);

  AllocateFwVarsPool(&FwVars);
  AllocateFwVarsPool(&FwVars2);
  RebuildVariableList(FwVars);
  RebuildVariableList(FwVars2);

  //
  // Add another indirection to the pointer so that the pointers
  // can later be translated to new virtual address map without
  // changing the NVram variable.
  //
  FwVarsBase = (UINT64)(UINTN) &FwVars;
  FwVarsBase2 = (UINT64)(UINTN) &FwVars2;

  FwMemoryMapBase = (UINT64)(UINTN) FwMemoryMap;

  Status = gBS->InstallMultipleProtocolInterfaces (
                  &ImageHandle,
                  &gEfiDriverBindingProtocolGuid,
                  &DriverBinding,
                  NULL
                  );
  if (EFI_ERROR(Status)) {
    DEBUG((
      EFI_D_ERROR,
      "InstallMultipleProtocolInterfaces returned %r\n",
      Status));
    return Status;
  }

  HookRuntimeVariableServices();

  gBS->CreateEventEx (
         EVT_NOTIFY_SIGNAL,
         TPL_NOTIFY,
         OnSetVirtualAddressMapEvent,
         NULL,
         &gEfiEventVirtualAddressChangeGuid,
         &SetVirtualAddressMapEvent
         );

  gBS->CreateEventEx (
         EVT_NOTIFY_SIGNAL,
         TPL_NOTIFY,
         OnExitBootServices,
         NULL,
         &gEfiEventExitBootServicesGuid,
         &ExitBootServiceEvent
         );

  gRT->SetVariable (
         L"FwVarsBase",
         &MyVendorGuid,
         EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
         sizeof(UINT64),
         &FwVarsBase
         );

  gRT->SetVariable (
         L"FwVarsBase2",
         &MyVendorGuid,
         EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
         sizeof(UINT64),
         &FwVarsBase2
         );

  gRT->SetVariable (
         L"FwMmap",
         &MyVendorGuid,
         EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
         sizeof(UINT64),
         &FwMemoryMapBase
         );

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiLoadedImageProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer
                  );
  if (!EFI_ERROR(Status)) {
    for (Index = 0; Index < HandleCount; ++Index) {
      gBS->ConnectController (HandleBuffer[Index], NULL, NULL, TRUE);
    }
    gBS->FreePool (HandleBuffer);
  }

  return EFI_SUCCESS;
}
