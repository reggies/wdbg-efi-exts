#include <ntddk.h>
#include <initguid.h>
#include <ntstrsafe.h>

#include "efihlp.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, MyUnload)
#pragma alloc_text (PAGE, MyDispatchPassThrough)
#pragma alloc_text (PAGE, ScanList)
#pragma alloc_text (PAGE, ReadPhysicalAddressFromEfiVar)
#pragma alloc_text (PAGE, GetRuntimeListHeadPA)
#pragma alloc_text (PAGE, InitFwVarsBaseAddress)
#pragma alloc_text (PAGE, InitFwMmapBaseAddress)
#pragma alloc_text (PAGE, ReadRuntimeModuleList)
#pragma alloc_text (PAGE, DumpFwVars)
#pragma alloc_text (PAGE, DumpFwMmap)
#pragma alloc_text (PAGE, MyKeySetString)
#pragma alloc_text (PAGE, DumpRuntimeDrivers)
#endif

static KBUGCHECK_REASON_CALLBACK_RECORD RuntimeModulesCallbackRecord;
static KBUGCHECK_REASON_CALLBACK_RECORD FwVarsCallbackRecord;
static KBUGCHECK_REASON_CALLBACK_RECORD FwVars2CallbackRecord;
static KBUGCHECK_REASON_CALLBACK_RECORD FwMmapCallbackRecord;

static NPAGED_LOOKASIDE_LIST mEfiModuleLookasideList;

static LIST_ENTRY mEfiRuntimeListHead;
const PLIST_ENTRY EfiRuntimeListHead = &mEfiRuntimeListHead;

PHYSICAL_ADDRESS EfiFwVarsBase = { 0 };
PHYSICAL_ADDRESS EfiFwVarsBase2 = { 0 };

PFW_VARS_POOL EfiFwVars = NULL;
PFW_VARS_POOL EfiFwVars2 = NULL;

PHYSICAL_ADDRESS EfiFwMmapBase = { 0 };

static FW_MMAP mEfiFwMmapCopy;

NTSTATUS
MyDispatchPassThrough (
	_In_   PDEVICE_OBJECT   DeviceObject,
	_In_   PIRP             Irp
	)
{
	PAGED_CODE();

	IoSkipCurrentIrpStackLocation (Irp);
	return IoCallDriver (DeviceObject, Irp);
}

VOID
MyUnload (
	_In_ PDRIVER_OBJECT DriverObject
	)
{
	UNREFERENCED_PARAMETER(DriverObject);

	PAGED_CODE();

	KeDeregisterBugCheckReasonCallback(&RuntimeModulesCallbackRecord);
	KeDeregisterBugCheckReasonCallback(&FwVars2CallbackRecord);
	KeDeregisterBugCheckReasonCallback(&FwVarsCallbackRecord);
	KeDeregisterBugCheckReasonCallback(&FwMmapCallbackRecord);

	ExDeleteNPagedLookasideList(&mEfiModuleLookasideList);
}

NTSTATUS
ScanList (
	_In_ ULONG_PTR PhysicalAddress
	)
{
	PVOID SystemAddress;
	RTMODULE RuntimeModule;
	PHYSICAL_ADDRESS liPhysicalAddress;
	PEFI_MODULE Elem;
	PHYSICAL_ADDRESS ImageBasePhysical;
	PVOID ImageBaseVirtual;

	PAGED_CODE();

	RtlZeroMemory(&RuntimeModule, sizeof(RTMODULE));

	for (liPhysicalAddress.QuadPart = PhysicalAddress;
	    liPhysicalAddress.QuadPart != 0;
	    liPhysicalAddress.QuadPart = RuntimeModule.Next)
	{
		SystemAddress = MmMapIoSpace(
		    liPhysicalAddress,
		    ROUND_TO_PAGES(sizeof(RTMODULE)),
		    MmCached);

		if (!SystemAddress)
		{
			MyDbgPrint("MmMapIoSpace returned NULL");
			continue;
		}

		RtlCopyMemory(&RuntimeModule, SystemAddress, sizeof(RTMODULE));

		if (RuntimeModule.Signature != RTMODULE_SIGNATURE)
		{
			MyDbgPrint("Runtime module signature is invalid\n");
			MmUnmapIoSpace(SystemAddress, ROUND_TO_PAGES(sizeof(RTMODULE)));
			continue;
		}

		ImageBasePhysical.QuadPart = RuntimeModule.ImageBase;
		ImageBaseVirtual = (PVOID) RuntimeModule.ImageBaseVirtual;

		MyDbgPrint("Runtime Module at %p\n", (PVOID)RuntimeModule.ImageBase);
		MyDbgPrint(" + VirtualBase: %p\n", (PVOID)RuntimeModule.ImageBaseVirtual);
		MyDbgPrint(" + Next: %p\n", (PVOID)RuntimeModule.Next);

		Elem = ExAllocateFromNPagedLookasideList(&mEfiModuleLookasideList);
		if (Elem)
		{
			RtlZeroMemory(Elem, sizeof(EFI_MODULE));
			Elem->Version = sizeof(EFI_MODULE);
			Elem->ImageBasePhysical = RuntimeModule.ImageBase;
			Elem->ImageSize = RuntimeModule.ImageSize;
			Elem->ImageBaseVirtual = (ULONG_PTR)ImageBaseVirtual;
			Elem->SourceDataPhysical = (ULONG_PTR)liPhysicalAddress.QuadPart;
			RtlCopyMemory(
			    Elem->DevicePath,
			    RuntimeModule.DevicePath,
			    sizeof(WCHAR) * MAX_DEVICE_PATH);
			RtlCopyMemory(
			    Elem->ModuleName,
			    RuntimeModule.ModuleName,
			    sizeof(WCHAR) * MAX_MODULE_NAME);
			InsertHeadList(EfiRuntimeListHead, &Elem->Link);
		}
		else
		{
			MyDbgPrint("ExAllocateFromNPagedLookasideList failed\n");
		}

		MmUnmapIoSpace(SystemAddress, ROUND_TO_PAGES(sizeof(RTMODULE)));
	}

	return STATUS_SUCCESS;
}

NTSTATUS
ReadPhysicalAddressFromEfiVar (
	_In_   PCWSTR             VarName,
	_Out_  PPHYSICAL_ADDRESS  Address
	)
{
	NTSTATUS Status;
	UNICODE_STRING VariableName;
	UCHAR Data[sizeof(ULONG_PTR)];
	ULONG DataSize = ARRAYSIZE(Data);
	GUID MyVendorGuid = GUID_MY_VENDOR;
	ULONG_PTR DataUlongPtr;

	PAGED_CODE();

	RtlInitUnicodeString(&VariableName, VarName);

	Status = ExGetFirmwareEnvironmentVariable(
	    &VariableName,
	    &MyVendorGuid,
	    Data,
	    &DataSize,
	    NULL);
	if (NT_ERROR(Status))
	{
		MyDbgPrint("ExGetFirmwareEnvironmentVariable returned 0x%08x", Status);
		return STATUS_UNSUCCESSFUL;
	}

	RtlCopyMemory(&DataUlongPtr, &Data, sizeof(ULONG_PTR));

	Address->QuadPart = DataUlongPtr;

	return STATUS_SUCCESS;
}

NTSTATUS
GetRuntimeListHeadPA (
	_Out_ PULONG_PTR RuntimeListHead
	)
{
	NTSTATUS Status;
	PHYSICAL_ADDRESS PhysAddress;

	Status = ReadPhysicalAddressFromEfiVar(L"RuntimeListHead", &PhysAddress);
	if (NT_ERROR(Status))
	{
		MyDbgPrint("ReadPhysicalAddressFromEfiVar returned 0x%08x\n", Status);
		return STATUS_UNSUCCESSFUL;
	}

	*RuntimeListHead = (ULONG_PTR)(ULONG64)PhysAddress.QuadPart;

	return STATUS_SUCCESS;
}

NTSTATUS
ReadVirtualPointer (
	_In_    PHYSICAL_ADDRESS   PhysicalAddress,
	_Out_   PVOID              *VirtualAddress
	)
{
	PVOID BaseAddress;

	BaseAddress = MmMapIoSpace(PhysicalAddress, ROUND_TO_PAGES(sizeof(PVOID)), MmCached);
	if (BaseAddress == NULL)
	{
		MyDbgPrint("MmMapIoSpace returned NULL\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlCopyMemory(VirtualAddress, BaseAddress, sizeof(PVOID));

	MmUnmapIoSpace(BaseAddress, ROUND_TO_PAGES(sizeof(PVOID)));

	return STATUS_SUCCESS;
}

NTSTATUS
InitFwVarsBaseAddress (VOID)
{
	NTSTATUS Status;

	PAGED_CODE();

	Status = ReadPhysicalAddressFromEfiVar(L"FwVarsBase", &EfiFwVarsBase);
	if (NT_ERROR(Status))
	{
		MyDbgPrint("ReadPhysicalAddressFromEfiVar returned 0x%08x\n", Status);
		return STATUS_UNSUCCESSFUL;
	}
	MyDbgPrint("FwVarsBase PA: 0x%016I64x\n", EfiFwVarsBase);

	Status = ReadVirtualPointer(EfiFwVarsBase, &EfiFwVars);
	if (NT_ERROR(Status))
	{
		MyDbgPrint("ReadVirtualPointer (FwVarsBase) returned 0x%08x\n", Status);
	}

	Status = ReadPhysicalAddressFromEfiVar(L"FwVarsBase2", &EfiFwVarsBase2);
	if (NT_ERROR(Status))
	{
		MyDbgPrint("ReadPhysicalAddressFromEfiVar(2) returned 0x%08x\n", Status);
		return STATUS_UNSUCCESSFUL;
	}
	MyDbgPrint("FwVarsBase2 PA: 0x%016I64x\n", EfiFwVarsBase2);

	Status = ReadVirtualPointer(EfiFwVarsBase2, &EfiFwVars2);
	if (NT_ERROR(Status))
	{
		MyDbgPrint("ReadVirtualPointer (FwVarsBase2) returned 0x%08x\n", Status);
	}

	return STATUS_SUCCESS;
}

NTSTATUS
InitFwMmapBaseAddress(VOID)
{
	NTSTATUS Status;
	PFW_MMAP FwMmapIo;

	PAGED_CODE();

	RtlZeroMemory(&mEfiFwMmapCopy, sizeof(FW_MMAP));
	EfiFwMmapBase.QuadPart = 0;

	Status = ReadPhysicalAddressFromEfiVar(L"FwMmap", &EfiFwMmapBase);
	if (NT_ERROR(Status))
	{
		MyDbgPrint("ReadPhysicalAddressFromEfiVar(FwMmap) returned 0x%08x\n", Status);
		return STATUS_UNSUCCESSFUL;
	}
	MyDbgPrint("EfiFwMmapBase: 0x%016I64x\n", EfiFwMmapBase);

	if (EfiFwMmapBase.QuadPart == 0)
	{
		return STATUS_UNSUCCESSFUL;
	}

	FwMmapIo = MmMapIoSpace(EfiFwMmapBase, ROUND_TO_PAGES(sizeof(FW_MMAP)), MmCached);
	if (FwMmapIo == NULL)
	{
		MyDbgPrint("MmMapIoSpace (FwMmap) returned NULL\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	if (FwMmapIo->Signature != FW_MMAP_SIGNATURE)
	{
		MyDbgPrint("FwMmap signature mismatch\n");
		Status = STATUS_NOT_FOUND;
		goto Exit;
	}

	RtlCopyMemory(&mEfiFwMmapCopy, FwMmapIo, sizeof(FW_MMAP));

	Status = STATUS_SUCCESS;

Exit:
	MmUnmapIoSpace(FwMmapIo, ROUND_TO_PAGES(sizeof(FW_MMAP)));
	return Status;
}

NTSTATUS
ReadRuntimeModuleList (VOID)
{
	NTSTATUS Status;
	ULONG_PTR PhysicalAddress;

	Status = GetRuntimeListHeadPA(&PhysicalAddress);
	if (NT_ERROR(Status))
	{
		MyDbgPrint("GetRuntimeListHeadPA returned 0x%08x", Status);
		return STATUS_UNSUCCESSFUL;
	}

	return ScanList(PhysicalAddress);
}

NTSTATUS
DumpFwVars (
	_In_   PFW_VARS_POOL    FwVars,
	_In_   PCWSTR           RegistryPath
	)
{
	NTSTATUS Status;
	ULONG Index;
	
	UNICODE_STRING ValueName;
	UNICODE_STRING KeyPath;
	HANDLE KeyHandle;
	OBJECT_ATTRIBUTES KeyAttributes;
	WCHAR wcValueBuffer[256];
	GUID Guid;
	ULONG Attributes;

	PAGED_CODE();

	if (FwVars == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	if (FwVars->Signature != FW_VAR_POOL_SIGNATURE)
	{
		MyDbgPrint("FwVars signature is a scam!\n");
		return STATUS_NOT_FOUND;
	}

	//
	// Delete key and create key again
	//

	RtlInitUnicodeString(&KeyPath, RegistryPath);
	InitializeObjectAttributes(
	    &KeyAttributes,
	    &KeyPath,
	    OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
	    NULL,
	    NULL);
	Status = ZwCreateKey(
	    &KeyHandle,
	    KEY_ALL_ACCESS,                                      // DesiredAccess
	    &KeyAttributes,
	    0,
	    NULL,
	    REG_OPTION_VOLATILE,                                 // CreateOptions
	    NULL);
	if (NT_ERROR(Status))
	{
		MyDbgPrint("ZwCreateKey returned 0x%08x\n", Status);
		return Status;
	}

	ZwDeleteKey(KeyHandle);
	ZwClose(KeyHandle);

	Status = ZwCreateKey(
	    &KeyHandle,
	    0,                                               // DesiredAccess
	    &KeyAttributes,
	    0,
	    NULL,
	    REG_OPTION_VOLATILE,                             // CreateOptions
	    NULL);
	if (NT_ERROR(Status))
	{
		MyDbgPrint("ZwCreateKey(2) returned 0x%08x\n", Status);
		return Status;
	}

	for (Index = 0; Index < FwVars->Count; ++Index)
	{
		Guid = FwVars->Objects[Index].Guid;
		Attributes = FwVars->Objects[Index].Attributes;
		ValueName.Buffer = wcValueBuffer;
		ValueName.Length = 0;
		ValueName.MaximumLength = sizeof(wcValueBuffer);
		RtlUnicodeStringPrintf(
		    &ValueName,
		    L"{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}-%s",
		    Guid.Data1,
		    Guid.Data2,
		    Guid.Data3,
		    Guid.Data4[0], Guid.Data4[1], Guid.Data4[2], Guid.Data4[3],
		    Guid.Data4[4], Guid.Data4[5], Guid.Data4[6], Guid.Data4[7],
		    FwVars->Objects[Index].Name);
		Status = ZwSetValueKey(
		    KeyHandle,
		    &ValueName,
		    0,
		    REG_DWORD,
		    &Attributes,
		    sizeof(ULONG));
		if (NT_ERROR(Status))
		{
			MyDbgPrint("ZwSetValueKey returned 0x%08x\n", Status);
		}
	}

	Status = ZwClose(KeyHandle);
	if (NT_ERROR(Status))
	{
		MyDbgPrint("ZwClose returned 0x%08x\n", Status);
	}

	return STATUS_SUCCESS;
}

NTSTATUS
DumpFwMmap(
	_In_ PCWSTR RegistryPath
	)
{
	NTSTATUS Status;
	ULONG Index;
	UNICODE_STRING ValueName;
	UNICODE_STRING KeyPath;
	HANDLE KeyHandle;
	OBJECT_ATTRIBUTES KeyAttributes;
	WCHAR wcSubKeyBuffer[256];
	FW_MMAPE Descriptor;

	PAGED_CODE();

	//
	// Delete key and create key again
	//

	RtlInitUnicodeString(&KeyPath, RegistryPath);
	InitializeObjectAttributes(
		&KeyAttributes,
		&KeyPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);
	Status = ZwCreateKey(
		&KeyHandle,
		KEY_ALL_ACCESS,                                      // DesiredAccess
		&KeyAttributes,
		0,
		NULL,
		REG_OPTION_VOLATILE,                                 // CreateOptions
		NULL);
	if (NT_ERROR(Status))
	{
		MyDbgPrint("ZwCreateKey returned 0x%08x\n", Status);
		return Status;
	}

	ZwDeleteKey(KeyHandle);
	ZwClose(KeyHandle);

	//
	// Create empty root key
	//

	Status = ZwCreateKey(
		&KeyHandle,
		0,                                                   // DesiredAccess
		&KeyAttributes,
		0,
		NULL,
		REG_OPTION_VOLATILE,                                 // CreateOptions
		NULL);
	if (NT_ERROR(Status))
	{
		MyDbgPrint("ZwCreateKey(2) returned 0x%08x\n", Status);
		return Status;
	}
	else
	{
		ZwClose(KeyHandle);
	}

	if (mEfiFwMmapCopy.Signature != FW_MMAP_SIGNATURE ||
		mEfiFwMmapCopy.Count > MAX_MEMORY_MAP)
	{
		return STATUS_UNSUCCESSFUL;
	}

	for (Index = 0; Index < mEfiFwMmapCopy.Count; ++Index)
	{
		Descriptor = mEfiFwMmapCopy.MMap[Index];

		KeyPath.Buffer = wcSubKeyBuffer;
		KeyPath.Length = 0;
		KeyPath.MaximumLength = sizeof(wcSubKeyBuffer);
		Status = RtlUnicodeStringPrintf(
			&KeyPath,
			L"%s\\Region%02x",
			RegistryPath,
			Index);
		if (NT_ERROR(Status))
		{
			MyDbgPrint("RtlUnicodeStringPrintf returned 0x%08x\n", Status);
			return Status;
		}

		InitializeObjectAttributes(
			&KeyAttributes,
			&KeyPath,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL,
			NULL);
		Status = ZwCreateKey(
			&KeyHandle,
			0,                                           // DesiredAccess
			&KeyAttributes,
			0,
			NULL,
			REG_OPTION_VOLATILE,                         // CreateOptions
			NULL);
		if (NT_ERROR(Status))
		{
			MyDbgPrint("ZwCreateKey(3) returned 0x%08x\n", Status);
			return Status;
		}

		RtlUnicodeStringInit(&ValueName, L"Attributes");
		Status = ZwSetValueKey(
			KeyHandle,
			&ValueName,
			0,
			REG_QWORD,
			&Descriptor.Attributes,
			sizeof(ULONG64));
		if (NT_ERROR(Status))
		{
			MyDbgPrint("ZwSetValueKey(1) returned 0x%08x\n", Status);
		}

		RtlUnicodeStringInit(&ValueName, L"Type");
		Status = ZwSetValueKey(
			KeyHandle,
			&ValueName,
			0,
			REG_DWORD,
			&Descriptor.Type,
			sizeof(ULONG32));
		if (NT_ERROR(Status))
		{
			MyDbgPrint("ZwSetValueKey(2) returned 0x%08x\n", Status);
		}

		RtlUnicodeStringInit(&ValueName, L"BasePhysical");
		Status = ZwSetValueKey(
			KeyHandle,
			&ValueName,
			0,
			REG_QWORD,
			&Descriptor.PhysicalAddress,
			sizeof(ULONG64));
		if (NT_ERROR(Status))
		{
			MyDbgPrint("ZwSetValueKey(3) returned 0x%08x\n", Status);
		}

		RtlUnicodeStringInit(&ValueName, L"BaseVirtual");
		Status = ZwSetValueKey(
			KeyHandle,
			&ValueName,
			0,
			REG_QWORD,
			&Descriptor.VirtualAddress,
			sizeof(ULONG64));
		if (NT_ERROR(Status))
		{
			MyDbgPrint("ZwSetValueKey(3) returned 0x%08x\n", Status);
		}

		RtlUnicodeStringInit(&ValueName, L"NumberOf4KPages");
		Status = ZwSetValueKey(
			KeyHandle,
			&ValueName,
			0,
			REG_QWORD,
			&Descriptor.NumberOf4KPages,
			sizeof(ULONG64));
		if (NT_ERROR(Status))
		{
			MyDbgPrint("ZwSetValueKey(4) returned 0x%08x\n", Status);
		}

		Status = ZwClose(KeyHandle);
		if (NT_ERROR(Status))
		{
			MyDbgPrint("ZwClose returned 0x%08x\n", Status);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS
MyKeySetString (
	_In_   HANDLE            KeyHandle,
	_In_   PUNICODE_STRING   ValueName,
	_In_   PWSTR             StringValue
	)
{
	size_t chCount = wcslen(StringValue) + 1;

	PAGED_CODE();

	return ZwSetValueKey(
	    KeyHandle,
	    ValueName,
	    0,
	    REG_SZ,
	    StringValue,
	    (ULONG)chCount * sizeof(WCHAR));
}

NTSTATUS
DumpRuntimeDrivers (
	_In_ PCWSTR RegistryPath
	)
{
	NTSTATUS Status;
	ULONG Index = 0;
	UNICODE_STRING ValueName;
	UNICODE_STRING KeyPath;
	HANDLE KeyHandle;
	OBJECT_ATTRIBUTES KeyAttributes;
	WCHAR wcSubKeyBuffer[256];
	PLIST_ENTRY ListEntry;
	PEFI_MODULE Module;

	PAGED_CODE();

	//
	// Delete old root key
	//
	RtlInitUnicodeString(&KeyPath, RegistryPath);
	InitializeObjectAttributes(
	    &KeyAttributes,
	    &KeyPath,
	    OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
	    NULL,
	    NULL);
	Status = ZwCreateKey(
	    &KeyHandle,
	    KEY_ALL_ACCESS,                                      // DesiredAccess
	    &KeyAttributes,
	    0,
	    NULL,
	    0,                                                   // CreateOptions
	    NULL);
	if (NT_SUCCESS(Status))
	{
		ZwDeleteKey(KeyHandle);
		ZwClose(KeyHandle);
	}

	//
	// Create empty root key
	//

	Status = ZwCreateKey(
	    &KeyHandle,
	    0,                                                   // DesiredAccess
	    &KeyAttributes,
	    0,
	    NULL,
	    REG_OPTION_VOLATILE,                                 // CreateOptions
	    NULL);
	if (NT_SUCCESS(Status))
	{
		ZwClose(KeyHandle);
	}

	//
	// Create subkey for each individual driver
	//
	for (ListEntry = EfiRuntimeListHead->Flink, Index = 0;
	    ListEntry != EfiRuntimeListHead;
	    ListEntry = ListEntry->Flink, ++Index)
	{
		Module = CONTAINING_RECORD(ListEntry, EFI_MODULE, Link);

		KeyPath.Buffer = wcSubKeyBuffer;
		KeyPath.Length = 0;
		KeyPath.MaximumLength = sizeof(wcSubKeyBuffer);
		Status = RtlUnicodeStringPrintf(
		    &KeyPath,
		    L"%s\\Runtime%04x",
		    RegistryPath,
		    Index);
		if (NT_ERROR(Status))
		{
			MyDbgPrint("RtlUnicodeStringPrintf returned 0x%08x\n", Status);
			return Status;
		}

		InitializeObjectAttributes(
		    &KeyAttributes,
		    &KeyPath,
		    OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		    NULL,
		    NULL);
		Status = ZwCreateKey(
		    &KeyHandle,
		    0,                                           // DesiredAccess
		    &KeyAttributes,
		    0,
		    NULL,
		    REG_OPTION_VOLATILE,                         // CreateOptions
		    NULL);
		if (NT_ERROR(Status))
		{
			MyDbgPrint("ZwCreateKey(2) returned 0x%08x\n", Status);
			return Status;
		}

		RtlUnicodeStringInit(&ValueName, L"BaseVirtual");
		Status = ZwSetValueKey(
			KeyHandle,
			&ValueName,
			0,
			REG_QWORD,
			&Module->ImageBaseVirtual,
			sizeof(ULONG64));
		if (NT_ERROR(Status))
		{
			MyDbgPrint("ZwSetValueKey(1) returned 0x%08x\n", Status);
		}

		RtlUnicodeStringInit(&ValueName, L"BaseAddress");
		Status = ZwSetValueKey(
		    KeyHandle,
		    &ValueName,
		    0,
		    REG_QWORD,
		    &Module->ImageBasePhysical,
		    sizeof(ULONG64));
		if (NT_ERROR(Status))
		{
			MyDbgPrint("ZwSetValueKey(2) returned 0x%08x\n", Status);
		}

		RtlUnicodeStringInit(&ValueName, L"ModuleName");
		Status = MyKeySetString(KeyHandle, &ValueName, Module->ModuleName);
		if (NT_ERROR(Status))
		{
			MyDbgPrint("ZwSetValueKey(3) returned 0x%08x\n", Status);
		}

		RtlUnicodeStringInit(&ValueName, L"DevicePath");
		Status = MyKeySetString(KeyHandle, &ValueName, Module->DevicePath);
		if (NT_ERROR(Status))
		{
			MyDbgPrint("ZwSetValueKey(4) returned 0x%08x\n", Status);
		}

		RtlUnicodeStringInit(&ValueName, L"Size");
		Status = ZwSetValueKey(
		    KeyHandle,
		    &ValueName,
		    0,
		    REG_QWORD,
		    &Module->ImageSize,
		    sizeof(ULONG64));
		if (NT_ERROR(Status))
		{
			MyDbgPrint("ZwSetValueKey(4) returned 0x%08x\n", Status);
		}

		RtlUnicodeStringInit(&ValueName, L"SourceDataPhysical");
		Status = ZwSetValueKey(
			KeyHandle,
			&ValueName,
			0,
			REG_QWORD,
			&Module->SourceDataPhysical,
			sizeof(ULONG64));
		if (NT_ERROR(Status))
		{
			MyDbgPrint("ZwSetValueKey(5) returned 0x%08x\n", Status);
		}

		Status = ZwClose(KeyHandle);
		if (NT_ERROR(Status))
		{
			MyDbgPrint("ZwClose returned 0x%08x\n", Status);
		}
	}

	return STATUS_SUCCESS;
}

void
AddPagesForRuntimeModulesCallbackRoutine(
	_In_             KBUGCHECK_CALLBACK_REASON Reason,
	_In_      KBUGCHECK_REASON_CALLBACK_RECORD *Record,
	_Inout_               PKBUGCHECK_ADD_PAGES AddPages,
	_In_                                 ULONG ReasonSpecificDataLength
	)
{
	PEFI_MODULE Module;
	PLIST_ENTRY DumpEntry = AddPages->Context;

	UNREFERENCED_PARAMETER(Reason);
	UNREFERENCED_PARAMETER(Record);
	UNREFERENCED_PARAMETER(ReasonSpecificDataLength);

	//
	// Dump one module at the time
	//

	if (DumpEntry == NULL)
	{
		DumpEntry = EfiRuntimeListHead->Flink;
	}

	if (DumpEntry != EfiRuntimeListHead)
	{
		Module = CONTAINING_RECORD(DumpEntry, EFI_MODULE, Link);

		AddPages->Context   = DumpEntry->Flink;
		AddPages->Address   = Module->ImageBaseVirtual;
		AddPages->Count     = BYTES_TO_PAGES(Module->ImageSize);
		AddPages->Flags     = KB_ADD_PAGES_FLAG_VIRTUAL_ADDRESS
		                    | KB_ADD_PAGES_FLAG_ADDITIONAL_RANGES_EXIST;

		return;
	}

	AddPages->Address   = 0;
	AddPages->Flags     = 0;
	AddPages->Count     = 0;
}

_Use_decl_annotations_
void
AddPagesForFwVars2CallbackRoutine(
	_In_             KBUGCHECK_CALLBACK_REASON Reason,
	_In_      KBUGCHECK_REASON_CALLBACK_RECORD *Record,
	_Inout_               PKBUGCHECK_ADD_PAGES AddPages,
	_In_                                 ULONG ReasonSpecificDataLength
	)
{
	UNREFERENCED_PARAMETER(Reason);
	UNREFERENCED_PARAMETER(Record);
	UNREFERENCED_PARAMETER(ReasonSpecificDataLength);

	if (EfiFwVars2 != NULL)
	{
		AddPages->Address = (ULONG_PTR) EfiFwVars2;
		AddPages->Count = BYTES_TO_PAGES(sizeof(FW_VARS_POOL));
		AddPages->Flags = KB_ADD_PAGES_FLAG_VIRTUAL_ADDRESS;

		return;
	}

	AddPages->Address = 0;
	AddPages->Count = 0;
	AddPages->Flags = 0;
}

_Use_decl_annotations_
void
AddPagesForFwVarsCallbackRoutine(
	_In_             KBUGCHECK_CALLBACK_REASON Reason,
	_In_      KBUGCHECK_REASON_CALLBACK_RECORD *Record,
	_Inout_               PKBUGCHECK_ADD_PAGES AddPages,
	_In_                                 ULONG ReasonSpecificDataLength
	)
{
	UNREFERENCED_PARAMETER(Reason);
	UNREFERENCED_PARAMETER(Record);
	UNREFERENCED_PARAMETER(ReasonSpecificDataLength);

	if (EfiFwVars != NULL)
	{
		AddPages->Address = (ULONG_PTR) EfiFwVars;
		AddPages->Count = BYTES_TO_PAGES(sizeof(FW_VARS_POOL));
		AddPages->Flags = KB_ADD_PAGES_FLAG_VIRTUAL_ADDRESS;

		return;
	}

	AddPages->Address = 0;
	AddPages->Count = 0;
	AddPages->Flags = 0;
}

_Use_decl_annotations_
void
AddPagesForFwMmapCallbackRoutine(
	_In_             KBUGCHECK_CALLBACK_REASON Reason,
	_In_      KBUGCHECK_REASON_CALLBACK_RECORD *Record,
	_Inout_               PKBUGCHECK_ADD_PAGES AddPages,
	_In_                                 ULONG ReasonSpecificDataLength
	)
{
	PFW_MMAPE Descriptor = AddPages->Context;

	UNREFERENCED_PARAMETER(Reason);
	UNREFERENCED_PARAMETER(Record);
	UNREFERENCED_PARAMETER(ReasonSpecificDataLength);

	//
	// Dump one region at a time
	//

	if (Descriptor == NULL)
	{
		Descriptor = &mEfiFwMmapCopy.MMap[0];
	}

	if (mEfiFwMmapCopy.Signature == FW_MMAP_SIGNATURE &&
		mEfiFwMmapCopy.Count < MAX_MEMORY_MAP)
	{
		for(; &mEfiFwMmapCopy.MMap[mEfiFwMmapCopy.Count] != Descriptor; ++Descriptor)
		{
			if ((PVOID) Descriptor->VirtualAddress == NULL)
				continue;

			if (!MmIsAddressValid((PVOID) Descriptor->VirtualAddress))
				continue;

			switch (Descriptor->Type) {
			case EfiRuntimeServicesCode:
			case EfiRuntimeServicesData:
				break;
			default:
				continue;
			}

			AddPages->Context = Descriptor + 1;
			AddPages->Address = Descriptor->VirtualAddress;
			AddPages->Count   = Descriptor->NumberOf4KPages;
			AddPages->Flags   = KB_ADD_PAGES_FLAG_VIRTUAL_ADDRESS
							  | KB_ADD_PAGES_FLAG_ADDITIONAL_RANGES_EXIST;

			return;
		}
	}

	AddPages->Address = 0;
	AddPages->Flags   = 0;
	AddPages->Count   = 0;
}

_Use_decl_annotations_
NTSTATUS
DriverEntry (
	_In_   PDRIVER_OBJECT    DriverObject,
	_In_   PUNICODE_STRING   RegistryPath
	)
{
	ULONG Index;

	UNREFERENCED_PARAMETER(RegistryPath);

	ExInitializeNPagedLookasideList(
	    &mEfiModuleLookasideList,
	    NULL,
	    NULL,
	    0,
	    sizeof(EFI_MODULE),
	    EFI_MODULE_TAG,
	    0);

	InitializeListHead(EfiRuntimeListHead);

	for (Index = 0; Index <= IRP_MJ_MAXIMUM_FUNCTION; ++Index)
	{
		DriverObject->MajorFunction[Index] = MyDispatchPassThrough;
	}

	DriverObject->DriverUnload = MyUnload;

	ReadRuntimeModuleList();

	InitFwVarsBaseAddress();

	InitFwMmapBaseAddress();

	//
	// Dump EFI runtime objects to the registry as another
	// option to explore the data
	//

	DumpFwVars(EfiFwVars, L"\\REGISTRY\\MACHINE\\Software\\EFIVariables");
	DumpFwVars(EfiFwVars2, L"\\REGISTRY\\MACHINE\\Software\\EFIVariables2");

	DumpRuntimeDrivers(L"\\REGISTRY\\MACHINE\\Software\\EFIRuntimeDrivers");

	DumpFwMmap(L"\\REGISTRY\\MACHINE\\Software\\EFIMemoryMap");

	KeInitializeCallbackRecord(&RuntimeModulesCallbackRecord);
	KeInitializeCallbackRecord(&FwVars2CallbackRecord);
	KeInitializeCallbackRecord(&FwVarsCallbackRecord);
	KeInitializeCallbackRecord(&FwMmapCallbackRecord);

	KeRegisterBugCheckReasonCallback(
		&FwMmapCallbackRecord,
		AddPagesForFwMmapCallbackRoutine,
		KbCallbackAddPages,
		(PUCHAR) "efimmap"
	);

	KeRegisterBugCheckReasonCallback(
		&RuntimeModulesCallbackRecord,
		AddPagesForRuntimeModulesCallbackRoutine,
		KbCallbackAddPages,
		(PUCHAR) "efirtimg"
		);

	KeRegisterBugCheckReasonCallback(
		&FwVars2CallbackRecord,
		AddPagesForFwVars2CallbackRoutine,
		KbCallbackAddPages,
		(PUCHAR) "efivar2"
		);

	KeRegisterBugCheckReasonCallback(
		&FwVarsCallbackRecord,
		AddPagesForFwVarsCallbackRoutine,
		KbCallbackAddPages,
		(PUCHAR) "efivar1"
		);

	//
	// Dont unload because we want extern data pointers be
	// available for the debugger
	//

	return STATUS_SUCCESS;
}