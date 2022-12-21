#pragma once

#define EFI_MODULE_TAG 'HIFE'
#define MAX_DEVICE_PATH 256
#define MAX_MODULE_NAME 256

#define SIGNATURE_16(A, B) \
	((A) | (B << 8))
#define SIGNATURE_32(A, B, C, D) \
	(SIGNATURE_16 (A, B) | (SIGNATURE_16 (C, D) << 16))
#define SIGNATURE_64(A, B, C, D, E, F, G, H) \
	(SIGNATURE_32 (A, B, C, D) | ((ULONG64) (SIGNATURE_32 (E, F, G, H)) << 32))

#define RTMODULE_SIGNATURE \
	SIGNATURE_64('R', 'T', 'M', 'o', 'd', 'u', 'l', 'e')

#pragma pack (push, 1)

typedef struct _RTMODULE
{
	ULONG64 Signature;
	ULONG_PTR Next;
	ULONG_PTR ImageBase;
	ULONG_PTR ImageBaseVirtual;
	ULONG64 ImageSize;
	ULONG32 ImageCodeType;
	ULONG32 ImageDataType;
	WCHAR DevicePath[MAX_DEVICE_PATH];
	WCHAR ModuleName[MAX_MODULE_NAME];
} RTMODULE, *PRTMODULE;

#pragma pack (pop)

//
// Pointer to the head of the linked list of EFI_MODULE elments.
//
const extern PLIST_ENTRY EfiRuntimeListHead;

typedef struct _EFI_MODULE
{
	LIST_ENTRY Link;
	ULONG32 Version;
	ULONG_PTR ImageBasePhysical;
	ULONG64 ImageSize;
	ULONG_PTR ImageBaseVirtual;
	WCHAR DevicePath[MAX_DEVICE_PATH];
	WCHAR ModuleName[MAX_MODULE_NAME];
	ULONG_PTR SourceDataPhysical;
} EFI_MODULE, *PEFI_MODULE;

#define MAX_VAR_NAME 2048
#define MAX_VAR_COUNT 2048

#define FW_VAR_POOL_SIGNATURE \
	SIGNATURE_64('F', 'W', 'V', 'A', 'R', 'P', 'O', 'O')

#pragma pack (push, 1)

typedef struct _FW_VAR
{
	GUID Guid;
	ULONG32 Attributes;
	WCHAR Name[MAX_VAR_NAME];
} FW_VAR, *PFW_VAR;

typedef struct _FW_VARS_POOL
{
	ULONG64 Signature;
	ULONG64 Count;
	FW_VAR Objects[MAX_VAR_COUNT];
} FW_VARS_POOL, *PFW_VARS_POOL;

#pragma pack (pop)

#define EFI_VARIABLE_NON_VOLATILE 	0x00000001
#define EFI_VARIABLE_BOOTSERVICE_ACCESS 	0x00000002
#define EFI_VARIABLE_RUNTIME_ACCESS 	0x00000004
#define EFI_VARIABLE_HARDWARE_ERROR_RECORD 	0x00000008
#define EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS 	0x00000010
#define EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS 	0x00000020
#define EFI_VARIABLE_APPEND_WRITE 	0x00000040

//
// Firmware variables with both BS and BS+RT attributes
//
// FwVarsBase and FwVarsBase2 are stored as physical address to virtual address to
// variable storage.
//
// FwVars and FwVars2 are stored as virtual address to the variable storage.
//
extern PHYSICAL_ADDRESS EfiFwVarsBase;
extern PFW_VARS_POOL EfiFwVars;

//
// Firmware variables with only BS+RT attributes
//
extern PHYSICAL_ADDRESS EfiFwVarsBase2;
extern PFW_VARS_POOL EfiFwVars2;

#define MAX_MEMORY_MAP 256

/* 'FWMEMMAP' */
#define FW_MMAP_SIGNATURE \
  SIGNATURE_64('F', 'W', 'M', 'E', 'M', 'M', 'A', 'P')

#pragma pack (push, 1)

typedef struct _FW_MMAPE
{
	ULONG32 Type;
	ULONG64 PhysicalAddress;
	ULONG64 VirtualAddress;
	ULONG64 NumberOf4KPages;
	ULONG64 Attributes;
} FW_MMAPE, *PFW_MMAPE;

typedef struct _FW_MMAP
{
	ULONG64 Signature;
	ULONG64 Count;
	FW_MMAPE MMap[MAX_MEMORY_MAP];
} FW_MMAP, *PFW_MMAP;

#pragma pack (pop)

enum _FW_MMAPE_TYPE
{
	EfiReservedMemoryType,
	EfiLoaderCode,
	EfiLoaderData,
	EfiBootServicesCode,
	EfiBootServicesData,
	EfiRuntimeServicesCode,
	EfiRuntimeServicesData,
	EfiConventionalMemory,
	EfiUnusableMemory,
	EfiACPIReclaimMemory,
	EfiACPIMemoryNVS,
	EfiMemoryMappedIO,
	EfiMemoryMappedIOPortSpace,
	EfiPalCode,
	EfiPersistentMemory,
	EfiMaxMemoryType
};

#define EFI_MEMORY_UC               0x0000000000000001ULL
#define EFI_MEMORY_WC               0x0000000000000002ULL
#define EFI_MEMORY_WT               0x0000000000000004ULL
#define EFI_MEMORY_WB               0x0000000000000008ULL
#define EFI_MEMORY_UCE              0x0000000000000010ULL

#define EFI_MEMORY_WP               0x0000000000001000ULL
#define EFI_MEMORY_RP               0x0000000000002000ULL
#define EFI_MEMORY_XP               0x0000000000004000ULL
#define EFI_MEMORY_RO               0x0000000000020000ULL

#define EFI_MEMORY_NV               0x0000000000008000ULL
#define EFI_MEMORY_MORE_RELIABLE    0x0000000000010000ULL
#define EFI_MEMORY_SP               0x0000000000040000ULL
#define EFI_MEMORY_CPU_CRYPTO       0x0000000000080000ULL
#define EFI_MEMORY_RUNTIME          0x8000000000000000ULL

//
// Physical address of the FW_MMAP structure allocated by runtime driver
//

extern PHYSICAL_ADDRESS EfiFwMmapBase;

DRIVER_INITIALIZE DriverEntry;

DRIVER_UNLOAD MyUnload;

_Dispatch_type_(IRP_MJ_OTHER)
DRIVER_DISPATCH MyDispatchPassThrough;

NTSTATUS
ScanList(
	_In_ ULONG_PTR PhysicalAddress
	);

NTSTATUS
ReadPhysicalAddressFromEfiVar(
	_In_ PCWSTR VarName,
	_Out_ PPHYSICAL_ADDRESS Address
	);

NTSTATUS
GetRuntimeListHeadPA(
	_Out_ PULONG_PTR RuntimeListHead
	);

NTSTATUS
InitFwVarsBaseAddress(VOID);

NTSTATUS
InitFwMmapBaseAddress(VOID);

NTSTATUS
ReadRuntimeModuleList(VOID);

NTSTATUS
DumpFwVars(
	_In_   PFW_VARS_POOL    FwVars,
	_In_   PCWSTR           RegistryPath
	);

NTSTATUS
DumpFwMmap(
	_In_ PCWSTR RegistryPath
	);

NTSTATUS
MyKeySetString(
	_In_ HANDLE KeyHandle,
	_In_ PUNICODE_STRING ValueName,
	_In_ PWSTR StringValue
	);

NTSTATUS
DumpRuntimeDrivers(
	_In_ PCWSTR RegistryPath
	);

NTSTATUS
ReadVirtualPointer(
	_In_    PHYSICAL_ADDRESS   PhysicalAddress,
	_Out_   PVOID              *VirtualAddress
	);

KBUGCHECK_REASON_CALLBACK_ROUTINE AddPagesForRuntimeModulesCallbackRoutine;
KBUGCHECK_REASON_CALLBACK_ROUTINE AddPagesForFwVars2CallbackRoutine;
KBUGCHECK_REASON_CALLBACK_ROUTINE AddPagesForFwVarsCallbackRoutine;
KBUGCHECK_REASON_CALLBACK_ROUTINE AddPagesForFwMmapCallbackRoutine;

// f08ae394-4e98-46e6-b3b0-1bb940ac663d
DEFINE_GUID(GUID_MY_VENDOR, 0xf08ae394, 0x4e98, 0x46e6, 0xb3, 0xb0, 0x1b, 0xb9, 0x40, 0xac, 0x66, 0x3d);

#define MyDbgPrint(STR, ...) DbgPrint("efihlp: " STR, __VA_ARGS__)
