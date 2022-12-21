#include <windows.h>
#include <atlbase.h>
#include <sal.h>

#ifdef _WIN64
#define KDEXT_64BIT
#else
#define KDEXT_32BIT
#endif

#include <wdbgexts.h>
#include <dbgeng.h>

#include <array>

WINDBG_EXTENSION_APIS ExtensionApis;

#define MAX_DEVICE_PATH 256
#define MAX_MODULE_NAME 256

#define RTMODULE_SIGNATURE \
	SIGNATURE_64('R', 'T', 'M', 'o', 'd', 'u', 'l', 'e')

typedef struct _EFI_MODULE64
{
	LIST_ENTRY64 Link;
	ULONG32 Version;
	ULONG64 ImageBasePhysical;
	ULONG64 ImageSize;
	ULONG64 ImageBaseVirtual;
	WCHAR DevicePath[MAX_DEVICE_PATH];
	WCHAR ModuleName[MAX_MODULE_NAME];
	ULONG64 SourceDataPhysical;
} EFI_MODULE64, *PEFI_MODULE64;

typedef struct _EFI_MODULE32
{
	LIST_ENTRY32 Link;
	ULONG32 Version;
	ULONG32 ImageBasePhysical;
	ULONG64 ImageSize;
	ULONG32 ImageBaseVirtual;
	WCHAR DevicePath[MAX_DEVICE_PATH];
	WCHAR ModuleName[MAX_MODULE_NAME];
	ULONG32 SourceDataPhysical;
} EFI_MODULE32, *PEFI_MODULE32;

#define MAX_VAR_NAME 2048
#define MAX_VAR_COUNT 2048

#define SIGNATURE_16(A, B) \
	((A) | (B << 8))
#define SIGNATURE_32(A, B, C, D) \
	(SIGNATURE_16 (A, B) | (SIGNATURE_16 (C, D) << 16))
#define SIGNATURE_64(A, B, C, D, E, F, G, H) \
	(SIGNATURE_32 (A, B, C, D) | ((ULONG64) (SIGNATURE_32 (E, F, G, H)) << 32))

#define RUNT_SERV_SIGNATURE \
	SIGNATURE_64('R', 'U', 'N', 'T', 'S', 'E', 'R', 'V')

#define FW_VAR_POOL_SIGNATURE \
	SIGNATURE_64('F', 'W', 'V', 'A', 'R', 'P', 'O', 'O')

#pragma pack (push, 1)

typedef struct _FW_VAR
{
	GUID Guid;
	UINT32 Attributes;
	WCHAR Name[MAX_VAR_NAME];
} FW_VAR, *PFW_VAR;

typedef struct _FW_VARS_POOL
{
	ULONG64 Signature;
	ULONG64 Count;
	FW_VAR Objects[MAX_VAR_COUNT];
} FW_VARS_POOL, *PFW_VARS_POOL;

#pragma pack (pop)

#define EFI_VARIABLE_NON_VOLATILE 0x00000001
#define EFI_VARIABLE_BOOTSERVICE_ACCESS 0x00000002
#define EFI_VARIABLE_RUNTIME_ACCESS 0x00000004
#define EFI_VARIABLE_HARDWARE_ERROR_RECORD 0x00000008
#define EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS 0x00000020
#define EFI_VARIABLE_APPEND_WRITE 0x00000040
#define EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS 0x00000010

static auto PXE_BASE = 0xFFFFF6FB7DBED000ULL;
static auto PPE_BASE = 0xFFFFF6FB7DA00000ULL;
static auto PDE_BASE = 0xFFFFF6FB40000000ULL;
static auto PTE_BASE = 0xFFFFF68000000000ULL;

#define PTE_SHIFT 12
#define PDE_SHIFT 21
#define PPE_SHIFT 30
#define PXE_SHIFT 39

typedef struct _MMPTE_HARDWARE
{
	ULONG64 Valid : 1;
	ULONG64 Write : 1;
	ULONG64 Owner : 1;
	ULONG64 WriteThrough : 1;
	ULONG64 CacheDisable : 1;
	ULONG64 Accessed : 1;
	ULONG64 Dirty : 1;
	ULONG64 LargePage : 1;
	ULONG64 Global : 1;
	ULONG64 CopyOnWrite : 1;
	ULONG64 Prototype : 1;
	ULONG64 Reserved0 : 1;
	ULONG64 PageFrameNumber : 28;
	ULONG64 Reserved1 : 12;
	ULONG64 SoftwareWsIndex : 11;
	ULONG64 NoExecute : 1;
} MMPTE_HARDWARE, *PMMPTE_HARDWARE;

struct _MI_SYSTEM_VA_ASSIGNMENT64
{
	ULONG64 BaseAddress;
	ULONG64 NumberOfBytes;
};

enum _MI_SYSTEM_VA_TYPE : UCHAR
{
	MiVaUnused = 0,
	MiVaSessionSpace = 1,
	MiVaProcessSpace = 2,
	MiVaBootLoaded = 3,
	MiVaPfnDatabase = 4,
	MiVaNonPagedPool = 5,
	MiVaPagedPool = 6,
	MiVaSpecialPoolPaged = 7,
	MiVaSystemCache = 8,
	MiVaSystemPtes = 9,
	MiVaHal = 10,
	MiVaSessionGlobalSpace = 11,
	MiVaDriverImages = 12,
	MiVaSpecialPoolNonPaged = 13,
	MiVaMaximumType = 14
};

enum _MI_ASSIGNED_REGION_TYPES : ULONG32
{
	AssignedRegionNonPagedPool = 0,
	AssignedRegionPagedPool = 1,
	AssignedRegionSystemCache = 2,
	AssignedRegionSystemPtes = 3,
	AssignedRegionUltraZero = 4,
	AssignedRegionPfnDatabase = 5,
	AssignedRegionCfg = 6,
	AssignedRegionHyperSpace = 7,
	AssignedRegionKernelStacks = 8,
	AssignedRegionPageTables = 9,
	AssignedRegionSession = 10,
	AssignedRegionSecureNonPagedPool = 11,
	AssignedRegionSystemImages = 12,
	AssignedRegionMaximum = 13
};

static
ULONG64
MiPxeToAddress(
	_In_ ULONG64 PxeVa)
{
	return (ULONG64)(((LONG64)PxeVa << 52) >> 16);
}

static
ULONG64
MiPpeToAddress(
	_In_ ULONG64 PpeVa)
{
	return (ULONG64)((LONG64)PpeVa << 43) >> 16;
}

static
ULONG64
MiPdeToAddress(
	_In_ ULONG64 PdeVa)
{
	return (ULONG64)(((LONG64)PdeVa << 34) >> 16);
}

static
ULONG64
MiPteToAddress(
	_In_ ULONG64 PointerPte)
{
	return (ULONG64)(((LONG64)PointerPte << 25) >> 16);
}

static
ULONG64
MiAddressToPxe(
	_In_ ULONG64 Address)
{
	ULONG64 Offset = Address >> (PXE_SHIFT - 3);
	Offset &= 0x1FFULL << 3;
	return PXE_BASE + Offset;
}

static
ULONG64
MiAddressToPpe(
	_In_ ULONG64 Address)
{
	ULONG64 Offset = Address >> (PPE_SHIFT - 3);
	Offset &= 0x3FFFFULL << 3;
	return PPE_BASE + Offset;
}

static
ULONG64
MiAddressToPde(
	_In_ ULONG64 Address)
{
	ULONG64 Offset = Address >> (PDE_SHIFT - 3);
	Offset &= 0x7FFFFFFULL << 3;
	return PDE_BASE + Offset;
}

static
ULONG64
MiAddressToPte(
	_In_ ULONG64 Address)
{
	ULONG64 Offset = Address >> (PTE_SHIFT - 3);
	Offset &= 0xFFFFFFFFFULL << 3;
	return PTE_BASE + Offset;
}

EXTERN_C
HRESULT
WDBGAPI
lsefi(
    _In_ PDEBUG_CLIENT4 Client,
    _In_ PCSTR Args)
{
	ULONG64 kgEfiRuntimeListHead;
	LIST_ENTRY64 ListHead;
	ULONG cbBytesRead;
	ULONG64 kulListElem;
	ULONG64 kulListHead;
	EFI_MODULE64 Module64;
	HRESULT hr;
	CComPtr<IDebugSymbols3> DebugSymbols;
	ULONG ulStatus;
	CHAR aModuleName[MAX_MODULE_NAME];
	CHAR aDevicePath[MAX_DEVICE_PATH];
	CHAR aSyntheticModuleName[MAX_MODULE_NAME];

	// dt efihlp!_EFI_MODULE -l Link.Flink <va>

	hr = Client->QueryInterface(IID_PPV_ARGS(&DebugSymbols));
	if (FAILED(hr)) {
		return hr;
	}

	kgEfiRuntimeListHead = GetExpression("efihlp!EfiRuntimeListHead"); // PLIST_ENTRY
	if (kgEfiRuntimeListHead == 0)
	{
		dprintf("efihlp!EfiRuntimeListHead not found\n");
		return E_FAIL;
	}

	//
	// Read LIST_ENTRY head to set list terminator
	//

	if (ReadListEntry(kgEfiRuntimeListHead, &ListHead) != 0)
	{
		kulListHead = ListHead.Flink;
		kulListElem = kulListHead;

		//
		// Now read all list elements
		//

		while (ReadListEntry(kulListElem, &ListHead) != 0)
		{
			kulListElem = ListHead.Flink;
			if (kulListElem == kulListHead)
				break;

			// FIELD_OFFSET(EFI_MODULE64, Link) == 0
			ulStatus = ReadMemory(kulListElem, &Module64, sizeof(EFI_MODULE64), &cbBytesRead);
			if (ulStatus == 0 || cbBytesRead < sizeof(EFI_MODULE64))
				continue;

			//
			// Ensure that our driver has compatible version
			//
			if (Module64.Version < sizeof(EFI_MODULE64))
			{
				dprintf("Driver efihlp.sys is outdated: %d\n", Module64.Version);
				break;
			}

			WideCharToMultiByte(CP_ACP, 0, Module64.ModuleName, MAX_MODULE_NAME, aModuleName, sizeof(aModuleName), NULL, NULL);
			WideCharToMultiByte(CP_ACP, 0, Module64.DevicePath, MAX_DEVICE_PATH, aDevicePath, sizeof(aDevicePath), NULL, NULL);

			if (strlen(aModuleName) != 0)
			{
				strcpy_s(aSyntheticModuleName, aModuleName);
			}
			else if (strlen(aDevicePath) != 0)
			{
				LPSTR lpFileName = PathFindFileNameA(aDevicePath);
				strcpy_s(aSyntheticModuleName, lpFileName);
				PathRemoveExtensionA(aSyntheticModuleName);
			}
			else
			{
				sprintf_s(aSyntheticModuleName, "efi%016I64x", Module64.ImageBasePhysical);
			}

			dprintf("%p: %s (%d bytes)\n", (ULONG_PTR)Module64.ImageBaseVirtual, aSyntheticModuleName, Module64.ImageSize);

			if (Module64.ImageSize > ULONG_MAX)
			{
				continue;
			}

			hr = DebugSymbols->AddSyntheticModule(
				Module64.ImageBaseVirtual,
				(ULONG) Module64.ImageSize,
				aModuleName,
				aSyntheticModuleName,
				DEBUG_ADDSYNTHMOD_DEFAULT);
			if (FAILED(hr))
			{
				dprintf("Warning: AddSynthethicModule failed: 0x%08x\n", hr);
			}
		}
	}

	return S_OK;
}

static
HRESULT
EnumerateEfiVariables(
	_In_ PDEBUG_CLIENT4 Client,
	_In_ ULONG64 kFwVarsBase)
{
	ULONG64 kgFwVarsBase;
	ULONG cbBytesRead;
	HRESULT hr;
	CComPtr<IDebugSymbols3> DebugSymbols;
	ULONG ulStatus;
	CHAR aFwVarName[MAX_VAR_NAME];
	LARGE_INTEGER liFwVarsBase;
	ULONG Index;
	FW_VAR FwVar;
	ULONG64 ulFwVarCount;
	ULONG64 ullFwVarSignature;
	GUID Guid;
	ULONG64 kulFwVarBaseOffset;

	hr = Client->QueryInterface(IID_PPV_ARGS(&DebugSymbols));
	if (FAILED(hr)) {
		return hr;
	}

	kgFwVarsBase = kFwVarsBase;

	ulStatus = ReadMemory(kgFwVarsBase, &liFwVarsBase, sizeof(LARGE_INTEGER), &cbBytesRead);
	if (ulStatus == 0 || cbBytesRead < sizeof(LARGE_INTEGER))
	{
		dprintf("ReadMemory failed\n");
		return E_FAIL;
	}

	kulFwVarBaseOffset = liFwVarsBase.QuadPart + FIELD_OFFSET(FW_VARS_POOL, Signature);
	ulStatus = ReadMemory(kulFwVarBaseOffset, &ullFwVarSignature, sizeof(ULONG64), &cbBytesRead);
	if (ulStatus == 0 ||
		cbBytesRead < sizeof(ULONG64) ||
		ullFwVarSignature != FW_VAR_POOL_SIGNATURE)
	{
		dprintf("Failed to verify FwVarsPool signature!\n");
		return E_FAIL;
	}

	kulFwVarBaseOffset = liFwVarsBase.QuadPart + FIELD_OFFSET(FW_VARS_POOL, Count);
	ulStatus = ReadMemory(kulFwVarBaseOffset, &ulFwVarCount, sizeof(ULONG64), &cbBytesRead);
	if (ulStatus == 0 || cbBytesRead < sizeof(ULONG64))
	{
		dprintf("ReadMemory failed while reading Count\n");
		return E_FAIL;
	}

	dprintf("EFI variable count: %d\n", ulFwVarCount);

	kulFwVarBaseOffset = liFwVarsBase.QuadPart + FIELD_OFFSET(FW_VARS_POOL, Objects);
	for (Index = 0; Index < ulFwVarCount; ++Index, kulFwVarBaseOffset += sizeof(FW_VAR))
	{
		ulStatus = ReadMemory(kulFwVarBaseOffset, &FwVar, sizeof(FW_VAR), &cbBytesRead);
		if (ulStatus == 0 || cbBytesRead < sizeof(FW_VAR))
		{
			dprintf("ReadMemory failed while reading FW_VAR\n");
			continue;
		}

		Guid = FwVar.Guid;

		aFwVarName[0] = '\0';

		WideCharToMultiByte(CP_ACP, 0, FwVar.Name, -1, aFwVarName, ARRAYSIZE(aFwVarName), NULL, NULL);

		dprintf("%c%c%c%c%c%c%c {%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}-%s\n",
			((FwVar.Attributes & EFI_VARIABLE_BOOTSERVICE_ACCESS) ? 'B' : ' '),
			((FwVar.Attributes & EFI_VARIABLE_RUNTIME_ACCESS) ? 'R' : ' '),
			((FwVar.Attributes & EFI_VARIABLE_NON_VOLATILE) ? 'N' : ' '),
			((FwVar.Attributes & EFI_VARIABLE_APPEND_WRITE) ? 'P' : ' '),
			((FwVar.Attributes & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) ? 'T' : ' '),
			((FwVar.Attributes & EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS) ? 'A' : ' '),
			((FwVar.Attributes & EFI_VARIABLE_HARDWARE_ERROR_RECORD) ? 'H' : ' '),
			Guid.Data1,
			Guid.Data2,
			Guid.Data3,
			Guid.Data4[0], Guid.Data4[1], Guid.Data4[2], Guid.Data4[3],
			Guid.Data4[4], Guid.Data4[5], Guid.Data4[6], Guid.Data4[7],
			aFwVarName);
	}

	return S_OK;
}

EXTERN_C
HRESULT
WDBGAPI
efivars(
	_In_ PDEBUG_CLIENT4 Client,
	_In_ PCSTR Args)
{
	ULONG64 kgFwVarsBase;

	if (strlen(Args) == 0)
	{
		kgFwVarsBase = GetExpression("efihlp!EfiFwVars"); // PLARGE_INTEGER
		if (kgFwVarsBase == 0)
		{
			dprintf("efihlp!EfiFwVars not found\n");
			return E_FAIL;
		}
	}
	else
	{
		kgFwVarsBase = GetExpression(Args); // PLARGE_INTEGER
	}

	return EnumerateEfiVariables(Client, kgFwVarsBase);
}

HRESULT
ReadPageTables(
	_In_ IDebugDataSpaces4 *Data,
	_In_ ULONG64 PteBase,
	_Out_ std::array<MMPTE_HARDWARE, 512> &PteArray)
{
	ULONG cbBytesRead = 0;
	HRESULT hr;
	ULONG cbRequest = (ULONG)(PteArray.size() * sizeof(MMPTE_HARDWARE));

	hr = Data->ReadVirtual(PteBase, PteArray.data(), cbRequest, &cbBytesRead);

	// 0x8007001e: ERROR_READ_FAULT
	// 0x80004002: page not present

	if (cbBytesRead != cbRequest)
		return E_FAIL;

	return hr;
}

EXTERN_C
HRESULT
WDBGAPI
findfwmem(
	_In_ PDEBUG_CLIENT4 Client,
	_In_ PCSTR Args)
{
	HRESULT hr;
	ULONG cbBytesRead;

	CComPtr<IDebugSymbols4> DebugSymbols;
	CComPtr<IDebugDataSpaces4> DebugData;

	ULONG64 MmSystemRangeStartOffset = 0;
	ULONG64 kMmSystemRangeStart = 0;
	ULONG64 SelfRef;
	ULONG NtModule;
	ULONG64 NtModuleBase;
	ULONG64 kMmPteBaseOffset;
	ULONG64 MmPteBase;
	ULONG MiVisibleStateTypeId;
	ULONG64 MiVisibleStateOffset;
	ULONG64 kMiVisibleState;

	ULONG SystemVaRegionsOffset;
	ULONG SystemVaTypeOffset;

	hr = Client->QueryInterface(IID_PPV_ARGS(&DebugSymbols));
	if (FAILED(hr))
	{
		dprintf("Failed to get IDebugSymbols4: 0x%08x\n", hr);
		return hr;
	}

	hr = Client->QueryInterface(IID_PPV_ARGS(&DebugData));
	if (FAILED(hr))
	{
		dprintf("Failed to get IDebugDataSpaces: 0x%08x\n", hr);
		return hr;
	}

	//
	// Read nt!MmSystemRangeStart
	//

	hr = DebugSymbols->GetOffsetByName("nt!MmSystemRangeStart", &MmSystemRangeStartOffset);
	if (FAILED(hr))
	{
		dprintf("nt!MmSystemRangeStart offset not found: 0x%08x\n", hr);
		return hr;
	}

	hr = DebugData->ReadPointersVirtual(1, MmSystemRangeStartOffset, &kMmSystemRangeStart);
	if (FAILED(hr))
	{
		// wtf 0x8007001e
		dprintf("ReadPointersVirtual(1) returned 0x%08x\n", hr);
		return hr;
	}

	//
	// Read nt!MmPteBase
	//

	hr = DebugSymbols->GetOffsetByName("nt!MmPteBase", &kMmPteBaseOffset);
	if (FAILED(hr))
	{
		return hr;
	}

	hr = DebugData->ReadPointersVirtual(1, kMmPteBaseOffset, &MmPteBase);
	if (FAILED(hr))
	{
		dprintf("ReadPointersVirtual(2) returned 0x%08x\n", hr);
		return hr;
	}

	hr = DebugSymbols->GetModuleByModuleName("nt", 0, &NtModule, &NtModuleBase);
	if (FAILED(hr))
	{
		dprintf("GetModuleByModuleName returned 0x%08x\n", hr);
		return hr;
	}

	SelfRef = (MmPteBase >> PXE_SHIFT) & 0x1ff;

	PXE_BASE = (0xffffULL << 48) | (SelfRef << PXE_SHIFT) | (SelfRef << PPE_SHIFT) | (SelfRef << PDE_SHIFT) | (SelfRef << PTE_SHIFT);
	PPE_BASE = (0xffffULL << 48) | (SelfRef << PXE_SHIFT) | (SelfRef << PPE_SHIFT) | (SelfRef << PDE_SHIFT);
	PDE_BASE = (0xffffULL << 48) | (SelfRef << PXE_SHIFT) | (SelfRef << PPE_SHIFT);
	PTE_BASE = (0xffffULL << 48) | (SelfRef << PXE_SHIFT);

	//
	// Read nt!MiVisibleState and obtain SystemVaType array
	//

	hr = DebugSymbols->GetOffsetByName("nt!MiVisibleState", &MiVisibleStateOffset);
	if (FAILED(hr))
		return hr;

	hr = DebugData->ReadPointersVirtual(1, MiVisibleStateOffset, &kMiVisibleState);
	if (FAILED(hr))
		return hr;

	hr = DebugSymbols->GetTypeId(NtModuleBase, "_MI_VISIBLE_STATE", &MiVisibleStateTypeId);
	if (FAILED(hr))
		return hr;

	hr = DebugSymbols->GetFieldOffset(NtModuleBase, MiVisibleStateTypeId, "SystemVaRegions", &SystemVaRegionsOffset);
	if (FAILED(hr))
		return hr;

	hr = DebugSymbols->GetFieldOffset(NtModuleBase, MiVisibleStateTypeId, "SystemVaType", &SystemVaTypeOffset);
	if (FAILED(hr))
		return hr;

	std::array<MMPTE_HARDWARE, 512> PxeArray;
	hr = ReadPageTables(DebugData, PXE_BASE, PxeArray);
	if (FAILED(hr))
	{
		dprintf("ReadPageTables returned 0x%08x\n", hr);
		return hr;
	}

	std::array<UCHAR, 256> MiSystemVaType;
	hr = DebugData->ReadVirtual(
		kMiVisibleState + SystemVaTypeOffset,
		MiSystemVaType.data(),
		(ULONG)sizeof(MiSystemVaType),
		&cbBytesRead);
	if (FAILED(hr))
	{
		dprintf("ReadSystemVaType returned 0x%08x\n", hr);
		return hr;
	}

	std::array<_MI_SYSTEM_VA_ASSIGNMENT64, AssignedRegionMaximum> MiSystemVaRegions;
	hr = DebugData->ReadVirtual(
		kMiVisibleState + SystemVaRegionsOffset,
		MiSystemVaRegions.data(),
		(ULONG)sizeof(MiSystemVaRegions),
		&cbBytesRead);
	if (FAILED(hr))
	{
		dprintf("ReadSystemVaRegions returned 0x%08x\n", hr);
		return hr;
	}

	//
	// According to my observations runtime EFI memory can be marked 3h (MiVaBootLoaded) is SystemVaType array, or
	// located in AssignedRegionSystemImages element of SystemVaRegions.
	//

	ULONG64 SystemImages0 =
		MiSystemVaRegions[AssignedRegionSystemImages].BaseAddress;
	ULONG64 SystemImages1 =
		MiSystemVaRegions[AssignedRegionSystemImages].BaseAddress +
		MiSystemVaRegions[AssignedRegionSystemImages].NumberOfBytes;

	ULONG64 PxeOffset = MiAddressToPxe(kMmSystemRangeStart);
	ULONG64 PxeIndex0 = (PxeOffset - PXE_BASE) / sizeof(MMPTE_HARDWARE);
	for (; PxeIndex0 < 512; PxeOffset += sizeof(MMPTE_HARDWARE), ++PxeIndex0)
	{
		MMPTE_HARDWARE Pxe = PxeArray[PxeIndex0];
		if (!Pxe.Valid)
			continue;

		ULONG64 PpeOffset = PPE_BASE + 0x1000 * PxeIndex0;
		std::array<MMPTE_HARDWARE, 512> PpeArray;

		hr = ReadPageTables(DebugData, PpeOffset, PpeArray);
		if (FAILED(hr))
		{
			dprintf("ReadPageTables (PPE 0x%016I64x) returned 0x%08x\n", PpeOffset, hr);
			return hr;
		}

		ULONG64 SystemVaTypeIndex = (PxeOffset - MiAddressToPxe(kMmSystemRangeStart)) / sizeof(MMPTE_HARDWARE);
		dprintf("PxeIndex0 %d -> 0x%016I64x\n", PxeIndex0, MiPxeToAddress(PxeOffset));

		if (MiSystemVaType[SystemVaTypeIndex] != MiVaBootLoaded)
		{
			if (MiPxeToAddress(PxeOffset + sizeof(MMPTE_HARDWARE)) < SystemImages0)
				continue;
			if (MiPxeToAddress(PxeOffset) >= SystemImages1)
				continue;
		}

		ULONG64 PpeIndex0 = (PpeOffset - PPE_BASE) / sizeof(MMPTE_HARDWARE);
		for (ULONG64 PpeIndex1 = 0; PpeIndex1 < 512; PpeOffset += sizeof(MMPTE_HARDWARE), ++PpeIndex0, ++PpeIndex1)
		{
			MMPTE_HARDWARE Ppe = PpeArray[PpeIndex1];
			if (!Ppe.Valid || Ppe.LargePage)
				continue;

			ULONG64 PdeOffset = PDE_BASE + 0x1000 * PpeIndex0;
			std::array<MMPTE_HARDWARE, 512> PdeArray;
			hr = ReadPageTables(DebugData, PdeOffset, PdeArray);
			if (FAILED(hr))
			{
				dprintf("ReadPageTables (PDE 0x%016I64x) returned 0x%08x\n", PdeOffset, hr);
				continue;
			}

			ULONG64 PdeIndex0 = (PdeOffset - PDE_BASE) / sizeof(MMPTE_HARDWARE);
			for (ULONG64 PdeIndex1 = 0; PdeIndex1 < 512; PdeOffset += sizeof(MMPTE_HARDWARE), ++PdeIndex0, ++PdeIndex1)
			{
				MMPTE_HARDWARE Pde = PdeArray[PdeIndex1];
				if (!Pde.Valid || Pde.LargePage)
					continue;

				ULONG64 PteOffset = PTE_BASE + 0x1000 * PdeIndex0;
				std::array<MMPTE_HARDWARE, 512> PteArray;
				hr = ReadPageTables(DebugData, PteOffset, PteArray);
				if (FAILED(hr))
				{
					dprintf("ReadPageTables (PTE 0x%016I64x) returned 0x%08x\n", PteOffset, hr);
					continue;
				}

				for (ULONG64 PteIndex1 = 0; PteIndex1 < 512; PteOffset += sizeof(MMPTE_HARDWARE), ++PteIndex1)
				{
					if (CheckControlC() != 0)
						goto Interrupted;

					MMPTE_HARDWARE Pte = PteArray[PteIndex1];
					if (!Pte.Valid)
						continue;

					ULONG64 VirtualAddress = MiPteToAddress(PteOffset);
					ULONG64 ProbeBytes;

					if (MiSystemVaType[SystemVaTypeIndex] != MiVaBootLoaded)
					{
						if (VirtualAddress < SystemImages0) continue;
						if (VirtualAddress >= SystemImages1) continue;
					}

					hr = DebugData->ReadPhysical(Pte.PageFrameNumber * 0x1000, &ProbeBytes, sizeof(ULONG64), &cbBytesRead);
					if (FAILED(hr) || sizeof(ULONG64) != cbBytesRead)
					{
						if (hr != 0x80004002)
						{
							dprintf("ReadPhysical returned 0x%08x (VA: 0x%016I64x)\n", hr, VirtualAddress);
						}
						continue;
					}

					switch (ProbeBytes) {
					case RTMODULE_SIGNATURE:
						dprintf("Runtime Module detected at 0x%016I64x\n", VirtualAddress);
						break;
					case FW_VAR_POOL_SIGNATURE:
						dprintf("FW_VAR_POOL detected at 0x%016I64x\n", VirtualAddress);
						break;
					case RUNT_SERV_SIGNATURE:
						// gRT = 0xfffff802`2aaf3b98
						// 0: kd > !pte 0xfffff802`2aaf3b98
						// VA fffff8022aaf3b98
						// PXE at FFFF9148A4522F80    PPE at FFFF9148A45F0040    PDE at FFFF9148BE008AA8    PTE at FFFF917C01155798
						// contains 0000000001108063  contains 0000000001109063  contains 000000000112F063  contains 090000007EFEE863
						// pfn 1108      -- - DA--KWEV  pfn 1109      -- - DA--KWEV  pfn 112f-- - DA--KWEV  pfn 7efee-- - DA--KWEV
						dprintf("RUNTSERV detected at 0x%016I64x\n", VirtualAddress);
						break;
					}
				}
			}
		}
	}

Interrupted:

	return S_OK;
}

EXTERN_C
__declspec(dllexport)
HRESULT
WDBGAPI
DebugExtensionInitialize(
	_Out_ PULONG Version,
	_Out_ PULONG Flags)
{
	IDebugClient* DebugClient;
	ULONG DebuggeeClass;
	ULONG DebuggeeQualifier;
	HRESULT hr;
	CComPtr<IDebugControl> DebugControl;

	*Version = DEBUG_EXTENSION_VERSION(0, 1);
	*Flags = 0;

	hr = DebugCreate(__uuidof(IDebugClient), (void**)&DebugClient);
	if (FAILED(hr))
	{
		return hr;
	}

	hr = DebugClient->QueryInterface(IID_PPV_ARGS(&DebugControl));
	if (SUCCEEDED(hr))
	{
		RtlZeroMemory(&ExtensionApis, sizeof(WINDBG_EXTENSION_APIS));
		ExtensionApis.nSize = sizeof(WINDBG_EXTENSION_APIS);
		hr = DebugControl->GetWindbgExtensionApis64(&ExtensionApis);

		hr = DebugControl->GetDebuggeeType(&DebuggeeClass, &DebuggeeQualifier);
		if (SUCCEEDED(hr))
		{
			if (DebuggeeClass != DEBUG_CLASS_KERNEL)
			{
				dprintf("Only kernel debug connection is supported\n");
				hr = S_FALSE;
			}
		}

		if (!IsPtr64())
		{
			dprintf("Only 64-bit targets are supported\n");
			hr = S_FALSE;
		}
	}
	DebugClient->Release();
	return hr;
}

EXTERN_C
__declspec(dllexport)
VOID
WDBGAPI
DebugExtensionUninitialize(void)
{
}

BOOL
APIENTRY
DllMain(
	_In_ HMODULE hModule,
	_In_ DWORD dwReason,
	_In_ LPVOID lpReserved
)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}