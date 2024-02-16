#include "TraceCleaner.hpp"

typedef struct _PIDDB_CACHE_ENTRY
{
	LIST_ENTRY		List;
	UNICODE_STRING	DriverName;
	ULONG			TimeDateStamp;
	NTSTATUS		LoadStatus;
	char			_0x0028[16];
} PIDDB_CACHE_ENTRY, * PPIDDB_CACHE_ENTRY;

typedef struct _HASH_BUCKET_ENTRY
{
	struct _HASH_BUCKET_ENTRY* Next;
	UNICODE_STRING DriverName;
	ULONG CertHash[5];
} HASH_BUCKET_ENTRY, * PHASH_BUCKET_ENTRY;

typedef struct _RTL_BALANCED_LINKS
{
	struct _RTL_BALANCED_LINKS* Parent;
	struct _RTL_BALANCED_LINKS* LeftChild;
	struct _RTL_BALANCED_LINKS* RightChild;
	CHAR Balance;
	UCHAR Reserved[3];
} RTL_BALANCED_LINKS;
typedef RTL_BALANCED_LINKS* PRTL_BALANCED_LINKS;

typedef struct _RTL_AVL_TABLE
{
	RTL_BALANCED_LINKS BalancedRoot;
	PVOID OrderedPointer;
	ULONG WhichOrderedElement;
	ULONG NumberGenericTableElements;
	ULONG DepthOfTree;
	PVOID RestartKey;
	ULONG DeleteCount;
	PVOID CompareRoutine;
	PVOID AllocateRoutine;
	PVOID FreeRoutine;
	PVOID TableContext;
} RTL_AVL_TABLE;
typedef RTL_AVL_TABLE* PRTL_AVL_TABLE;

typedef struct _SYSTEM_HANDLE
{
	PVOID Object;
	HANDLE UniqueProcessId;
	HANDLE HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG_PTR HandleCount;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

bool TraceCleaner::ExAcquireResourceExclusiveLite(PVOID Resource, BOOLEAN Wait)
{
	if (!Resource)
		return 0;

	static auto pExAcquireResourceExclusiveLite = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("ExAcquireResourceExclusiveLite"));

	if (!pExAcquireResourceExclusiveLite)
	{
		printf(xor ("\n[Zalupa] Error: ExAcquireResourceExclusiveLite not found.\n"));
		return 0;
	}

	BOOLEAN out;

	return (VDM::SystemCall(pExAcquireResourceExclusiveLite, &out, Resource, Wait) && out);
}

bool TraceCleaner::ExReleaseResourceLite(PVOID Resource)
{
	if (!Resource)
		return false;

	static auto pExReleaseResourceLite = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("ExReleaseResourceLite"));

	if (!pExReleaseResourceLite)
	{
		printf(xor ("\n[Zalupa] Error: ExReleaseResourceLite not found.\n"));
		return false;
	}

	return VDM::SystemCall<void>(pExReleaseResourceLite, nullptr, Resource);
}

BOOLEAN TraceCleaner::RtlDeleteElementGenericTableAvl(PVOID Table, PVOID Buffer)
{
	if (!Table)
		return false;

	static auto pRtlDeleteElementGenericTableAvl = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("RtlDeleteElementGenericTableAvl"));

	if (!pRtlDeleteElementGenericTableAvl)
	{
		printf(xor ("\n[Zalupa] Error: RtlDeleteElementGenericTableAvl not found.\n"));
		return false;
	}

	BOOLEAN out;

	return (VDM::SystemCall(pRtlDeleteElementGenericTableAvl, &out, Table, Buffer) && out);
}

BOOLEAN DataCompare(PVOID Address, LPCSTR Pattern, LPCSTR Mask)
{
	for (auto Buffer = reinterpret_cast<PBYTE>(Address); *Mask; ++Pattern, ++Mask, ++Buffer)
	{
		if (*Mask == 'x' && *reinterpret_cast<LPCBYTE>(Pattern) != *Buffer)
			return FALSE;
	}

	return TRUE;
}

uintptr_t FindPattern(uintptr_t moduleBase, uintptr_t moduleSize, LPCSTR pattern, LPCSTR mask)
{
	moduleSize -= static_cast<DWORD>(strlen(mask));

	for (uintptr_t i = 0UL; i < moduleSize; i++)
	{
		auto pAddress = reinterpret_cast<PBYTE>(moduleBase) + i;

		if (DataCompare(pAddress, pattern, mask))
			return (uintptr_t)(pAddress);
	}

	return 0;
}

PVOID FindPatternInSection(uintptr_t moduleBase, char* sectionName, PULONG outSize)
{
	PIMAGE_NT_HEADERS pImageNtHeader = (PIMAGE_NT_HEADERS)(moduleBase + ((PIMAGE_DOS_HEADER)moduleBase)->e_lfanew);
	PIMAGE_SECTION_HEADER pFirstSection = IMAGE_FIRST_SECTION(pImageNtHeader);

	size_t nameSize = strlen(sectionName);

	for (PIMAGE_SECTION_HEADER pSectionHeader = pFirstSection;
		pSectionHeader < pFirstSection + pImageNtHeader->FileHeader.NumberOfSections; pSectionHeader++)
	{
		if (memcmp(pSectionHeader->Name, sectionName, nameSize) == 0 && strlen((char*)pSectionHeader->Name) == nameSize)
		{
			if (outSize)
				*outSize = pSectionHeader->Misc.VirtualSize;

			return (PVOID)(moduleBase + pSectionHeader->VirtualAddress);
		}
	}

	return 0;
}

uintptr_t TraceCleaner::FindPatternInKernel(uintptr_t moduleBase, uintptr_t moduleSize, LPCSTR pattern, LPCSTR mask)
{
	if (!moduleBase)
	{
		printf(xor ("\n[Zalupa] Unable to find pattern: Invalid base address.\n"));
		return 0;
	}

	BYTE* sectionData = new BYTE[moduleSize];
	VDM::ReadVirtualMemory(moduleBase, sectionData, moduleSize);

	auto result = FindPattern((uintptr_t)sectionData, moduleSize, pattern, mask);

	if (result <= 0)
	{
		printf(xor ("\n[Zalupa] Failed to find pattern.\n"));

		delete[] sectionData;
		return 0;
	}

	result = moduleBase + result - (uintptr_t)sectionData;

	delete[] sectionData;

	return result;
}

uintptr_t TraceCleaner::FindExtendedPattern(uintptr_t moduleBase, char* sectionName, PULONG outSize)
{
	if (!moduleBase)
	{
		printf(xor ("\n[Zalupa] Unable to find pattern in section: Invalid address.\n"));
		return 0;
	}

	BYTE sectionBase[0x1000];

	if (!VDM::ReadVirtualMemory(moduleBase, sectionBase, 0x1000))
	{
		printf(xor ("\n[Zalupa] Unable to find pattern in section: Invalid PE.\n"));
		return 0;
	}

	ULONG sectionSize = 0;
	auto section = (uintptr_t)FindPatternInSection((uintptr_t)sectionBase, sectionName, &sectionSize);

	if (!section || !sectionSize)
	{
		printf(xor ("\n[Zalupa] Failed to find pattern in section.\n"));
		return false;
	}

	if (outSize)
		*outSize = sectionSize;

	return section - (uintptr_t)sectionBase + moduleBase;
}

uintptr_t TraceCleaner::FindPatternInKernelSection(uintptr_t modulePtr, char* sectionName, LPCSTR bMask, LPCSTR szMask)
{
	ULONG sectionSize = 0;
	auto section = FindExtendedPattern(modulePtr, sectionName, &sectionSize);

	return FindPatternInKernel(section, sectionSize, bMask, szMask);
}

PVOID TraceCleaner::ResolveRelativeAddress(PVOID Instruction, ULONG OffsetOffset, ULONG InstructionSize)
{
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = 0;

	if (!VDM::ReadVirtualMemory(Instr + OffsetOffset, &RipOffset, sizeof(LONG)))
		return nullptr;

	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);

	return ResolvedAddr;
}

PIDDB_CACHE_ENTRY* LocatePiDDB(PRTL_AVL_TABLE PiDDBCacheTable, ULONG timeStamp)
{
	PIDDB_CACHE_ENTRY* firstEntry;

	if (!VDM::ReadMemory((uintptr_t)PiDDBCacheTable + (offsetof(struct _RTL_AVL_TABLE, BalancedRoot.RightChild)), &firstEntry, sizeof(_RTL_BALANCED_LINKS*)))
		return nullptr;

	(*(uintptr_t*)&firstEntry) += sizeof(RTL_BALANCED_LINKS);

	PIDDB_CACHE_ENTRY* cache_entry;

	if (!VDM::ReadMemory((uintptr_t)firstEntry + (offsetof(struct _PIDDB_CACHE_ENTRY, List.Flink)), &cache_entry, sizeof(_LIST_ENTRY*)))
		return nullptr;

	while (true)
	{
		ULONG itemTimeDateStamp = 0;

		if (!VDM::ReadMemory((uintptr_t)cache_entry + (offsetof(struct _PIDDB_CACHE_ENTRY, TimeDateStamp)), &itemTimeDateStamp, sizeof(ULONG)))
			return nullptr;

		if (itemTimeDateStamp == timeStamp)
			return cache_entry;

		if ((uintptr_t)cache_entry == (uintptr_t)firstEntry)
			break;

		if (!VDM::ReadMemory((uintptr_t)cache_entry + (offsetof(struct _PIDDB_CACHE_ENTRY, List.Flink)), &cache_entry, sizeof(_LIST_ENTRY*)))
			return nullptr;
	}

	return nullptr;
}

uintptr_t PiDDBLockPtr;
uintptr_t PiDDBCacheTablePtr;

bool TraceCleaner::CleanPiDDBCacheTable()
{
	if (!VDM::g_KernelBase)
	{
		printf(xor ("\n[Zalupa] Unable to clean PCT: Kernel base not found.\n"));
		return false;
	}

	PiDDBLockPtr = FindPatternInKernelSection(VDM::g_KernelBase, xor ("PAGE"),
		xor ("\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x66\xFF\x88\x00\x00\x00\x00\xB2\x01\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24"),
			xor ("xxxxxx????xxxxx????xxx????xxxxx????x????xx?x"));

	PiDDBCacheTablePtr = FindPatternInKernelSection(VDM::g_KernelBase, xor ("PAGE"), xor ("\x66\x03\xD2\x48\x8D\x0D"), xor ("xxxxxx"));

	if (!PiDDBLockPtr)
	{
		PiDDBLockPtr = FindPatternInKernelSection(VDM::g_KernelBase, xor ("PAGE"),
			xor ("\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x0F\x85\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xE8"),
				xor ("xxx????xxxxx????xxx????x????x"));

		if (!PiDDBLockPtr)
		{
			printf(xor ("\n[Zalupa] Unable to clean PCT: Lock not found.\n"));

			return false;
		}

		PiDDBLockPtr += 16;
	}
	else 
	{
		PiDDBLockPtr += 28;
	}

	if (!PiDDBCacheTablePtr)
	{
		printf(xor ("\n[Zalupa] Unable to clean PCT: Cache Table not found.\n"));
		return false;
	}

	PVOID PiDDBLock = ResolveRelativeAddress((PVOID)PiDDBLockPtr, 3, 7);
	PRTL_AVL_TABLE PiDDBCacheTable = (PRTL_AVL_TABLE)ResolveRelativeAddress((PVOID)PiDDBCacheTablePtr, 6, 10);

	VDM::SetMemory((uintptr_t)PiDDBCacheTable + (offsetof(struct _RTL_AVL_TABLE, TableContext)), 1, sizeof(PVOID));

	if (!ExAcquireResourceExclusiveLite(PiDDBLock, true))
	{
		printf(xor ("\n[Zalupa] Unable to clean PCT: Cat't lock.\n"));

		return false;
	}

	PIDDB_CACHE_ENTRY* pTargetDriverEntry = (PIDDB_CACHE_ENTRY*)LocatePiDDB(PiDDBCacheTable, 0x5AB08710);

	if (pTargetDriverEntry == nullptr)
	{
		printf(xor ("\n[Zalupa] Unable to clean PCT: Cache not found.\n"));

		ExReleaseResourceLite(PiDDBLock);

		return false;
	}

	PLIST_ENTRY prev;
	if (!VDM::ReadMemory((uintptr_t)pTargetDriverEntry + (offsetof(struct _PIDDB_CACHE_ENTRY, List.Blink)), &prev, sizeof(_LIST_ENTRY*)))
	{
		printf(xor ("\n[Zalupa] Unable to clean PCT: #1\n"));

		ExReleaseResourceLite(PiDDBLock);

		return false;
	}

	PLIST_ENTRY next;
	if (!VDM::ReadMemory((uintptr_t)pTargetDriverEntry + (offsetof(struct _PIDDB_CACHE_ENTRY, List.Flink)), &next, sizeof(_LIST_ENTRY*)))
	{
		printf(xor ("\n[Zalupa] Unable to clean PCT: #2\n"));

		ExReleaseResourceLite(PiDDBLock);

		return false;
	}

	if (!VDM::WriteMemory((uintptr_t)prev + (offsetof(struct _LIST_ENTRY, Flink)), &next, sizeof(_LIST_ENTRY*)))
	{
		printf(xor ("\n[Zalupa] Unable to clean PCT: #3\n"));

		ExReleaseResourceLite(PiDDBLock);

		return false;
	}

	if (!VDM::WriteMemory((uintptr_t)next + (offsetof(struct _LIST_ENTRY, Blink)), &prev, sizeof(_LIST_ENTRY*)))
	{
		printf(xor ("\n[Zalupa] Unable to clean PCT: #4\n"));

		ExReleaseResourceLite(PiDDBLock);

		return false;
	}

	if (!RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pTargetDriverEntry))
	{
		printf(xor ("\n[Zalupa] Unable to clean PCT: Cat't remove from table.\n"));

		ExReleaseResourceLite(PiDDBLock);

		return false;
	}

	ULONG deleteCount = 0;
	VDM::ReadMemory((uintptr_t)PiDDBCacheTable + (offsetof(struct _RTL_AVL_TABLE, DeleteCount)), &deleteCount, sizeof(ULONG));
	
	if (deleteCount > 0) 
	{
		deleteCount--;
		VDM::WriteMemory((uintptr_t)PiDDBCacheTable + (offsetof(struct _RTL_AVL_TABLE, DeleteCount)), &deleteCount, sizeof(ULONG));
	}

	ExReleaseResourceLite(PiDDBLock);

	return true;
}

bool TraceCleaner::CleanMmUnloadedDrivers(HANDLE hDriver)
{
	ULONG querySize = 0;
	PVOID pInfo = nullptr;

	auto status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(64), pInfo, querySize, &querySize);

	while (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		VirtualFree(pInfo, 0, MEM_RELEASE);

		pInfo = VirtualAlloc(nullptr, querySize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(64), pInfo, querySize, &querySize);
	}

	if (!NT_SUCCESS(status) || pInfo == 0)
	{
		if (pInfo != 0)
			VirtualFree(pInfo, 0, MEM_RELEASE);

		return false;
	}

	uint64_t unloadedDriverEntry = 0;

	auto systemHandleInforamtion = static_cast<PSYSTEM_HANDLE_INFORMATION_EX>(pInfo);

	for (auto i = 0u; i < systemHandleInforamtion->HandleCount; ++i)
	{
		const SYSTEM_HANDLE systemHandle = systemHandleInforamtion->Handles[i];

		if (systemHandle.UniqueProcessId != reinterpret_cast<HANDLE>(static_cast<uint64_t>(GetCurrentProcessId())))
			continue;

		if (systemHandle.HandleValue == hDriver)
		{
			unloadedDriverEntry = reinterpret_cast<uint64_t>(systemHandle.Object);
			break;
		}
	}

	VirtualFree(pInfo, 0, MEM_RELEASE);

	if (!unloadedDriverEntry)
		return false;

	uint64_t deviceObject = 0;

	if (!VDM::ReadVirtualMemory(unloadedDriverEntry + 0x8, &deviceObject, sizeof(deviceObject)) || !deviceObject)
	{
		printf(xor ("\n[Zalupa] Unable to clean MUD: DeviceObject not found.\n"));

		return false;
	}

	uint64_t driverObject = 0;

	if (!VDM::ReadVirtualMemory(deviceObject + 0x8, &driverObject, sizeof(driverObject)) || !driverObject)
	{
		printf(xor ("\n[Zalupa] Unable to clean MUD: DriverObject not found.\n"));

		return false;
	}

	uint64_t driverSection = 0;

	if (!VDM::ReadVirtualMemory(driverObject + 0x28, &driverSection, sizeof(driverSection)) || !driverSection)
	{
		printf(xor ("\n[Zalupa] Unable to clean MUD: DriverSection not found.\n"));

		return false;
	}

	UNICODE_STRING driverBaseName = { 0 };

	if (!VDM::ReadVirtualMemory(driverSection + 0x58, &driverBaseName, sizeof(driverBaseName)) || driverBaseName.Length == 0)
	{
		printf(xor ("\n[Zalupa] Unable to clean MUD: Driver name not found.\n"));

		return false;
	}

	wchar_t* unloadedDriverName = new wchar_t[driverBaseName.Length];
	memset(unloadedDriverName, 0, driverBaseName.Length * sizeof(wchar_t));

	VDM::ReadVirtualMemory((uintptr_t)driverBaseName.Buffer, unloadedDriverName, driverBaseName.Length * sizeof(wchar_t));

	driverBaseName.Length = 0;

	if (!VDM::WriteVirtualMemory(driverSection + 0x58, &driverBaseName, sizeof(driverBaseName)))
	{
		printf(xor ("\n[Zalupa] Unable to clean MUD.\n"));

		return false;
	}

	delete[] unloadedDriverName;

	return true;
}

bool TraceCleaner::CleanKernelHashBucketList(std::string driverName)
{
	std::wstring driverNameW(driverName.begin(), driverName.end());
	driverNameW = L"\\" + driverNameW;

	auto ciBase = VDM::GetKernelModule(xor ("ci.dll"));

	auto PoolBigPageTablePtr = FindPatternInKernelSection(ciBase, xor ("PAGE"), xor ("\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00"), xor ("xxx????x?xxxxxxx"));

	if (!PoolBigPageTablePtr)
	{
		printf(xor ("\n[Zalupa] Unable to clean KHL: KHL not found.\n"));

		return false;
	}

	auto PoolBigPageTableSizePtr = (uintptr_t)FindPatternInKernel(PoolBigPageTablePtr - 50, 50, xor ("\x48\x8D\x0D"), xor ("xxx"));

	if (!PoolBigPageTableSizePtr)
	{
		printf(xor ("\n[Zalupa] Unable to clean KHL: HCL not found.\n"));

		return false;
	}

	const auto g_KernelHashBucketList = ResolveRelativeAddress((PVOID)PoolBigPageTablePtr, 3, 7);
	const auto g_HashCacheLock = ResolveRelativeAddress((PVOID)PoolBigPageTableSizePtr, 3, 7);

	if (!g_KernelHashBucketList || !g_HashCacheLock)
	{
		printf(xor ("\n[Zalupa] Unable to clean KHL: HCE not found.\n"));

		return false;
	}

	if (!ExAcquireResourceExclusiveLite(g_HashCacheLock, true))
	{
		printf(xor ("\n[Zalupa] Unable to clean KHL: Can't lock HCL.\n"));

		return false;
	}

	HASH_BUCKET_ENTRY* PrevHashEntry = (HASH_BUCKET_ENTRY*)g_KernelHashBucketList;
	HASH_BUCKET_ENTRY* HashEntry = 0;

	VDM::ReadVirtualMemory((uintptr_t)PrevHashEntry, &HashEntry, sizeof(HashEntry));

	if (!HashEntry)
	{
		printf(xor ("\n[Zalupa] Unable to clean KHL: KHL empty.\n"));

		ExReleaseResourceLite(g_HashCacheLock);

		return true;
	}

	while (HashEntry)
	{
		wchar_t* hashName = 0;
		USHORT hashNameLen = 0;

		VDM::ReadVirtualMemory((uintptr_t)HashEntry + offsetof(HASH_BUCKET_ENTRY, DriverName.Buffer), &hashName, sizeof(hashName));
		VDM::ReadVirtualMemory((uintptr_t)HashEntry + offsetof(HASH_BUCKET_ENTRY, DriverName.Length), &hashNameLen, sizeof(hashNameLen));

		wchar_t* driverHashName = new wchar_t[hashNameLen];
		memset(driverHashName, 0, hashNameLen * sizeof(wchar_t));

		VDM::ReadVirtualMemory((uintptr_t)hashName, driverHashName, hashNameLen * sizeof(wchar_t));

		if (std::wstring(driverHashName).find(driverNameW) != std::wstring::npos)
		{
			HASH_BUCKET_ENTRY* Next = 0;
			VDM::ReadVirtualMemory((uintptr_t)HashEntry, &Next, sizeof(Next));

			VDM::WriteVirtualMemory((uintptr_t)PrevHashEntry, &Next, sizeof(Next));

			VDM::ExFreePool((uintptr_t)HashEntry);

			ExReleaseResourceLite(g_HashCacheLock);

			delete[] driverHashName;

			return true;
		}

		PrevHashEntry = HashEntry;

		delete[] driverHashName;

		VDM::ReadVirtualMemory((uintptr_t)HashEntry, &HashEntry, sizeof(HashEntry));
	}

	ExReleaseResourceLite(g_HashCacheLock);

	return false;
}