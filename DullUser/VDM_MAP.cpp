#include "VDM_MAP.hpp"
#include "PEHelper.hpp"

#define PAGE_SIZE 0x1000

struct KERNEL_DATA
{
	ULONG64 MdlData;

	uintptr_t ExAllocatePoolWithTag = 0;
	uintptr_t ExFreePoolWithTag = 0;

	uintptr_t PsLookupProcessByProcessId = 0;

	uintptr_t KeStackAttachProcess = 0;
	uintptr_t KeUnstackDetachProcess = 0;

	uintptr_t ObfDereferenceObject = 0;
	uintptr_t IoGetCurrentProcess = 0;

	uintptr_t PsGetProcessPeb = 0;

	uintptr_t RtlFindExportedRoutineByName = 0;

	uintptr_t MmGetSystemRoutineAddress = 0;
	uintptr_t MmGetVirtualForPhysical = 0;

	uintptr_t MmIsAddressValid = 0;
	uintptr_t MmCopyVirtualMemory = 0;

	uintptr_t ZwQuerySystemInformation = 0;
	uintptr_t ZwAllocateVirtualMemory = 0;
	uintptr_t ZwProtectVirtualMemory = 0;
	uintptr_t ZwQueryVirtualMemory = 0;
	uintptr_t ZwFreeVirtualMemory = 0;

	uintptr_t IoAllocateMdl = 0;
	uintptr_t IoFreeMdl = 0;

	uintptr_t MmMapLockedPagesSpecifyCache = 0;
	uintptr_t MmProtectMdlSystemAddress = 0;
	uintptr_t MmProbeAndLockPages = 0;
	uintptr_t MmUnmapLockedPages = 0;
	uintptr_t MmUnlockPages = 0;

	uintptr_t MmAllocateContiguousMemorySpecifyCache = 0;
	uintptr_t MmBuildMdlForNonPagedPool = 0;
};

VOID ResolveRelocs(PEHelper::pe_relocs relocs, const uint64_t delta)
{
	for (const auto& relocation : relocs)
	{
		for (auto idx = 0u; idx < relocation.count; idx++)
		{
			const uint16_t type = relocation.delta[idx] >> 12;
			const uint16_t offset = relocation.delta[idx] & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64)
				*reinterpret_cast<uint64_t*>(relocation.base + offset) += delta;
		}
	}
}

uint64_t AllocMdlMemory(uint64_t size, uint64_t* mdlPtr)
{
	LARGE_INTEGER LowAddress, HighAddress;
	LowAddress.QuadPart = 0;
	HighAddress.QuadPart = 0xffff'ffff'ffff'ffffULL;

	uint64_t pages = (size / PAGE_SIZE) + 1;

	auto mdl = VDM::MmAllocatePagesForMdl(LowAddress, HighAddress, LowAddress, pages * (uint64_t)PAGE_SIZE);
	
	if (!mdl) 
	{
		printf(xor ("[Zalupa] Failed to allocate pages.\n"));

		return 0;
	}

	uint32_t byteCount = 0;
	if (!VDM::ReadMemory(mdl + 0x028, &byteCount, sizeof(uint32_t))) 
	{
		printf(xor ("[Zalupa] Failed to read count.\n"));

		return 0;
	}

	if (byteCount < size) 
	{
		printf(xor ("[Zalupa] Failed to align memory.\n"));

		VDM::MmFreePagesFromMdl(mdl);
		VDM::ExFreePool(mdl);

		return 0;
	}

	auto mappingStartAddress = VDM::MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
	
	if (!mappingStartAddress) 
	{
		printf(xor ("[Zalupa] Failed to lock pages.\n"));
		
		VDM::MmFreePagesFromMdl(mdl);
		VDM::ExFreePool(mdl);
		
		return 0;
	}

	const auto result = VDM::MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
	
	if (!result) 
	{
		printf(xor ("[Zalupa] Failed to set page protection.\n"));
		
		VDM::MmUnmapLockedPages(mappingStartAddress, mdl);
		VDM::MmFreePagesFromMdl(mdl);
		VDM::ExFreePool(mdl);
		
		return 0;
	}

	if (mdlPtr)
		*mdlPtr = mdl;

	return mappingStartAddress;
}

bool VDM_MAP::MapKernelModule(std::vector<uint8_t> driverImage)
{
	const auto pImageNtHeader = PEHelper::GetImageNtHeader(driverImage.data());

	if (!pImageNtHeader)
	{
		printf(xor ("\n[Zalupa] Failed to map vdm: #1\n"));

		return false;
	}

	KERNEL_DATA KernelData{};

	KernelData.ExAllocatePoolWithTag = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("ExAllocatePoolWithTag"));
	KernelData.ExFreePoolWithTag = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("ExFreePoolWithTag"));

	KernelData.PsLookupProcessByProcessId = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("PsLookupProcessByProcessId"));

	KernelData.KeStackAttachProcess = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("KeStackAttachProcess"));
	KernelData.KeUnstackDetachProcess = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("KeUnstackDetachProcess"));

	KernelData.ObfDereferenceObject = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("ObfDereferenceObject"));
	KernelData.IoGetCurrentProcess = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("IoGetCurrentProcess"));

	KernelData.PsGetProcessPeb = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("PsGetProcessPeb"));
	KernelData.RtlFindExportedRoutineByName = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("RtlFindExportedRoutineByName"));

	KernelData.MmGetSystemRoutineAddress = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("MmGetSystemRoutineAddress"));
	KernelData.MmGetVirtualForPhysical = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("MmGetVirtualForPhysical"));
	
	KernelData.MmIsAddressValid = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("MmIsAddressValid"));
	KernelData.MmCopyVirtualMemory = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("MmCopyVirtualMemory"));

	KernelData.ZwQuerySystemInformation = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("ZwQuerySystemInformation"));
	KernelData.ZwAllocateVirtualMemory = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("ZwAllocateVirtualMemory"));
	KernelData.ZwProtectVirtualMemory = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("ZwProtectVirtualMemory"));
	KernelData.ZwQueryVirtualMemory = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("ZwQueryVirtualMemory"));
	KernelData.ZwFreeVirtualMemory = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("ZwFreeVirtualMemory"));

	KernelData.IoAllocateMdl = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("IoAllocateMdl"));
	KernelData.IoFreeMdl = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("IoFreeMdl"));

	KernelData.MmMapLockedPagesSpecifyCache = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("MmMapLockedPagesSpecifyCache"));
	KernelData.MmProtectMdlSystemAddress = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("MmProtectMdlSystemAddress"));
	KernelData.MmProbeAndLockPages = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("MmProbeAndLockPages"));
	KernelData.MmUnmapLockedPages = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("MmUnmapLockedPages"));
	KernelData.MmUnlockPages = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("MmUnlockPages"));

	KernelData.MmAllocateContiguousMemorySpecifyCache = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("MmAllocateContiguousMemorySpecifyCache"));
	KernelData.MmBuildMdlForNonPagedPool = VDM::GetKernelProcAddress(VDM::g_KernelBase, xor ("MmBuildMdlForNonPagedPool"));

	if (!KernelData.ExAllocatePoolWithTag
		|| !KernelData.ExFreePoolWithTag
		|| !KernelData.PsLookupProcessByProcessId
		|| !KernelData.KeStackAttachProcess
		|| !KernelData.KeUnstackDetachProcess
		|| !KernelData.ObfDereferenceObject
		|| !KernelData.IoGetCurrentProcess
		|| !KernelData.PsGetProcessPeb
		|| !KernelData.RtlFindExportedRoutineByName
		|| !KernelData.MmGetSystemRoutineAddress
		|| !KernelData.MmGetVirtualForPhysical
		|| !KernelData.MmIsAddressValid
		|| !KernelData.MmCopyVirtualMemory
		|| !KernelData.ZwQuerySystemInformation
		|| !KernelData.ZwAllocateVirtualMemory
		|| !KernelData.ZwProtectVirtualMemory
		|| !KernelData.ZwQueryVirtualMemory
		|| !KernelData.ZwFreeVirtualMemory
		|| !KernelData.IoAllocateMdl
		|| !KernelData.IoFreeMdl
		|| !KernelData.MmMapLockedPagesSpecifyCache
		|| !KernelData.MmProtectMdlSystemAddress
		|| !KernelData.MmProbeAndLockPages
		|| !KernelData.MmUnmapLockedPages
		|| !KernelData.MmUnlockPages
		|| !KernelData.MmAllocateContiguousMemorySpecifyCache
		|| !KernelData.MmBuildMdlForNonPagedPool)
	{
		printf(xor ("\n[Zalupa] Failed to map vdm: #2\n"));

		return false;
	}

	uint32_t driverSize = pImageNtHeader->OptionalHeader.SizeOfImage;
	uint32_t totalDriverSize = (IMAGE_FIRST_SECTION(pImageNtHeader))->VirtualAddress;

	PVOID localBase = VirtualAlloc(NULL, driverSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (!localBase)
	{
		printf(xor ("\n[Zalupa] Failed to map vdm: #3\n"));

		return false;
	}

	ULONG64 driverBase = AllocMdlMemory(driverSize, &KernelData.MdlData);

	if (!driverBase || !KernelData.MdlData)
	{
		printf(xor ("\n[Zalupa] Failed to map vdm: #4\n"));

		VirtualFree(localBase, 0, MEM_RELEASE);
		
		return false;
	}

	VDM::SetMemory(driverBase, 0, driverSize);

	uint64_t realBase = 0;

	do
	{
		if (!driverBase)
			break;

		memcpy(localBase, driverImage.data(), pImageNtHeader->OptionalHeader.SizeOfHeaders);

		const PIMAGE_SECTION_HEADER pFirstSection = IMAGE_FIRST_SECTION(pImageNtHeader);

		for (PIMAGE_SECTION_HEADER pSectionHeader = pFirstSection;
			pSectionHeader < pFirstSection + pImageNtHeader->FileHeader.NumberOfSections; pSectionHeader++)
		{
			if (/*!(pSectionHeader->Characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE))
				|| */pSectionHeader->SizeOfRawData == 0)
			{
				continue;
			}

			auto pImageSection = reinterpret_cast<PVOID>(reinterpret_cast<uint64_t>(localBase) + pSectionHeader->VirtualAddress);

			memcpy(pImageSection, reinterpret_cast<PVOID>(reinterpret_cast<uint64_t>(driverImage.data()) + pSectionHeader->PointerToRawData), pSectionHeader->SizeOfRawData);
		}

		realBase = driverBase;

		driverBase -= totalDriverSize;
		driverSize -= totalDriverSize;

		ResolveRelocs(PEHelper::ParseRelocs(localBase), driverBase - pImageNtHeader->OptionalHeader.ImageBase);

		ULONG64 driverBaseEx = realBase;
		ULONG64 localBaseEx = (ULONG64)localBase + totalDriverSize;

		for (ULONG i = 0; i < (driverSize / PAGE_SIZE); ++i)
		{
			if (!VDM::WriteVirtualMemory(driverBaseEx, (PVOID)((uintptr_t)localBaseEx), PAGE_SIZE))
			{
				printf(xor ("\n[Zalupa] Failed to map vdm: #5\n"));
				goto fail;
			}

			driverBaseEx += PAGE_SIZE;
			localBaseEx += PAGE_SIZE;
		}

		uint64_t driverEntry = driverBase + pImageNtHeader->OptionalHeader.AddressOfEntryPoint;

		NTSTATUS status = STATUS_UNSUCCESSFUL;

		if (!VDM::SystemCall(driverEntry, &status, KernelData))
		{
			printf(xor ("\n[Zalupa] Failed to map vdm: #6\n"));

			driverBase = realBase;
			break;
		}

		if (!NT_SUCCESS(status))
		{
			printf(xor ("\n[Zalupa] Failed to map vdm. Status: 0x%p\n"), status);

			driverBase = realBase;
			break;
		}

		VirtualFree(localBase, 0, MEM_RELEASE);

		VDM::ExFreePool(KernelData.MdlData);

		return true;
	} 
	while (false);

fail:
	VirtualFree(localBase, 0, MEM_RELEASE);

	VDM::MmUnmapLockedPages(realBase, KernelData.MdlData);
	VDM::MmFreePagesFromMdl(KernelData.MdlData);

	return false;
}