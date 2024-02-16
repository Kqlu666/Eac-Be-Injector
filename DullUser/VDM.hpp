#pragma once

#include "LoadUp.hpp"

#include <atlstr.h>
#include <assert.h>

#include <utility>
#include <random>

#define VDM_POOL_TAG 'RSPL'

class VDM
{
private:
	static HANDLE hDriver;
	static DWORD_PTR m_pPML4Base;

	static ULONG64 TranslateLinearAddress(ULONG64 VirtualAddress);

	static NTSTATUS MapPhysicalMemory(uint64_t address, uint64_t size, HANDLE* phSection, PVOID* pSectionAddr, PVOID* pObjectAddr);
	static NTSTATUS UnMapPhysicalMemory(HANDLE hSection, void* sectionAddress, void* objectAddress);

public:
	static uint64_t g_KernelBase;

	static bool Init(HANDLE hDevice);
	static bool IsLoaded();

	static std::pair<HANDLE, std::string> Load(std::vector<std::uint8_t>& driverBuffer);
	static bool Unload(std::string driverName);

	static bool InitPageTableBase();
	
	static bool ReadPhysicalMemory(uint64_t address, uint64_t size, void* Data);
	static bool WritePhysicalMemory(uint64_t address, uint64_t size, void* Data);

	static bool ReadVirtualMemory(uint64_t address, void* buffer, uint64_t size);
	static bool WriteVirtualMemory(uint64_t address, void* buffer, uint64_t size);

	static bool MemCopy(void* address, const void* buffer, size_t size);
	static bool SetMemory(uint64_t address, uint32_t value, uint64_t size);

	static bool ReadMemory(uint64_t address, void* buffer, uint64_t size);
	static bool WriteMemory(uint64_t address, void* buffer, uint64_t size);

	static uint64_t ExAllocatePool(ntspace::POOL_TYPE pool_type, uint64_t size);
	static bool ExFreePool(uint64_t address);

	static uint64_t MmAllocatePagesForMdl(LARGE_INTEGER LowAddress, LARGE_INTEGER HighAddress, LARGE_INTEGER SkipBytes, SIZE_T TotalBytes);
	static uint64_t MmMapLockedPagesSpecifyCache(uint64_t pmdl, KPROCESSOR_MODE AccessMode, MEMORY_CACHING_TYPE CacheType, uint64_t RequestedAddress, ULONG BugCheckOnFailure, ULONG Priority);

	static bool MmProtectMdlSystemAddress(uint64_t MemoryDescriptorList, ULONG NewProtect);
	static bool MmUnmapLockedPages(uint64_t BaseAddress, uint64_t pmdl);
	static bool MmFreePagesFromMdl(uint64_t MemoryDescriptorList);

	static uint64_t GetKernelProcAddress(uint64_t moduleBase, std::string funcName);

	static uint64_t GetKernelModule(const char* moduleName)
	{
		DWORD querySize = 0;
		PVOID pInfo = nullptr;

		auto status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(11), pInfo, querySize, &querySize);

		while (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			VirtualFree(pInfo, NULL, MEM_RELEASE);

			pInfo = VirtualAlloc(nullptr, querySize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(11), pInfo, querySize, &querySize);
		}

		if (!NT_SUCCESS(status))
		{
			VirtualFree(pInfo, NULL, MEM_RELEASE);
			return NULL;
		}

		const auto kernelModules = static_cast<PRTL_PROCESS_MODULES>(pInfo);

		for (auto i = 0u; i < kernelModules->NumberOfModules; i++)
		{
			const auto kernelModuleName = std::string(reinterpret_cast<char*>(kernelModules->Modules[i].FullPathName) + kernelModules->Modules[i].OffsetToFileName);

			if (!_stricmp(kernelModuleName.c_str(), moduleName))
			{
				const auto kernelBase = reinterpret_cast<std::uint64_t>(kernelModules->Modules[i].ImageBase);

				VirtualFree(pInfo, NULL, MEM_RELEASE);
				return kernelBase;
			}
		}

		VirtualFree(pInfo, NULL, MEM_RELEASE);

		return NULL;
	}

	template<typename ReturnType, typename ...ArgPack>
	static bool SystemCall(uint64_t address, ReturnType* result, const ArgPack ...args)
	{
		if (!address)
			return false;

		constexpr auto IsVoidType = std::is_same_v<ReturnType, void>;

		if constexpr (!IsVoidType)
		{
			if (!result)
				return false;
		}
		else
		{
			UNREFERENCED_PARAMETER(result);
		}

		const auto UserSyscall = reinterpret_cast<void*>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationAtom"));

		if (!UserSyscall)
		{
			printf("\n[Zalupa] Error: User syscall not found.\n");
			return false;
		}

		const auto KernelSyscall = GetKernelProcAddress(g_KernelBase, "NtQueryInformationAtom");

		if (!KernelSyscall)
		{
			printf("\n[Zalupa] Error: Kernel syscall not found.\n");
			return false;
		}

		uint8_t KernelWorkerCode[] =
		{
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0
		};

		uint8_t OriginalSystemFunction[sizeof(KernelWorkerCode)];

		*reinterpret_cast<uint64_t*>(&KernelWorkerCode[2]) = address;

		if (!ReadVirtualMemory(KernelSyscall, &OriginalSystemFunction, sizeof(KernelWorkerCode)))
			return false;

		if (!WriteVirtualMemory(KernelSyscall, &KernelWorkerCode, sizeof(KernelWorkerCode)))
			return false;

		if constexpr (!IsVoidType)
		{
			using ArgData = ReturnType(__stdcall*)(ArgPack...);
			const auto Data = reinterpret_cast<ArgData>(UserSyscall);

			*result = Data(args...);
		}
		else
		{
			using ArgData = void(__stdcall*)(ArgPack...);
			const auto Data = reinterpret_cast<ArgData>(UserSyscall);

			Data(args...);
		}

		WriteVirtualMemory(KernelSyscall, OriginalSystemFunction, sizeof(KernelWorkerCode));

		return true;
	}
};