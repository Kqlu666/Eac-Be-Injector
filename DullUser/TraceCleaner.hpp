#pragma once

#include "VDM.hpp"

class TraceCleaner
{
public:
	static bool ExAcquireResourceExclusiveLite(PVOID Resource, BOOLEAN Wait);
	static bool ExReleaseResourceLite(PVOID Resource);
	static BOOLEAN RtlDeleteElementGenericTableAvl(PVOID Table, PVOID Buffer);

	static uintptr_t FindPatternInKernel(uintptr_t moduleBase, uintptr_t moduleSize, LPCSTR pattern, LPCSTR mask);
	static uintptr_t FindExtendedPattern(uintptr_t moduleBase, char* sectionName, PULONG outSize);

	static uintptr_t FindPatternInKernelSection(uintptr_t modulePtr, char* sectionName, LPCSTR bMask, LPCSTR szMask);

	static PVOID ResolveRelativeAddress(PVOID Instruction, ULONG OffsetOffset, ULONG InstructionSize);

	static bool CleanPiDDBCacheTable();
	static bool CleanMmUnloadedDrivers(HANDLE hDriver);
	static bool CleanKernelHashBucketList(std::string driverName);
};