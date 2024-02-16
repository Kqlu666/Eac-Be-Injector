#include "MemoryUtils.hpp"

MemoryUtils::MemoryUtils(OperationCallback operation, uint64_t pid)
{
	operationCallback = operation;
	processId = pid;
}

NTSTATUS MemoryUtils::ReadBuffer(uint64_t address, LPVOID lpBuffer, SIZE_T nSize)
{
	if (lpBuffer == 0)
		return STATUS_INVALID_PARAMETER;

	return Communication::CopyVirtualMemory(operationCallback, processId, address, GetCurrentProcessId(), uintptr_t(lpBuffer), nSize);
}

NTSTATUS MemoryUtils::WriteMemory(uint64_t address, uintptr_t dstAddress, SIZE_T nSize)
{
	if (dstAddress == 0)
		return STATUS_INVALID_PARAMETER;

	return Communication::CopyVirtualMemory(operationCallback, GetCurrentProcessId(), dstAddress, processId, address, nSize);
}

uint64_t MemoryUtils::GetModuleBase(wstring moduleName)
{
	return Communication::GetModuleBaseOperation(operationCallback, processId, moduleName);
}

uint64_t MemoryUtils::AllocateMemory(size_t size, uint32_t allocation_type, uint32_t protect)
{
	uint64_t address = 0;
	return Communication::AllocateVirtualMemory(operationCallback, processId, size, allocation_type, protect, address);
}

NTSTATUS MemoryUtils::ProtectMemory(uint64_t address, size_t size, uint32_t protect)
{
	return Communication::ProtectVirtualMemory(operationCallback, processId, size, protect, address);
}

NTSTATUS MemoryUtils::FreeMemory(uint64_t address)
{
	return Communication::FreeVirtualMemory(operationCallback, processId, address);
}

uint64_t MemoryUtils::AllocateStealthMemory(size_t size)
{
	uint64_t address = 0;
	return Communication::AllocateStealthMemory(operationCallback, processId, size, address);
}