#include "Communication.hpp"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)

BYTE* GetUserProcAddress(HMODULE hModule, const char* szFunc)
{
	if (!hModule)
		return nullptr;

	BYTE* pBase = reinterpret_cast<BYTE*>(hModule);

	auto* pNT = reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pBase)->e_lfanew);
	auto* pExportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(pBase + pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	ULONG max = pExportDir->NumberOfNames;

	for (ULONG i = 0; i < max; ++i)
	{
		ULONG CurrNameRVA = reinterpret_cast<ULONG*>(pBase + pExportDir->AddressOfNames)[i];
		char* szName = reinterpret_cast<char*>(pBase + CurrNameRVA);

		if (strcmp(szName, szFunc) == 0)
		{
			USHORT Ordinal = reinterpret_cast<USHORT*>(pBase + pExportDir->AddressOfNameOrdinals)[i];
			ULONG RVA = reinterpret_cast<ULONG*>(pBase + pExportDir->AddressOfFunctions)[Ordinal];

			return pBase + RVA;
		}
	}

	return nullptr;
}

OperationCallback Communication::Init(string exportName)
{
	auto moduleName = xorstr("win32u.dll");

	auto hModule = LoadLibraryA(moduleName.crypt_get());

	moduleName.crypt();

	if (!hModule)
		return nullptr;

	OperationCallback callback = (OperationCallback)GetUserProcAddress(hModule, exportName.c_str());

	if (!callback)
		return nullptr;

	return callback;
}

bool Communication::IsConnected(OperationCallback operation)
{
	PACKET_BASE packet{};

	packet.op = TEST;
	packet.side = SIDE::SERVER;
	packet.magic = 0xFED0D3;

	constexpr ULONG firstCall = 1;

	auto veh = AddVectoredExceptionHandler(firstCall, [](PEXCEPTION_POINTERS exceptionHandler) -> LONG
		{
			auto context = exceptionHandler->ContextRecord;
	context->Rip += 8;

	return EXCEPTION_CONTINUE_EXECUTION;
		});

	if (!veh)
		return false;

	if (!operation(packet, 0, 0, 0xD0FAB0FA, 0, 0))
		return false;

	if (!RemoveVectoredExceptionHandler(veh))
		return false;

	return packet.client.test.valid;
}

NTSTATUS Communication::CopyVirtualMemory(OperationCallback operation, ULONGLONG srcPid, uintptr_t srcAddr, ULONGLONG targetPid, uintptr_t targetAddr, SIZE_T size)
{
	PACKET_BASE packet{};

	packet.op = COPY_VIRTUAL_MEMORY;
	packet.side = SIDE::SERVER;
	packet.magic = 0xFED0D3;

	auto& serverRequest = packet.server.copy_virtual_memory;

	serverRequest.sourcePid = srcPid;
	serverRequest.sourceAddress = srcAddr;

	serverRequest.targetPid = targetPid;
	serverRequest.targetAddress = targetAddr;

	serverRequest.size = size;

	constexpr ULONG firstCall = 1;

	auto veh = AddVectoredExceptionHandler(firstCall, [](PEXCEPTION_POINTERS exceptionHandler) -> LONG
		{
			auto context = exceptionHandler->ContextRecord;
	context->Rip += 8;

	return EXCEPTION_CONTINUE_EXECUTION;
		});

	if (!veh)
		return STATUS_UNSUCCESSFUL;

	if (!operation(packet, 0, 0, 0xD0FAB0FA, 0, 0))
		return STATUS_INVALID_HANDLE;

	if (!RemoveVectoredExceptionHandler(veh))
		return STATUS_UNSUCCESSFUL;

	auto clientRequest = packet.client.copy_virtual_memory;

	return NTSTATUS(clientRequest.size);
}

uint64_t Communication::GetModuleBaseOperation(OperationCallback operation, ULONGLONG processId, wstring moduleName)
{
	PACKET_BASE packet{};

	packet.op = GET_MODULE_BASE_SIZE;
	packet.side = SIDE::SERVER;
	packet.magic = 0xFED0D3;

	auto& serverRequest = packet.server;
	moduleName.copy(serverRequest.get_module.name, moduleName.length());

	serverRequest.get_module.pid = processId;

	constexpr ULONG firstCall = 1;

	auto veh = AddVectoredExceptionHandler(firstCall, [](PEXCEPTION_POINTERS exceptionHandler) -> LONG
		{
			auto context = exceptionHandler->ContextRecord;
	context->Rip += 8;

	return EXCEPTION_CONTINUE_EXECUTION;
		});

	if (!veh)
		return 0;

	if (!operation(packet, 0, 0, 0xD0FAB0FA, 0, 0))
		return -1;

	if (!RemoveVectoredExceptionHandler(veh))
		return 0;

	auto clientRequest = packet.client.get_module;

	return clientRequest.baseAddress;
}

uint64_t Communication::AllocateVirtualMemory(OperationCallback operation, ULONGLONG targetPid, size_t size, uint32_t allocationType, uint32_t protect, uintptr_t sourceAddress)
{
	PACKET_BASE packet{};

	packet.op = ALLOC_VIRTUAL_MEMORY;
	packet.side = SIDE::SERVER;
	packet.magic = 0xFED0D3;

	auto& serverRequest = packet.server.alloc_virtual_memory;

	serverRequest.targetPid = targetPid;
	serverRequest.sourceAddress = sourceAddress;

	serverRequest.allocationType = allocationType;
	serverRequest.protect = protect;

	serverRequest.size = size;
	serverRequest.code = STATUS_NO_MEMORY;

	constexpr ULONG firstCall = 1;

	auto veh = AddVectoredExceptionHandler(firstCall, [](PEXCEPTION_POINTERS exceptionHandler) -> LONG
		{
			auto context = exceptionHandler->ContextRecord;
	context->Rip += 8;

	return EXCEPTION_CONTINUE_EXECUTION;
		});

	if (!veh)
		return 0;

	if (!operation(packet, 0, 0, 0xD0FAB0FA, 0, 0))
		return -1;

	if (!RemoveVectoredExceptionHandler(veh))
		return 0;

	auto clientRequest = packet.client.alloc_virtual_memory;

	return clientRequest.targetAddress;
}

NTSTATUS Communication::ProtectVirtualMemory(OperationCallback operation, ULONGLONG targetPid, size_t size, uint32_t protect, uintptr_t sourceAddress)
{
	PACKET_BASE packet{};

	packet.op = PROTECT_VIRTUAL_MEMORY;
	packet.side = SIDE::SERVER;
	packet.magic = 0xFED0D3;

	auto& serverRequest = packet.server.protect_virtual_memory;

	serverRequest.targetPid = targetPid;
	serverRequest.sourceAddress = sourceAddress;

	serverRequest.protect = protect;

	serverRequest.size = size;
	serverRequest.code = STATUS_NO_MEMORY;

	constexpr ULONG firstCall = 1;

	auto veh = AddVectoredExceptionHandler(firstCall, [](PEXCEPTION_POINTERS exceptionHandler) -> LONG
		{
			auto context = exceptionHandler->ContextRecord;
	context->Rip += 8;

	return EXCEPTION_CONTINUE_EXECUTION;
		});

	if (!veh)
		return STATUS_UNSUCCESSFUL;

	if (!operation(packet, 0, 0, 0xD0FAB0FA, 0, 0))
		return STATUS_INVALID_HANDLE;

	if (!RemoveVectoredExceptionHandler(veh))
		return STATUS_UNSUCCESSFUL;

	auto clientRequest = packet.client.protect_virtual_memory;

	protect = clientRequest.protect;

	return NTSTATUS(clientRequest.code);
}

NTSTATUS Communication::FreeVirtualMemory(OperationCallback operation, ULONGLONG targetPid, uintptr_t address)
{
	PACKET_BASE packet{};

	packet.op = FREE_VIRTUAL_MEMORY;
	packet.side = SIDE::SERVER;
	packet.magic = 0xFED0D3;

	auto& serverRequest = packet.server.free_memory;

	serverRequest.targetPid = targetPid;
	serverRequest.address = address;

	serverRequest.code = STATUS_NO_MEMORY;

	constexpr ULONG firstCall = 1;

	auto veh = AddVectoredExceptionHandler(firstCall, [](PEXCEPTION_POINTERS exceptionHandler) -> LONG
		{
			auto context = exceptionHandler->ContextRecord;
	context->Rip += 8;

	return EXCEPTION_CONTINUE_EXECUTION;
		});

	if (!veh)
		return STATUS_UNSUCCESSFUL;

	if (!operation(packet, 0, 0, 0xD0FAB0FA, 0, 0))
		return STATUS_INVALID_HANDLE;

	if (!RemoveVectoredExceptionHandler(veh))
		return STATUS_UNSUCCESSFUL;

	auto clientRequest = packet.client.free_memory;

	return NTSTATUS(clientRequest.code);
}

uint64_t Communication::AllocateStealthMemory(OperationCallback operation, ULONGLONG targetPid, size_t size, uintptr_t sourceAddress)
{
	PACKET_BASE packet{};

	packet.op = ALLOC_STEALTH_MEMORY;
	packet.side = SIDE::SERVER;
	packet.magic = 0xFED0D3;

	auto& serverRequest = packet.server.alloc_stealth_memory;

	serverRequest.targetPid = targetPid;
	serverRequest.sourceAddress = sourceAddress;

	serverRequest.size = size;
	serverRequest.code = STATUS_NO_MEMORY;

	constexpr ULONG firstCall = 1;

	auto veh = AddVectoredExceptionHandler(firstCall, [](PEXCEPTION_POINTERS exceptionHandler) -> LONG
		{
			auto context = exceptionHandler->ContextRecord;
	context->Rip += 8;

	return EXCEPTION_CONTINUE_EXECUTION;
		});

	if (!veh)
		return false;

	if (!operation(packet, 0, 0, 0xD0FAB0FA, 0, 0))
		return -1;

	if (!RemoveVectoredExceptionHandler(veh))
		return false;

	auto clientRequest = packet.client.alloc_stealth_memory;

	return clientRequest.targetAddress;
}