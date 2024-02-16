#include "ModuleMapper.hpp"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

MemoryUtils* ModuleMapper::memoryInstance = nullptr;

std::map<string, uint64_t> imports;

BOOL ParseImports(uint64_t moduleBase)
{
	auto dos_header{ memoryUtils->Read< IMAGE_DOS_HEADER >(moduleBase) };
	auto nt_headers{ memoryUtils->Read< IMAGE_NT_HEADERS >(moduleBase + dos_header.e_lfanew) };
	auto descriptor{ memoryUtils->Read< IMAGE_IMPORT_DESCRIPTOR >(moduleBase + nt_headers.OptionalHeader.DataDirectory[1].VirtualAddress) };

	int descriptor_count{ 0 };
	int thunk_count{ 0 };

	while (descriptor.Name)
	{
		auto first_thunk{ memoryUtils->Read< IMAGE_THUNK_DATA >(moduleBase + descriptor.FirstThunk) };
		auto original_first_thunk{ memoryUtils->Read< IMAGE_THUNK_DATA >(moduleBase + descriptor.OriginalFirstThunk) };
		thunk_count = 0;

		while (original_first_thunk.u1.AddressOfData)
		{
			char name[256];
			memoryUtils->ReadBuffer(moduleBase + original_first_thunk.u1.AddressOfData + 0x2, (LPVOID)name, 256);

			std::string str_name(name);
			auto thunk_offset{ thunk_count * sizeof(uintptr_t) };

			if (str_name.length() > 0)
				imports[str_name] = moduleBase + descriptor.FirstThunk + thunk_offset;

			++thunk_count;
			first_thunk = memoryUtils->Read< IMAGE_THUNK_DATA >(moduleBase + descriptor.FirstThunk + sizeof(IMAGE_THUNK_DATA) * thunk_count);
			original_first_thunk = memoryUtils->Read< IMAGE_THUNK_DATA >(moduleBase + descriptor.OriginalFirstThunk + sizeof(IMAGE_THUNK_DATA) * thunk_count);
		}

		++descriptor_count;
		descriptor = memoryUtils->Read< IMAGE_IMPORT_DESCRIPTOR >(moduleBase + nt_headers.OptionalHeader.DataDirectory[1].VirtualAddress + sizeof(IMAGE_IMPORT_DESCRIPTOR) * descriptor_count);
	}

	return (imports.size() > 0);
}

PIMAGE_NT_HEADERS64 GetImageNtHeaders(PVOID pImageBase)
{
	const auto pImageDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pImageBase);
	const auto pImageNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<uint64_t>(pImageBase) + pImageDosHeader->e_lfanew);

	return pImageNtHeader;
}

wstring ToUnicode(const string& input, DWORD locale = CP_UTF8)
{
	wchar_t buffer[1024] = { 0 };
	MultiByteToWideChar(locale, 0, input.c_str(), (int)input.length(), buffer, ARRAYSIZE(buffer));

	return buffer;
}

PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(PIMAGE_NT_HEADERS pNtHeader, uint64_t rva)
{
	auto pFirstSection = IMAGE_FIRST_SECTION(pNtHeader);

	for (PIMAGE_SECTION_HEADER pSectionHeader = pFirstSection;
		pSectionHeader < pFirstSection + pNtHeader->FileHeader.NumberOfSections; pSectionHeader++)
	{
		uint64_t size = pSectionHeader->Misc.VirtualSize;

		if (!size)
			size = pSectionHeader->SizeOfRawData;

		if ((rva >= pSectionHeader->VirtualAddress) && (rva < (pSectionHeader->VirtualAddress + size)))
			return pSectionHeader;
	}

	return 0;
}

uint64_t* RvaToVa(PIMAGE_NT_HEADERS pNtHeader, uint8_t* imageBase, uint64_t rva)
{
	auto pEnclosingSection = GetEnclosingSectionHeader(pNtHeader, rva);

	if (!pEnclosingSection)
		return 0;

	auto delta = (int64_t)(pEnclosingSection->VirtualAddress - pEnclosingSection->PointerToRawData);

	return (uint64_t*)(imageBase + rva - delta);
}

uint64_t GetFuncAddress(const char* moduleName, const char* funcName)
{
	auto moduleNameUTF = ToUnicode(string(moduleName));

	auto remoteBase = ModuleMapper::memoryInstance->GetModuleBase(moduleNameUTF);

	if (!remoteBase)
	{
		printf(xor ("\n[Zalupa] Module base for %s not found.%ws\n"), moduleNameUTF.c_str());
		Exit;
	}

	auto localModule = GetModuleHandleA(moduleName);

	if (localModule)
	{
		uint64_t delta = remoteBase - reinterpret_cast<uint64_t>(localModule);

		return ((uint64_t)GetProcAddress(localModule, funcName) + delta);
	}

	printf(xor ("\n[Zalupa] Module %s not found.\n"), moduleName);

	return 0;
}

BOOL SolveRelocations(PVOID moduleBase, PVOID localBase, PIMAGE_NT_HEADERS pNtHeader)
{
	struct RelocationEntry
	{
		ULONG ToRVA;
		ULONG Size;

		struct
		{
			WORD Delta : 12;
			WORD Type : 4;
		} item[1];
	};

	auto delta = (uintptr_t)moduleBase - pNtHeader->OptionalHeader.ImageBase;

	if (!delta)
		return TRUE;

	auto relocationEntry = (RelocationEntry*)RvaToVa(pNtHeader, (PBYTE)localBase, pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	auto relocationEnd = (uintptr_t)relocationEntry + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	if (relocationEntry == nullptr)
		return TRUE;

	while ((uintptr_t)relocationEntry < relocationEnd && relocationEntry->Size)
	{
		DWORD relocationCount = (relocationEntry->Size - 8) >> 1;

		for (DWORD i = 0; i < relocationCount; i++)
		{
			WORD relocationType = (relocationEntry->item[i].Type);
			WORD shiftDelta = (relocationEntry->item[i].Delta) % 4096;

			if (relocationType == IMAGE_REL_BASED_ABSOLUTE)
				continue;

			if (relocationType == IMAGE_REL_BASED_HIGHLOW || relocationType == IMAGE_REL_BASED_DIR64)
			{
				auto fixedVA = (uintptr_t)RvaToVa(pNtHeader, (PBYTE)localBase, relocationEntry->ToRVA);

				if (!fixedVA)
					fixedVA = (uintptr_t)localBase;

				*(uintptr_t*)(fixedVA + shiftDelta) += delta;
			}
		}

		relocationEntry = (RelocationEntry*)((LPBYTE)relocationEntry + relocationEntry->Size);
	}

	return TRUE;
}

BOOL SolveImports(PIMAGE_NT_HEADERS pNtHeader, uint8_t* moduleBase)
{
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)RvaToVa(pNtHeader, moduleBase,
		(uint64_t)(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));

	char* moduleName;
	while ((moduleName = (char*)RvaToVa(pNtHeader, (PBYTE)moduleBase, (DWORD64)(pImportTable->Name))))
	{
		auto hModule = LoadLibraryA(moduleName);

		if (!hModule)
			return FALSE;

		auto importFirstThunk = (IMAGE_THUNK_DATA*)RvaToVa(pNtHeader, (PBYTE)moduleBase, (DWORD64)(pImportTable->FirstThunk));

		while (importFirstThunk->u1.AddressOfData)
		{
			auto imageImport = (IMAGE_IMPORT_BY_NAME*)RvaToVa(pNtHeader, (PBYTE)moduleBase, (DWORD64)(importFirstThunk->u1.AddressOfData));
			
			auto importFunctionEx = (uint64_t)(GetFuncAddress(moduleName, (char*)imageImport->Name));

			if (!importFunctionEx)
				return FALSE;

			importFirstThunk->u1.Function = importFunctionEx;
			importFirstThunk++;
		}

		pImportTable++;
	}

	return TRUE;
}

VOID MapSections(PIMAGE_NT_HEADERS pNtHeader, PVOID moduleBase, PVOID localBase)
{
	auto pFirstSection = IMAGE_FIRST_SECTION(pNtHeader);

	for (PIMAGE_SECTION_HEADER pSectionHeader = pFirstSection;
		pSectionHeader < pFirstSection + pNtHeader->FileHeader.NumberOfSections; pSectionHeader++)
	{
		if (!(pSectionHeader->Characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE))
			|| pSectionHeader->SizeOfRawData == 0 || !strcmp((const char*)pSectionHeader->Name, ".rsrc"))
		{
			continue;
		}

		ModuleMapper::memoryInstance->WriteMemory((uint64_t)((uintptr_t)moduleBase + pSectionHeader->VirtualAddress), (uintptr_t)((uintptr_t)localBase + pSectionHeader->PointerToRawData), pSectionHeader->SizeOfRawData);
	}
}

VOID EraseDiscardableSection(PIMAGE_NT_HEADERS pNtHeader, PVOID moduleBase)
{
	auto pFirstSection = IMAGE_FIRST_SECTION(pNtHeader);

	for (PIMAGE_SECTION_HEADER pSectionHeader = pFirstSection;
		pSectionHeader < pFirstSection + pNtHeader->FileHeader.NumberOfSections; pSectionHeader++)
	{
		if (pSectionHeader->SizeOfRawData == 0)
			continue;

		if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_DISCARDABLE || !strcmp((const char*)pSectionHeader->Name, ".rsrc"))
		{
			PVOID filledData = VirtualAlloc(NULL, pSectionHeader->SizeOfRawData, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

			ModuleMapper::memoryInstance->WriteMemory((uint64_t)((uintptr_t)moduleBase + pSectionHeader->VirtualAddress), (uintptr_t)filledData, pSectionHeader->SizeOfRawData);

			if (filledData)
				VirtualFree(filledData, 0, MEM_RELEASE);
		}
	}
}

VOID ErasePE(PIMAGE_NT_HEADERS pNtHeader, PVOID moduleBase)
{
	PVOID filledData = VirtualAlloc(NULL, pNtHeader->OptionalHeader.SizeOfHeaders, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	memoryUtils->WriteMemory((uint64_t)((uintptr_t)moduleBase), (uintptr_t)filledData, pNtHeader->OptionalHeader.SizeOfHeaders);

	if (filledData)
		VirtualFree(filledData, 0, MEM_RELEASE);
}

BYTE ImportTableWorkerCode[] =
{
	0x00, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x48, 0xBA, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x10,
	0x48, 0x83, 0xEC, 0x28, 0x48, 0xBA, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x15,
	0x02, 0x00, 0x00, 0x00, 0xEB, 0x08, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83,
	0xC4, 0x28, 0x48, 0x31, 0xC0, 0x80, 0x05, 0xBC,
	0xFF, 0xFF, 0xFF, 0x01, 0xC3
};

VOID HijackViaImportTable(PVOID imageBase, PIMAGE_NT_HEADERS ntHeader, bool Delay)
{
	uint64_t User32Base = memoryUtils->GetModuleBase(xor (L"user32.dll"));

	if (!User32Base)
	{
		printf(xor ("\n[Zalupa] Failed to get base."));
		Exit;
	}

	if (!ParseImports(User32Base))
	{
		printf(xor ("\n[Zalupa] Failed to parse imports."));
		Exit;
	}

	uint64_t TargetImportFunction = imports[xor ("NtUserGetForegroundWindow")];

	if (!TargetImportFunction)
	{
		printf(xor ("\n[Zalupa] Target import not found."));
		Exit;
	}

	uint64_t OriginalImportFunction = memoryUtils->Read<uint64_t>(TargetImportFunction);

	*reinterpret_cast<uint64_t*>(&ImportTableWorkerCode[3]) = TargetImportFunction;
	*reinterpret_cast<uint64_t*>(&ImportTableWorkerCode[13]) = OriginalImportFunction;

	uint64_t DllMainFunc = ((uintptr_t)imageBase + ntHeader->OptionalHeader.AddressOfEntryPoint);

	*reinterpret_cast<uint64_t*>(&ImportTableWorkerCode[46]) = DllMainFunc;

	uint64_t ImportWorkerCode = memoryUtils->AllocateMemory(sizeof(ImportTableWorkerCode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!ImportWorkerCode)
	{
		printf(xor ("\n[Zalupa] Failed to allocate pe worker."));
		Exit;
	}

	printf(xor ("\n[Zalupa] Calling...\n\n"));

	memoryUtils->WriteMemory(ImportWorkerCode, (uintptr_t)ImportTableWorkerCode, sizeof(ImportTableWorkerCode));

	memoryUtils->ProtectMemory(TargetImportFunction, sizeof(uint64_t), PAGE_EXECUTE_READWRITE);

	auto InjectedStatus = ImportWorkerCode + 1;

	memoryUtils->WriteMemory(TargetImportFunction, (uintptr_t)&InjectedStatus, sizeof(InjectedStatus));

	for (uint64_t ImportStatus = 0;; Sleep(1))
	{
		auto Status = memoryUtils->ReadBuffer(TargetImportFunction, &ImportStatus, sizeof(uint64_t));

		if (!NT_SUCCESS(Status))
		{
			printf(xor ("\n[Zalupa] Failed to read status."));
			Exit;
		}

		if (ImportStatus != InjectedStatus)
			break;
	}

	memoryUtils->ProtectMemory(TargetImportFunction, sizeof(uint64_t), PAGE_READONLY);

	for (BYTE EntryStatus = 0;; Sleep(10))
	{
		auto Status = memoryUtils->ReadBuffer(ImportWorkerCode, &EntryStatus, sizeof(BYTE));

		if (!NT_SUCCESS(Status))
		{
			printf(xor ("\n[Zalupa] Failed to read entry status."));
			Exit;
		}

		if (EntryStatus)
			break;
	}

	if (Delay)
		Sleep(1500);

	auto Status = memoryUtils->FreeMemory(ImportWorkerCode);

	if (!NT_SUCCESS(Status))
	{
		printf(xor ("\n[Zalupa] Failed to free memory. Error: %p\n"), Status);
		Exit;
	}
}

PVOID ModuleMapper::LoadLocalImage(const char* imagePath)
{
	HANDLE hFile = CreateFileA(imagePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return NULL;

	DWORD fileSize = GetFileSize(hFile, NULL);
	PVOID fileBuffer = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	ReadFile(hFile, fileBuffer, fileSize, NULL, FALSE);

	CloseHandle(hFile);

	return fileBuffer;
}

BOOL ModuleMapper::LoadModule(PVOID LocalImage, bool Delay)
{
	if (!LocalImage)
	{
		printf(xor ("\n[Zalupa] Image not found.\n"));
		return FALSE;
	}

	auto pImageNtHeader = GetImageNtHeaders(LocalImage);

	if (!pImageNtHeader)
	{
		printf(xor ("\n[Zalupa] Invali PE.\n"));
		return FALSE;
	}

	size_t moduleSize = pImageNtHeader->OptionalHeader.SizeOfImage;

	uint64_t moduleBase = memoryInstance->AllocateStealthMemory(moduleSize);

	if (!moduleBase)
	{
		printf(xor ("\n[Zalupa] Failed to allocate image.\n"));
		return FALSE;
	}

	printf(xor ("\n[Zalupa] Image base: 0x%p\n"), moduleBase);

	//cin.get();

	if (pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
	{
		if (!SolveRelocations((PVOID)moduleBase, LocalImage, pImageNtHeader))
		{
			printf(xor ("\n[Zalupa] Failed to solve relocs.\n"));

			memoryInstance->FreeMemory(moduleBase);
			return FALSE;
		}
	}

	if (pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		if (!SolveImports(pImageNtHeader, (uint8_t*)LocalImage))
		{
			printf(xor ("\n[Zalupa] Failed to solve imports.\n"));

			memoryInstance->FreeMemory(moduleBase);
			return FALSE;
		}
	}

	MapSections(pImageNtHeader, (PVOID)moduleBase, LocalImage);
	memoryUtils->WriteMemory(moduleBase, (uintptr_t)LocalImage, pImageNtHeader->OptionalHeader.SizeOfHeaders);

	HijackViaImportTable((PVOID)moduleBase, pImageNtHeader, Delay);

	EraseDiscardableSection(pImageNtHeader, (PVOID)moduleBase);
	ErasePE(pImageNtHeader, (PVOID)moduleBase);

	VirtualFree(LocalImage, 0, MEM_RELEASE);

	return TRUE;
}