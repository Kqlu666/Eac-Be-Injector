#include "PEHelper.hpp"

PIMAGE_NT_HEADERS64 PEHelper::GetImageNtHeader(PVOID pImageBase)
{
	const auto pImageDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pImageBase);
	const auto pImageNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<uint64_t>(pImageBase) + pImageDosHeader->e_lfanew);

	return pImageNtHeader;
}

PEHelper::pe_relocs PEHelper::ParseRelocs(PVOID pImageBase)
{
	const PIMAGE_NT_HEADERS64 pImageNtHeader = GetImageNtHeader(pImageBase);

	if (!pImageNtHeader)
		return {};

	const auto pImageRelocDirectory = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(&pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

	if (!pImageRelocDirectory || !pImageRelocDirectory->VirtualAddress)
		return {};

	auto startBaseReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uint64_t>(pImageBase) + pImageRelocDirectory->VirtualAddress);
	const auto endBaseReloc = reinterpret_cast<uint64_t>(startBaseReloc) + pImageRelocDirectory->Size;

	pe_relocs relocs;

	while (startBaseReloc->VirtualAddress && startBaseReloc->VirtualAddress < endBaseReloc && startBaseReloc->SizeOfBlock)
	{
		const auto relocBase = reinterpret_cast<uint64_t>(pImageBase) + startBaseReloc->VirtualAddress;
		const auto relocCount = (startBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);

		auto relocDelta = reinterpret_cast<uint16_t*>(reinterpret_cast<uint64_t>(startBaseReloc) + sizeof(IMAGE_BASE_RELOCATION));

		RelocationInfo relocInfo;

		relocInfo.base = relocBase;
		relocInfo.delta = relocDelta;
		relocInfo.count = static_cast<uint32_t>(relocCount);

		relocs.push_back(relocInfo);

		startBaseReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uint64_t>(startBaseReloc) + startBaseReloc->SizeOfBlock);
	}

	return relocs;
}

PEHelper::pe_imports PEHelper::ParseImports(PVOID pImageBase)
{
	const PIMAGE_NT_HEADERS64 pImageNtHeader = GetImageNtHeader(pImageBase);

	if (!pImageNtHeader)
		return {};

	const auto dwImportVA = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	if (!dwImportVA)
		return {};

	pe_imports imports;

	auto pCurrentImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<uint64_t>(pImageBase) + dwImportVA);

	while (pCurrentImportDescriptor->FirstThunk)
	{
		ImportInfo importInfo;

		importInfo.moduleName = std::string(reinterpret_cast<char*>(reinterpret_cast<uint64_t>(pImageBase) + pCurrentImportDescriptor->Name));

		auto imageFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(reinterpret_cast<uint64_t>(pImageBase) + pCurrentImportDescriptor->FirstThunk);
		auto originalFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(reinterpret_cast<uint64_t>(pImageBase) + pCurrentImportDescriptor->OriginalFirstThunk);

		while (originalFirstThunk->u1.Function)
		{
			ImportFunctionInfo functionInfo;

			auto thunk_data = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<uint64_t>(pImageBase) + originalFirstThunk->u1.AddressOfData);

			functionInfo.name = thunk_data->Name;
			functionInfo.address = &imageFirstThunk->u1.Function;

			importInfo.functionInfos.push_back(functionInfo);

			++originalFirstThunk;
			++imageFirstThunk;
		}

		imports.push_back(importInfo);

		++pCurrentImportDescriptor;
	}

	return imports;
}