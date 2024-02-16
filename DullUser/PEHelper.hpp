#include <Windows.h>
#include <cstdint>

#include <string>
#include <vector>

namespace PEHelper
{
	struct RelocationInfo
	{
		uint64_t base;
		uint16_t* delta;
		uint32_t count;
	};

	struct ImportFunctionInfo
	{
		std::string name;
		uint64_t* address;
	};

	struct ImportInfo
	{
		std::string moduleName;
		std::vector<ImportFunctionInfo> functionInfos;
	};

	using pe_relocs = std::vector<RelocationInfo>;
	using pe_imports = std::vector<ImportInfo>;

	PIMAGE_NT_HEADERS64 GetImageNtHeader(PVOID pImageBase);

	pe_relocs ParseRelocs(PVOID pImageBase);
	pe_imports ParseImports(PVOID pImageBase);
}