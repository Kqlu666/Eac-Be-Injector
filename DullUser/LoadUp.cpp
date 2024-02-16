#include "LoadUp.hpp"

extern "C" NTSTATUS NtLoadDriver(PUNICODE_STRING);
extern "C" NTSTATUS NtUnloadDriver(PUNICODE_STRING);

__forceinline bool GrantPrivileges(std::wstring privilegeName)
{
	HANDLE hToken = NULL;
	
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return false;

	LUID luid{};

	if (!LookupPrivilegeValueW(nullptr, privilegeName.data(), &luid))
		return false;

	TOKEN_PRIVILEGES state{};

	state.PrivilegeCount = 1;

	state.Privileges[0].Luid = luid;
	state.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &state, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
		return false;

	CloseHandle(hToken);

	return true;
}

__forceinline bool RemoveServiceEntry(const std::string& serviceName)
{
	static const std::string registryKey = xor ("System\\CurrentControlSet\\Services\\");

	HKEY hKey = NULL;

	auto status = RegOpenKeyA(HKEY_LOCAL_MACHINE, registryKey.c_str(), &hKey);

	if (status != ERROR_SUCCESS)
		return false;

	status = RegDeleteKeyA(hKey, serviceName.data());

	if (status != ERROR_SUCCESS)
		return false;

	return RegCloseKey(hKey) == ERROR_SUCCESS;
}

__forceinline bool CreateServiceEntry(std::string driverPath, std::string serviceName)
{
	std::string registryKey = xor ("System\\CurrentControlSet\\Services\\") + serviceName;
	
	HKEY hKey = NULL;

	auto status = RegCreateKeyA(HKEY_LOCAL_MACHINE, registryKey.c_str(), &hKey);

	if (status != ERROR_SUCCESS)
		return false;

	status = RegSetValueExA(hKey, xor ("ImagePath"), NULL, REG_SZ, (std::uint8_t*)driverPath.c_str(), static_cast<DWORD>(driverPath.size()));

	if (status != ERROR_SUCCESS)
		return false;

	std::uint8_t typeValue = 1;

	status = RegSetValueExA(hKey, xor ("Type"), NULL, REG_DWORD, &typeValue, 4u);

	if (status != ERROR_SUCCESS)
		return false;

	return RegCloseKey(hKey) == ERROR_SUCCESS;
}

bool LoadUp::LoadVulnerable(std::string driverPath, std::string serviceName)
{
	if (!GrantPrivileges(xor (L"SeLoadDriverPrivilege")))
	{
		printf(xor ("\n[Zalupa] Failed to set privilege.\n"));
		return false;
	}

	if (!CreateServiceEntry("\\??\\" + std::filesystem::absolute(std::filesystem::path(driverPath)).string(), serviceName))
	{
		printf(xor ("\n[Zalupa] Failed to create service.\n"));
		return false;
	}

	std::string registryPath = xor ("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\") + serviceName;

	ANSI_STRING driverPathA;
	RtlInitAnsiString(&driverPathA, registryPath.c_str());

	UNICODE_STRING driverPathW;
	RtlAnsiStringToUnicodeString(&driverPathW, &driverPathA, true);

	NTSTATUS status = NtLoadDriver(&driverPathW);

	return NT_SUCCESS(status);
}

bool LoadUp::UnloadVulnerable(std::string serviceName)
{
	std::string registryPath = xor ("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\") + serviceName;

	ANSI_STRING driverPathA;
	RtlInitAnsiString(&driverPathA, registryPath.c_str());

	UNICODE_STRING driverPathW;
	RtlAnsiStringToUnicodeString(&driverPathW, &driverPathA, true);

	NTSTATUS status = NtUnloadDriver(&driverPathW);

	RemoveServiceEntry(serviceName);

	try
	{
		std::filesystem::remove(std::filesystem::temp_directory_path().string() + serviceName);
	}
	catch (std::exception&)
	{
		return false;
	}

	return NT_SUCCESS(status);
}