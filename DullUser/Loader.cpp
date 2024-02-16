#include "Kernel.hpp"
#include "ModuleMapper.hpp"

MemoryUtils* memoryUtils = nullptr;

int main()
{
	setlocale(0, "");

	printf(xor ("[Zalupa] Initializing...\n"));

	auto functionName = xorstr("NtUserCreateDesktopEx");

	OperationCallback operation = Communication::Init(functionName.crypt_get());

	functionName.crypt();

	if (!operation)
	{
		printf(xor ("\n[Zalupa] Failed."));
		Exit;
	}

	bool status = Communication::IsConnected(operation);

	if (!status)
	{
		printf(xor ("\n[Zalupa] Loading vdm...\n"));

		Sleep(1500);

		std::vector<uint8_t> driverImage(sizeof(Kernel_sys));
		memcpy(driverImage.data(), Kernel_sys, sizeof(Kernel_sys));

		if (!Mapper::MapDriver(driverImage))
		{
			printf(xor ("\n\n[Zalupa] Loading failed."));
			Exit;
		}

		printf(xor ("\n[Zalupa] Success!\n\n"));
	}
	else
	{
		printf(xor ("[Zalupa] Success!\n\n"));
	}

	printf(xor ("[Zalupa] Finding game...\n"));

	DWORD processId = ProcessUtils::GetProcessID(xor ("notepad.exe"));

	if (!processId)
	{
		printf(xor ("\n[Zalupa] Game not found."));
		Exit;
	}

	memoryUtils = new MemoryUtils(operation, processId);
	ModuleMapper::memoryInstance = memoryUtils;

	string current_path = std::filesystem::current_path().string();
	string image_path = current_path + "\\Test.dll";

	PVOID LocalImage = ModuleMapper::LoadLocalImage(image_path.c_str());

	if (!LocalImage)
	{
		printf(xor ("\n[Zalupa] Failed to load local image"));
		Exit;
	}

	printf(xor ("[Zalupa] Injecting...\n"));
	Sleep(1000);

	bool delay_for_free = true;

	if (!ModuleMapper::LoadModule(LocalImage, delay_for_free))
	{
		printf("\n[Zalupa] Injection failed.");
		Exit;
	}

	printf("[Zalupa] Successfully injected!");

	cin.get();
	return EXIT_SUCCESS;
}