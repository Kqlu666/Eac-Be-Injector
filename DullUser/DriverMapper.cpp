#include "DriverMapper.hpp"

#include "VDM_MAP.hpp"
#include "Vulnerable.hpp"

bool Mapper::MapDriver(std::vector<uint8_t> driverImage)
{
	if (VDM::IsLoaded())
	{
		printf(xor ("\n[Zalupa] Failed to load vdm. Driver already loaded.\n"));

		return false;
	}

	std::vector<uint8_t> vdm_image(sizeof(ene_sys));
	memcpy(vdm_image.data(), ene_sys, sizeof(ene_sys));

	auto loadInfo = VDM::Load(vdm_image);

	auto hDeviceHadle = loadInfo.first;
	auto driverName = loadInfo.second;

	if (hDeviceHadle == NULL || driverName.empty())
	{
		printf(xor ("\n[Zalupa] Failed to load vdm.\n"));

		return false;
	}

	if (!VDM::Init(hDeviceHadle))
	{
		printf(xor ("\n[Zalupa] Failed to init vdm.\n"));

		return false;
	}

	if (!VDM::InitPageTableBase())
	{
		printf(xor ("\n[Zalupa] Failed to init page tables.\n"));

		VDM::Unload(driverName);

		return false;
	}

	printf(xor ("[Zalupa] Cleaning...\n"));
	Sleep(1000);

	if (!TraceCleaner::CleanPiDDBCacheTable())
	{
		printf(xor ("\n[Zalupa] Failed: #1.\n"));

		VDM::Unload(driverName);

		return false;
	}

	if (!TraceCleaner::CleanKernelHashBucketList(driverName))
	{
		printf(xor ("\n[Zalupa] Failed: #2.\n"));

		VDM::Unload(driverName);

		return false;
	}

	if (!TraceCleaner::CleanMmUnloadedDrivers(hDeviceHadle))
	{
		printf(xor ("\n[Zalupa] Failed: #3.\n"));

		VDM::Unload(driverName);

		return false;
	}

	printf(xor ("[Zalupa] Mapping...\n"));
	Sleep(1000);

	if (!VDM_MAP::MapKernelModule(driverImage))
	{
		VDM::Unload(driverName);

		return false;
	}

	if (!VDM::Unload(driverName))
		return false;

	return true;
}