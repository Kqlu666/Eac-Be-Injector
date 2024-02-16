#pragma once

#include "TraceCleaner.hpp"

class VDM_MAP
{
public:
	static bool MapKernelModule(std::vector<uint8_t> driverImage);
};