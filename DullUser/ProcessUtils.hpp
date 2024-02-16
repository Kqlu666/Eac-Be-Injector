#pragma once

#include "DriverMapper.hpp"

class ProcessUtils
{
public:
	static DWORD GetProcessID(std::string processName);
};