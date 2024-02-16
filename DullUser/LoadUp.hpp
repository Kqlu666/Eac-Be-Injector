#pragma once

#include "NtStruct.hpp"
#include "xor.hpp"

#include <cstdint>

#include <iostream>

#include <string>
#include <vector>

#include <fstream>
#include <filesystem>

class LoadUp
{
public:
	static bool LoadVulnerable(std::string driverPath, std::string serviceName);
	static  bool UnloadVulnerable(std::string serviceName);
};