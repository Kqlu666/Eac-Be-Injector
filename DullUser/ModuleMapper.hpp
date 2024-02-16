#include "MemoryUtils.hpp"

class ModuleMapper
{
public:
	static MemoryUtils* memoryInstance;

	static PVOID LoadLocalImage(const char* imagePath);
	static BOOL LoadModule(PVOID LocalImage, bool Delay);
};