#pragma once

#include <Windows.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

#define PAGE_4KB 0x1000

#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL              ((NTSTATUS)0xC0000001L)

#define STATUS_ABANDONED                 ((NTSTATUS)0x00000080L)
#define STATUS_FAIL_CHECK                ((NTSTATUS)0xC0000229L)

#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)

#define STATUS_INVALID_IMAGE_HASH        ((NTSTATUS)0xC0000428L)
#define STATUS_IMAGE_ALREADY_LOADED      ((NTSTATUS)0xC000010EL)

typedef CCHAR KPROCESSOR_MODE;

typedef enum _MODE 
{
	KernelMode,
	UserMode,
	MaximumMode
} MODE;

typedef enum _MM_PAGE_PRIORITY 
{
	LowPagePriority,
	NormalPagePriority = 16,
	HighPagePriority = 32
} MM_PAGE_PRIORITY;

typedef enum _MEMORY_CACHING_TYPE_ORIG 
{
	MmFrameBufferCached = 2
} MEMORY_CACHING_TYPE_ORIG;

typedef enum _MEMORY_CACHING_TYPE 
{
	MmNonCached = FALSE,
	MmCached = TRUE,
	MmWriteCombined = MmFrameBufferCached,
	MmHardwareCoherentCached,
	MmNonCachedUnordered,
	MmUSWCCached,
	MmMaximumCacheType,
	MmNotMapped = -1
} MEMORY_CACHING_TYPE;

#pragma warning(push)
#pragma warning(disable: 4214)
#pragma pack(push,2)

typedef struct _FAR_JMP_16
{
	UCHAR  OpCode;
	USHORT Offset;
} FAR_JMP_16;

typedef struct _FAR_TARGET_32
{
	ULONG Offset;
	USHORT Selector;
} FAR_TARGET_32;

typedef struct _PSEUDO_DESCRIPTOR_32 {
	USHORT Limit;
	ULONG Base;
} PSEUDO_DESCRIPTOR_32;

#pragma pack(pop)
typedef union _KGDTENTRY64
{
	struct
	{
		USHORT  LimitLow;
		USHORT  BaseLow;
		union
		{
			struct
			{
				UCHAR   BaseMiddle;
				UCHAR   Flags1;
				UCHAR   Flags2;
				UCHAR   BaseHigh;
			} Bytes;

			struct
			{
				ULONG   BaseMiddle : 8;
				ULONG   Type : 5;
				ULONG   Dpl : 2;
				ULONG   Present : 1;
				ULONG   LimitHigh : 4;
				ULONG   System : 1;
				ULONG   LongMode : 1;
				ULONG   DefaultBig : 1;
				ULONG   Granularity : 1;
				ULONG   BaseHigh : 8;
			} Bits;
		};
		ULONG BaseUpper;
		ULONG MustBeZero;
	};
	ULONG64 Alignment;
} KGDTENTRY64, * PKGDTENTRY64;

typedef union _KIDTENTRY64
{
	struct
	{
		USHORT OffsetLow;
		USHORT Selector;
		USHORT IstIndex : 3;
		USHORT Reserved0 : 5;
		USHORT Type : 5;
		USHORT Dpl : 2;
		USHORT Present : 1;
		USHORT OffsetMiddle;
		ULONG OffsetHigh;
		ULONG Reserved1;
	};
	ULONG64 Alignment;
} KIDTENTRY64, * PKIDTENTRY64;

typedef union _KGDT_BASE
{
	struct
	{
		USHORT BaseLow;
		UCHAR BaseMiddle;
		UCHAR BaseHigh;
		ULONG BaseUpper;
	};
	ULONG64 Base;
} KGDT_BASE, * PKGDT_BASE;

typedef union _KGDT_LIMIT
{
	struct
	{
		USHORT LimitLow;
		USHORT LimitHigh : 4;
		USHORT MustBeZero : 12;
	};
	ULONG Limit;
} KGDT_LIMIT, * PKGDT_LIMIT;

#define PSB_GDT32_MAX       3

typedef struct _KDESCRIPTOR
{
	USHORT Pad[3];
	USHORT Limit;
	PVOID Base;
} KDESCRIPTOR, * PKDESCRIPTOR;

typedef struct _KDESCRIPTOR32
{
	USHORT Pad[3];
	USHORT Limit;
	ULONG Base;
} KDESCRIPTOR32, * PKDESCRIPTOR32;

typedef struct _KSPECIAL_REGISTERS
{
	ULONG64 Cr0;
	ULONG64 Cr2;
	ULONG64 Cr3;
	ULONG64 Cr4;
	ULONG64 KernelDr0;
	ULONG64 KernelDr1;
	ULONG64 KernelDr2;
	ULONG64 KernelDr3;
	ULONG64 KernelDr6;
	ULONG64 KernelDr7;
	KDESCRIPTOR Gdtr;
	KDESCRIPTOR Idtr;
	USHORT Tr;
	USHORT Ldtr;
	ULONG MxCsr;
	ULONG64 DebugControl;
	ULONG64 LastBranchToRip;
	ULONG64 LastBranchFromRip;
	ULONG64 LastExceptionToRip;
	ULONG64 LastExceptionFromRip;
	ULONG64 Cr8;
	ULONG64 MsrGsBase;
	ULONG64 MsrGsSwap;
	ULONG64 MsrStar;
	ULONG64 MsrLStar;
	ULONG64 MsrCStar;
	ULONG64 MsrSyscallMask;
} KSPECIAL_REGISTERS, * PKSPECIAL_REGISTERS;

typedef struct _KPROCESSOR_STATE
{
	KSPECIAL_REGISTERS SpecialRegisters;
	CONTEXT ContextFrame;
} KPROCESSOR_STATE, * PKPROCESSOR_STATE;

typedef struct _PROCESSOR_START_BLOCK* PPROCESSOR_START_BLOCK;
typedef struct _PROCESSOR_START_BLOCK
{
	FAR_JMP_16 Jmp;
	ULONG CompletionFlag;
	PSEUDO_DESCRIPTOR_32 Gdt32;
	PSEUDO_DESCRIPTOR_32 Idt32;
	KGDTENTRY64 Gdt[PSB_GDT32_MAX + 1];
	ULONG64 TiledCr3;
	FAR_TARGET_32 PmTarget;
	FAR_TARGET_32 LmIdentityTarget;
	PVOID LmTarget;
	PPROCESSOR_START_BLOCK SelfMap;
	ULONG64 MsrPat;
	ULONG64 MsrEFER;
	KPROCESSOR_STATE ProcessorState;
} PROCESSOR_START_BLOCK;
#pragma warning(pop)

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

namespace ntspace
{
	typedef struct _SYSTEM_HANDLE
	{
		PVOID Object;
		HANDLE UniqueProcessId;
		HANDLE HandleValue;
		ULONG GrantedAccess;
		USHORT CreatorBackTraceIndex;
		USHORT ObjectTypeIndex;
		ULONG HandleAttributes;
		ULONG Reserved;
	} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

	typedef struct _SYSTEM_HANDLE_INFORMATION_EX
	{
		ULONG_PTR HandleCount;
		ULONG_PTR Reserved;
		SYSTEM_HANDLE Handles[1];
	} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

	typedef enum class _POOL_TYPE
	{
		NonPagedPool,
		NonPagedPoolExecute,
		PagedPool,
		NonPagedPoolMustSucceed,
		DontUseThisType,
		NonPagedPoolCacheAligned,
		PagedPoolCacheAligned,
		NonPagedPoolCacheAlignedMustS,
		MaxPoolType,
		NonPagedPoolBase,
		NonPagedPoolBaseMustSucceed,
		NonPagedPoolBaseCacheAligned,
		NonPagedPoolBaseCacheAlignedMustS,
		NonPagedPoolSession,
		PagedPoolSession,
		NonPagedPoolMustSucceedSession,
		DontUseThisTypeSession,
		NonPagedPoolCacheAlignedSession,
		PagedPoolCacheAlignedSession,
		NonPagedPoolCacheAlignedMustSSession,
		NonPagedPoolNx,
		NonPagedPoolNxCacheAligned,
		NonPagedPoolSessionNx
	} POOL_TYPE;
}