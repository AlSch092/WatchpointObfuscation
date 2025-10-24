// AntiWatchpoint.cpp : This file contains the 'main' function. https://github.com/AlSch092/WatchpointObfuscation/
// This code is meant to provoke thought, rather than being a solution to any specific problem

#include <Windows.h>
#include <new>
#include <iostream>
#include <stdint.h>
#include <time.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(linker, "/ALIGN:0x10000") //for SEC_NO_CHANGE

#define SEC_NO_CHANGE 0x00400000

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

EXTERN_C NTSTATUS NTAPI NtCreateSection(
	_Out_    PHANDLE            SectionHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PLARGE_INTEGER     MaximumSize,
	_In_     ULONG              SectionPageProtection,
	_In_     ULONG              AllocationAttributes,
	_In_opt_ HANDLE             FileHandle
);

EXTERN_C NTSTATUS NTAPI NtMapViewOfSection(
	_In_        HANDLE          SectionHandle,
	_In_        HANDLE          ProcessHandle,
	_Inout_     PVOID* BaseAddress,
	_In_        ULONG_PTR       ZeroBits,
	_In_        SIZE_T          CommitSize,
	_Inout_opt_ PLARGE_INTEGER  SectionOffset,
	_Inout_     PSIZE_T         ViewSize,
	_In_        SECTION_INHERIT InheritDisposition,
	_In_        ULONG           AllocationType,
	_In_        ULONG           Win32Protect
);

EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(_In_ HANDLE  ProcessHandle, _In_opt_    PVOID   BaseAddress);

struct ValuableStruct
{
	uint32_t x = 0, y = 0, z = 0;
	char testStr[24]{ 0 };
};

unsigned int rand_lim(unsigned int limit)
{
	srand(time(0));
	unsigned int  divisor = RAND_MAX / (limit + 1);
	unsigned int  retval = 0;

	do
	{
		retval = rand() / divisor;
	} while (retval > limit);

	return retval;
}

/*
* @detail This routine tests a memory obfuscation technique by creating multiple shared memory-mapped views of a section
* @detail Only 1/N views are writable (and their page protects can't be changed), while the rest are read-only. This means watchpoints won't trigger on writes unless the watchpoint is on the writable view.
* @detail This trick can also trip up naive scanning - by default tools like Cheat Engine have scanning of MEM_MAPPED off, so these regions are skipped completely unless this default option is changed!
* @detail As a result, if an attacker wants to find which instructions write to our data, they have to manually sift through possibly hundreds of addresses which share the same data, making the origin of that data much harder to find, and giving us a high chance of catching them using debug registers
* @detail Pointer scanning on read-only views also will give 0 results, they will be forced to pointer scan on the data's value rather than address
* @return boolean value indicating success or failure of the tests
*/
bool ObfuscateWatchpointsOnStructure()
{
	const SIZE_T N = 256; //make 256 views
	const SIZE_T MAPPED_MEM_SIZE = sizeof(ValuableStruct);

	const int WritableView = rand_lim(N - 1); //pick a random view each time as the writable one

	HANDLE hSec = INVALID_HANDLE_VALUE;
	LARGE_INTEGER cbSectionSize = {};
	cbSectionSize.QuadPart = MAPPED_MEM_SIZE; //minimum size (1 page)

	std::cout << "The writable view will be at index: " << WritableView << std::endl;

	NTSTATUS ntstatus = NtCreateSection(
		&hSec,
		SECTION_ALL_ACCESS,
		NULL,
		&cbSectionSize,
		PAGE_READWRITE,
		SEC_COMMIT | SEC_NO_CHANGE,
		NULL);

	if (hSec == NULL || hSec == INVALID_HANDLE_VALUE)
	{
		std::cerr << "CreateFileMappingW failed: " << GetLastError() << std::endl;
		return false;
	}

	LPVOID mappedView[N]; //create N views, which share the same physical page. Only 1 view should be writable, while the others are read-only

	for (int i = 0; i < N; ++i)
	{
		LARGE_INTEGER cbSectionOffset = {};
		SIZE_T cbViewSize = 0;
		PVOID pViewBase = NULL;

		if (i == WritableView)
		{
			mappedView[WritableView] = MapViewOfFile(hSec, FILE_MAP_WRITE, 0, 0, MAPPED_MEM_SIZE); //only 1 view is writable, so updates to any data are done through this view
		}
		else
		{
			//These sections will not be writable, and they can't have their page protections changed using VirtualProtect without re-re-mapping with a new section
			mappedView[i] = MapViewOfFile(hSec, FILE_MAP_READ, 0, 0, cbSectionSize.QuadPart); //NtMapViewOfSection can also be used if you want
		}

		if (mappedView[i] == NULL)
		{
			std::cerr << "MapViewOfFile failed at loop: " << i << "with error: " << GetLastError() << std::endl;
			continue;
		}

		printf("Mapped view %d at address %llX\n", i, (uintptr_t)mappedView[i]);
	}

	if (mappedView[WritableView] == NULL)
	{
		std::cerr << "[ERROR] Failed to map WRITABLE view: " << GetLastError() << std::endl;
		CloseHandle(hSec);
		return false;
	}

	std::cout << "Mapped WRITABLE view at address: " << std::hex << (uintptr_t)mappedView[WritableView] << std::endl;

	alignas(64) ValuableStruct* ExampleObfuscatedStruct = new (mappedView[WritableView]) ValuableStruct(); //create our memory inside the writable view, while the rest are read-only

	strcpy_s(ExampleObfuscatedStruct->testStr, strlen("Hello!") + 1, "Hello!");

	std::cout << std::dec << N - 1 << " non-writable views now share the same physical page, and 1 view allowing writes." << std::endl;
	std::cout << "Trying to use tools like cheat engine's 'Find out what accesses/writes to this address' will fail, unless it's used on the one writable view's address." << std::endl;
	std::cout << "The user now must either start hooking mapping WINAPIs or manually sifting through " << N << " views before their watchpoint triggers successfully." << std::endl;

	for (int i = 0; i < N; i++)
	{
		if (ExampleObfuscatedStruct)
		{
			ExampleObfuscatedStruct->x = (70 + i); //do some stuff which shows that all view memory is updated together when the writable view is written to
			ExampleObfuscatedStruct->y = (71 + i);
			ExampleObfuscatedStruct->z = (72 + i);

			std::cout << "Incremented structure values by 1: X=" << ExampleObfuscatedStruct->x << ", Y=" << ExampleObfuscatedStruct->y << ", Z=" << ExampleObfuscatedStruct->x << std::endl;
		}

		Sleep(10000);
	}

	for (int i = 0; i < N; ++i) //unmap our views and end the test
	{
		if (mappedView[i])
			UnmapViewOfFile(mappedView[i]);
	}

	//Note that we don't delete the memory of `ExampleObfuscatedStruct` since unmapping the view where it's housed takes care of deallocation
	//Any dynamic resources in structures should get a function to clean them up, as destructors won't be called when unmapping

	CloseHandle(hSec);
	return true;
}

int main()
{
	if (ObfuscateWatchpointsOnStructure())
	{
		std::cout << "Tests ran successfully." << std::endl;
	}
	else
	{
		std::cout << "Tests failed!" << std::endl;
		return -1;
	}

	return 0;
}
