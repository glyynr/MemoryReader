/**
* Date: October 3, 2013
* Authors: Talha Zekeriya Durmuş, talhazekeriyadurmus@gmail.com
* License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).
* Copyright: Rhodeus 2013
*/
module rhodeus.windows.psapi;
import rhodeus.windows.d;
import std.stdio;

pragma(lib, "psapi");
extern(Windows){
	/**
	*Removes as many pages as possible from the working set of the specified process.
	*Params:
	*hProcess = 
	*A handle to the process. The handle must have the PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION access right
	* and the PROCESS_SET_QUOTA access right.
	* For more information, see Process Security and Access Rights<http://msdn.microsoft.com/en-us/library/windows/desktop/ms684880(v=vs.85).aspx>.
	*/
	BOOL EmptyWorkingSet(HANDLE hProcess);

	/**
	*Retrieves the load address for each device driver in the system.
	*Params:
	*lpImageBase = 
	*An array that receives the list of load addresses for the device drivers.
	*cb = 
	*The size of the lpImageBase array, in bytes. If the array is not large enough to store the load addresses, the lpcbNeeded parameter receives the required size of the array.
	*lpcbNeeded =
	*The number of bytes returned in the lpImageBase array.

	*/
	BOOL EnumDeviceDrivers(LPVOID* lpImageBase, DWORD cb, DWORD* lpcbNeeded);
	///
	unittest{
		enum ARRAY_SIZE = 1024;
		LPVOID[ARRAY_SIZE] drivers;
		DWORD cbNeeded;
		int cDrivers, i;
		if( EnumDeviceDrivers(drivers.ptr, drivers.sizeof, &cbNeeded) && cbNeeded < drivers.sizeof){ 
			char[ARRAY_SIZE] szDriver;

			cDrivers = cbNeeded / drivers[0].sizeof;

			writeln("There are %d drivers:", cDrivers);      
			for (i=0; i < cDrivers; i++ ){
				if(GetDeviceDriverBaseName(drivers[i], szDriver.ptr, szDriver.sizeof / szDriver[0].sizeof)){
					writefln("%d: %s", i+1, cstr2dstr(szDriver));
				}
			}
		}else{
			writeln("EnumDeviceDrivers failed; array size needed is %d", cbNeeded / LPVOID.sizeof);
			return;
		}
	}

	BOOL EnumPageFiles(typeof(EnumPageFilesProc) pCallbackRoutine,LPVOID lpContext);
	BOOL EnumPageFilesProc(LPVOID pContext, ENUM_PAGE_FILE_INFORMATION* pPageFileInfo, LPCTSTR lpFilename);
	BOOL EnumProcesses(DWORD* pProcessIds, DWORD cb, DWORD* pBytesReturned);
	BOOL EnumProcessModules(HANDLE hProcess, HMODULE *lphModule, DWORD cb, LPDWORD lpcbNeeded);
	BOOL EnumProcessModulesEx(HANDLE hProcess, HMODULE *lphModule, DWORD cb, LPDWORD lpcbNeeded, DWORD dwFilterFlag);
	DWORD GetDeviceDriverBaseName(LPVOID ImageBase,LPTSTR lpBaseName,DWORD nSize);
	DWORD GetDeviceDriverFileName(LPVOID ImageBase, LPTSTR lpFilename, DWORD nSize);
	DWORD GetMappedFileName(HANDLE hProcess, LPVOID lpv, LPTSTR lpFilename, DWORD nSize);
	DWORD GetModuleBaseName(HANDLE hProcess, HMODULE hModule, LPTSTR lpBaseName, DWORD nSize);
	DWORD GetModuleFileNameEx(HANDLE hProcess, HMODULE hModule, LPTSTR lpFilename, DWORD nSize);
	BOOL GetModuleInformation(HANDLE hProcess, HMODULE hModule, MODULEINFO* lpmodinfo, DWORD cb);
	BOOL GetPerformanceInfo(PERFORMANCE_INFORMATION* pPerformanceInformation,DWORD cb);
	DWORD GetProcessImageFileName(HANDLE hProcess,LPTSTR lpImageFileName,DWORD nSize);
	BOOL GetProcessMemoryInfo(HANDLE Process,PROCESS_MEMORY_COUNTERS* ppsmemCounters,DWORD cb);
	BOOL GetWsChanges(HANDLE hProcess,PSAPI_WS_WATCH_INFORMATION* lpWatchInfo,DWORD cb);
	BOOL GetWsChangesEx(HANDLE hProcess,PSAPI_WS_WATCH_INFORMATION_EX* lpWatchInfoEx,PDWORD cb);
	BOOL InitializeProcessForWsWatch(HANDLE hProcess);
	BOOL QueryWorkingSet(HANDLE hProcess,PVOID pv,DWORD cb);
	BOOL QueryWorkingSetEx(HANDLE hProcess,PVOID pv,DWORD cb);



}

unittest{
	void PrintMemoryInfo( DWORD processID ){
		HANDLE hProcess;
		PROCESS_MEMORY_COUNTERS pmc;
		// Print the process identifier.
		printf( "\nProcess ID: %u\n", processID );
		// Print information about the memory usage of the process.
		hProcess = OpenProcess(  ProcessAccessFlags.QueryInformation |
							   ProcessAccessFlags.VMRead ,
							   FALSE, processID );
		if (null == hProcess)
			return;

		if ( GetProcessMemoryInfo( hProcess, &pmc, pmc.sizeof) ){
			printf( "\tPageFaultCount: 0x%08X\n", pmc.PageFaultCount );
			printf( "\tPeakWorkingSetSize: 0x%08X\n", 
				   pmc.PeakWorkingSetSize );
			printf( "\tWorkingSetSize: 0x%08X\n", pmc.WorkingSetSize );
			printf( "\tQuotaPeakPagedPoolUsage: 0x%08X\n", 
				   pmc.QuotaPeakPagedPoolUsage );
			printf( "\tQuotaPagedPoolUsage: 0x%08X\n", 
				   pmc.QuotaPagedPoolUsage );
			printf( "\tQuotaPeakNonPagedPoolUsage: 0x%08X\n", 
				   pmc.QuotaPeakNonPagedPoolUsage );
			printf( "\tQuotaNonPagedPoolUsage: 0x%08X\n", 
				   pmc.QuotaNonPagedPoolUsage );
			printf( "\tPagefileUsage: 0x%08X\n", pmc.PagefileUsage ); 
			printf( "\tPeakPagefileUsage: 0x%08X\n", 
				   pmc.PeakPagefileUsage );
		}

		CloseHandle( hProcess );
	}

	// Get the list of process identifiers.
	DWORD[1024] aProcesses;
	DWORD cbNeeded, cProcesses;
    uint i;
    if ( !EnumProcesses( aProcesses.ptr, aProcesses.sizeof, &cbNeeded ) ){
        return;
    }
	// Calculate how many process identifiers were returned.
    cProcesses = cbNeeded / DWORD.sizeof;
    // Print the memory usage for each process
    for ( i = 0; i < cProcesses; i++ ){
        PrintMemoryInfo( aProcesses[i] );
    }
}

unittest{
	// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS
	// and compile with -DPSAPI_VERSION=1

	void PrintProcessNameAndID( DWORD processID )
	{
		char szProcessName[MAX_PATH] = "<unknown>";

		// Get a handle to the process.

		HANDLE hProcess = OpenProcess(  ProcessAccessFlags.QueryInformation |
									  ProcessAccessFlags.VMRead ,
									  FALSE, processID );

		// Get the process name.
		if (null != hProcess ){
			HMODULE hMod;
			DWORD cbNeeded;
			if ( EnumProcessModules( hProcess, &hMod, hMod.sizeof, &cbNeeded) ){
				GetModuleBaseName( hProcess, hMod, szProcessName.ptr, 
								  szProcessName.sizeof/char.sizeof );
			}
		}
		// Print the process name and identifier.
		writefln( "%s  (PID: %u)", szProcessName.cstr2dstr(), processID );
		// Release the handle to the process.
		CloseHandle( hProcess );
	}

	// Get the list of process identifiers.

	DWORD aProcesses[1024];
	DWORD cbNeeded, cProcesses;
	uint i;

	if ( !EnumProcesses( aProcesses.ptr, aProcesses.sizeof, &cbNeeded ) )
	{
		return;
	}


	// Calculate how many process identifiers were returned.

	cProcesses = cbNeeded / DWORD.sizeof;

	// Print the name and process identifier for each process.

	for ( i = 0; i < cProcesses; i++ )
	{
		if( aProcesses[i] != 0 )
		{
			PrintProcessNameAndID( aProcesses[i] );
		}
	}

}

unittest{
	int PrintModules( DWORD processID )
	{
		HMODULE hMods[1024];
		HANDLE hProcess;
		DWORD cbNeeded;
		uint i;

		// Print the process identifier.

		printf( "\nProcess ID: %u\n", processID );

		// Get a handle to the process.

		hProcess = OpenProcess(  ProcessAccessFlags.QueryInformation |
							   ProcessAccessFlags.VMRead ,
							   FALSE, processID );
		if (null == hProcess)
			return 1;

		// Get a list of all the modules in this process.

		if( EnumProcessModules(hProcess, hMods.ptr, hMods.sizeof, &cbNeeded)){
			for ( i = 0; i < (cbNeeded / HMODULE.sizeof); i++ ){
				char szModName[MAX_PATH];
				// Get the full path to the module's file.
				if ( GetModuleFileNameEx( hProcess, hMods[i], szModName.ptr, szModName.sizeof / char.sizeof)){
					// Print the module name and handle value.
					writefln("\t%s (0x%08X)", szModName.cstr2dstr, hMods[i] );
				}
			}
		}
		// Release the handle to the process.
		CloseHandle( hProcess );
		return 0;
	}

	DWORD aProcesses[1024]; 
	DWORD cbNeeded; 
	DWORD cProcesses;
	uint i;
	// Get the list of process identifiers.
	if ( !EnumProcesses( aProcesses.ptr, aProcesses.sizeof, &cbNeeded ) )
		return;
	// Calculate how many process identifiers were returned.
	cProcesses = cbNeeded / DWORD.sizeof;
	// Print the names of the modules for each process.
	for ( i = 0; i < cProcesses; i++ ){
		PrintModules( aProcesses[i] );
	}
}

/**
*Contains the memory statistics for a process.
*Params:
*cb=
*The size of the structure, in bytes.
*PageFaultCount=
*The number of page faults.
*PeakWorkingSetSize=
*The peak working set size, in bytes.
*WorkingSetSize=
*The current working set size, in bytes.
*QuotaPeakPagedPoolUsage=
*The peak paged pool usage, in bytes.
*QuotaPagedPoolUsage=
*The current paged pool usage, in bytes.
*QuotaPeakNonPagedPoolUsage=
*The peak nonpaged pool usage, in bytes.
*QuotaNonPagedPoolUsage=
*The current nonpaged pool usage, in bytes.
*PagefileUsage=
*The Commit Charge value in bytes for this process. Commit Charge is the total amount of memory that the memory manager has committed for a running process.
*PeakPagefileUsage=
*The peak value in bytes of the Commit Charge during the lifetime of this process.
*/
struct PROCESS_MEMORY_COUNTERS {
	DWORD  cb;
	DWORD  PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
};
enum ProcessAccessFlags : uint{
    All = 0x001F0FFF,
    Terminate = 0x00000001,
    CreateThread = 0x00000002,
    VMOperation = 0x00000008,
    VMRead = 0x00000010,
    VMWrite = 0x00000020,
    DupHandle = 0x00000040,
    SetInformation = 0x00000200,
    QueryInformation = 0x00000400,
    Synchronize = 0x00100000
}


/**
*Contains information about a pagefile.
*Params:
*cb=
*The size of this structure, in bytes.
*Reserved=
*This member is reserved.
*TotalSize=
*The total size of the pagefile, in pages.
*TotalInUse=
*The current pagefile usage, in pages.
*PeakUsage=
*The peak pagefile usage, in pages.
*/
struct ENUM_PAGE_FILE_INFORMATION {
	DWORD  cb;
	DWORD  Reserved;
	SIZE_T TotalSize;
	SIZE_T TotalInUse;
	SIZE_T PeakUsage;
};

/**
*Contains the module load address, size, and entry point.
*Params:
*lpBaseOfDll=
*The load address of the module.
*SizeOfImage=
*The size of the linear space that the module occupies, in bytes.
*EntryPoint=
*The entry point of the module.
*Remarks:
*The load address of a module is the same as the HMODULE value. 
*The information returned in the SizeOfImage and EntryPoint members comes from the module's Portable Executable (PE) header. 
*The module entry point is the location called during process startup, thread startup, process shutdown, and thread shutdown. 
*While this is not the address of the DllMain function, it should be close enough for most purposes.
*/
struct MODULEINFO{
	LPVOID lpBaseOfDll;
	DWORD  SizeOfImage;
	LPVOID EntryPoint;
};

/**
*Contains performance information.
*Params:
*cb=
*The size of this structure, in bytes.
*CommitTotal=
*The number of pages currently committed by the system. Note that committing pages (using VirtualAlloc with MEM_COMMIT) changes this value immediately; however, the physical memory is not charged until the pages are accessed.
*CommitLimit=
*The current maximum number of pages that can be committed by the system without extending the paging file(s). This number can change if memory is added or deleted, or if pagefiles have grown, shrunk, or been added. If the paging file can be extended, this is a soft limit.
*CommitPeak=
*The maximum number of pages that were simultaneously in the committed state since the last system reboot.
*PhysicalTotal=
*The amount of actual physical memory, in pages.
*PhysicalAvailable=
*The amount of physical memory currently available, in pages. This is the amount of physical memory that can be immediately reused without having to write its contents to disk first. It is the sum of the size of the standby, free, and zero lists.
*SystemCache=
*The amount of system cache memory, in pages. This is the size of the standby list plus the system working set.
*KernelTotal=
*The sum of the memory currently in the paged and nonpaged kernel pools, in pages.
*KernelPaged=
*The memory currently in the paged kernel pool, in pages.
*KernelNonpaged=
*The memory currently in the nonpaged kernel pool, in pages.
*PageSize=
*The size of a page, in bytes.
*HandleCount=
*The current number of open handles.
*ProcessCount=
*The current number of processes.
*ThreadCount=
*The current number of threads.
*/
struct PERFORMANCE_INFORMATION {
	DWORD  cb;
	SIZE_T CommitTotal;
	SIZE_T CommitLimit;
	SIZE_T CommitPeak;
	SIZE_T PhysicalTotal;
	SIZE_T PhysicalAvailable;
	SIZE_T SystemCache;
	SIZE_T KernelTotal;
	SIZE_T KernelPaged;
	SIZE_T KernelNonpaged;
	SIZE_T PageSize;
	DWORD  HandleCount;
	DWORD  ProcessCount;
	DWORD  ThreadCount;
};

/**
*Contains extended memory statistics for a process.
*Params:
*cb=
*The size of the structure, in bytes.
*PageFaultCount=
*The number of page faults.
*PeakWorkingSetSize=
*The peak working set size, in bytes.
*WorkingSetSize=
*The current working set size, in bytes.
*QuotaPeakPagedPoolUsage=
*The peak paged pool usage, in bytes.
*QuotaPagedPoolUsage=
*The current paged pool usage, in bytes.
*QuotaPeakNonPagedPoolUsage=
*The peak nonpaged pool usage, in bytes.
*QuotaNonPagedPoolUsage=
*The current nonpaged pool usage, in bytes.
*PagefileUsage=
*The Commit Charge value in bytes for this process. Commit Charge is the total amount of memory that the memory manager has committed for a running process.
*Windows 7 and Windows Server 2008 R2 and earlier:  PagefileUsage is always zero. Check PrivateUsage instead.
*PeakPagefileUsage=
*The peak value in bytes of the Commit Charge during the lifetime of this process.
*PrivateUsage=
*Same as PagefileUsage. The Commit Charge value in bytes for this process. Commit Charge is the total amount of memory that the memory manager has committed for a running process.
*/
struct PROCESS_MEMORY_COUNTERS_EX{
	DWORD  cb;
	DWORD  PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivateUsage;
};


struct PSAPI_WS_WATCH_INFORMATION {
	LPVOID FaultingPc;
	LPVOID FaultingVa;
}

struct PSAPI_WS_WATCH_INFORMATION_EX {
	PSAPI_WS_WATCH_INFORMATION BasicInfo;
	ULONG_PTR                  FaultingThreadId;
	ULONG_PTR                  Flags;
};