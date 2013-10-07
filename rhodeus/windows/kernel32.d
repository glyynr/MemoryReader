/**
* Date: October 3, 2013
* Authors: Talha Zekeriya Durmuş, talhazekeriyadurmus@gmail.com
* License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).
* Copyright: Rhodeus 2013
*/
module rhodeus.windows.kernel32;
import rhodeus.windows.d;

import std.stdio;
pragma(lib, "kernel32");

enum PROCESS_HEAP_ENTRY_BUSY = 0x0004;
enum PROCESS_HEAP_ENTRY_MOVEABLE = 0x0010;
enum PROCESS_HEAP_ENTRY_DDESHARE = 0x0020;
enum PROCESS_HEAP_UNCOMMITTED_RANGE = 0x0002;
enum PROCESS_HEAP_REGION = 0x0001;
struct PROCESS_HEAP_ENTRY {
	PVOID lpData;
	DWORD cbData;
	BYTE  cbOverhead;
	BYTE  iRegionIndex;
	WORD  wFlags;
	union {
		struct{
			HANDLE hMem;
			DWORD  dwReserved[3];
		};
		struct{
			DWORD  dwCommittedSize;
			DWORD  dwUnCommittedSize;
			LPVOID lpFirstBlock;
			LPVOID lpLastBlock;
		} ;
	};
};

extern(Windows){

	HANDLE HeapCreate(DWORD flOptions,SIZE_T dwInitialSize,SIZE_T dwMaximumSize);
	BOOL HeapLock(HANDLE hHeap);
	BOOL HeapUnlock(HANDLE hHeap);
	BOOL HeapDestroy(HANDLE hHeap);

	BOOL HeapWalk(HANDLE hHeap,PROCESS_HEAP_ENTRY* lpEntry);

	LPVOID HeapAlloc(HANDLE hHeap,DWORD dwFlags,SIZE_T dwBytes);
	BOOL HeapFree(HANDLE hHeap,DWORD dwFlags,LPVOID lpMem);
	HANDLE GetProcessHeap();
	DWORD GetProcessHeaps(DWORD NumberOfHeaps,PHANDLE ProcessHeaps);
	HANDLE OpenFileMappingA(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCTSTR lpName);
	HANDLE OpenProcess(uint dwDesiredAccess, BOOL bInheritHandle, uint dwProcessId);
	BOOL Process32First(HANDLE hSnapshot, PROCESSENTRY32* lppe);
	BOOL Process32Next(HANDLE hSnapshot, PROCESSENTRY32* lppe);	
	BOOL Thread32First(HANDLE hSnapshot,THREADENTRY32* lpte);
	BOOL Thread32Next(HANDLE hSnapshot,THREADENTRY32* lpte);
	HANDLE CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
	BOOL ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
	BOOL WriteProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
}

struct THREADENTRY32 {
	DWORD dwSize;
	DWORD cntUsage;
	DWORD th32ThreadID;
	DWORD th32OwnerProcessID;
	LONG  tpBasePri;
	LONG  tpDeltaPri;
	DWORD dwFlags;
};

struct PROCESSENTRY32{
	uint dwSize;
	uint cntUsage;
	uint th32ProcessID;
	uint th32DefaultHeapID;
	uint th32ModuleID;
	uint cntThreads;
	uint th32ParentProcessID;
	int  pcPriClassBase;
	uint dwFlags;
	char[MAX_PATH] szExeFile;
};

public class CreateToolhelp32SnapshotFlags{
    public const uint TH32CS_SNAPHEAPLIST = 0x00000001;
    public const uint TH32CS_SNAPPROCESS  = 0x00000002;
    public const uint TH32CS_SNAPTHREAD   = 0x00000004;
    public const uint TH32CS_SNAPMODULE   = 0x00000008;
    public const uint TH32CS_SNAPMODULE32 = 0x00000010;
    public const uint TH32CS_SNAPALL      = (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE);
    public const uint TH32CS_INHERIT      = 0x80000000;
}

enum : DWORD
{
	THREAD_TERMINATE                 = 0x0001,  
	THREAD_SUSPEND_RESUME            = 0x0002,  
	THREAD_GET_CONTEXT               = 0x0008,  
	THREAD_SET_CONTEXT               = 0x0010,  
	THREAD_QUERY_INFORMATION         = 0x0040,  
	THREAD_SET_INFORMATION           = 0x0020,  
	THREAD_SET_THREAD_TOKEN          = 0x0080,
	THREAD_IMPERSONATE               = 0x0100,
	THREAD_DIRECT_IMPERSONATION      = 0x0200,

	THREAD_SET_LIMITED_INFORMATION   = 0x0400,
	THREAD_QUERY_LIMITED_INFORMATION = 0x0800,

	THREAD_ALL_ACCESS        = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3FF
}
enum{
	PROCESS_TERMINATE     = 0x00000001,
	PROCESS_CREATE_THREAD     = 0x00000002,
	PROCESS_SET_SESSIONID     = 0x00000004,
	PROCESS_VM_OPERATION      = 0x00000008,
	PROCESS_VM_READ       = 0x00000010,
	PROCESS_VM_WRITE      = 0x00000020,
	PROCESS_DUP_HANDLE    = 0x00000040,
	PROCESS_CREATE_PROCESS    = 0x00000080,
	PROCESS_SET_QUOTA     = 0x00000100,
	PROCESS_SET_INFORMATION   = 0x00000200,
	PROCESS_QUERY_INFORMATION = 0x00000400,
	PROCESS_ALL_ACCESS = PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_SET_SESSIONID | PROCESS_VM_OPERATION |
	PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE | PROCESS_CREATE_PROCESS | PROCESS_SET_QUOTA |
	PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION | STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE
}

unittest{
	DWORD NumberOfHeaps;
    DWORD HeapsIndex;
    DWORD HeapsLength;
    HANDLE hDefaultProcessHeap;
    HRESULT Result;
    PHANDLE aHeaps;
    SIZE_T BytesToAllocate;

    //
    // Retrieve the number of active heaps for the current process
    // so we can calculate the buffer size needed for the heap handles.
    //
    NumberOfHeaps = GetProcessHeaps(0, null);
    if (NumberOfHeaps == 0) {
        writefln("Failed to retrieve the number of heaps with LastError %d.\n",
                 GetLastError());
        return;
    }

    //
    // Calculate the buffer size.
    //
	BytesToAllocate = (*aHeaps).sizeof * NumberOfHeaps;//SIZETMult(NumberOfHeaps, (*aHeaps).sizeof, &BytesToAllocate);

    //
    // Get a handle to the default process heap.
    //
    hDefaultProcessHeap = GetProcessHeap();
    if (hDefaultProcessHeap == null) {
        writefln("Failed to retrieve the default process heap with LastError %d.\n",
                 GetLastError());
        return;
    }

    //
    // Allocate the buffer from the default process heap.
    //
    aHeaps = cast(PHANDLE)HeapAlloc(hDefaultProcessHeap, 0, BytesToAllocate);
    if (aHeaps == null) {
        writefln("HeapAlloc failed to allocate %d bytes.\n",
                 BytesToAllocate);
        return;
    }

    // 
    // Save the original number of heaps because we are going to compare it
    // to the return value of the next GetProcessHeaps call.
    //
    HeapsLength = NumberOfHeaps;

    //
    // Retrieve handles to the process heaps and print them to stdout. 
    // Note that heap functions should be called only on the default heap of the process
    // or on private heaps that your component creates by calling HeapCreate.
    //
    NumberOfHeaps = GetProcessHeaps(HeapsLength, aHeaps);
    if (NumberOfHeaps == 0) {
        writefln("Failed to retrieve heaps with LastError %d.\n",
                 GetLastError());
        return;
    }
    else if (NumberOfHeaps > HeapsLength) {

        //
        // Compare the latest number of heaps with the original number of heaps.
        // If the latest number is larger than the original number, another
        // component has created a new heap and the buffer is too small.
        //
        writefln("Another component created a heap between calls. ""Please try again.\n");
        return;
    }

    writefln("Process has %d heaps.", HeapsLength);
    for (HeapsIndex = 0; HeapsIndex < HeapsLength; ++HeapsIndex) {
        writefln("Heap %d at address: %s.",
                 HeapsIndex,
                 aHeaps[HeapsIndex]);
    }

    //
    // Release memory allocated from default process heap.
    //
    if (HeapFree(hDefaultProcessHeap, 0, aHeaps) == FALSE) {
        writeln("Failed to free allocation from default process heap.\n");
    }
}

unittest{
	enum BUF_SIZE = 256;
	enum szName = "Global\\MyFileMappingObject";
	enum szMsg="Message from first process.";

	HANDLE hMapFile;
	LPCTSTR pBuf;

	int y(){

		hMapFile = CreateFileMappingA(
									  INVALID_HANDLE_VALUE,    // use paging file
									  null,                    // default security
									  PAGE_READWRITE,          // read/write access
									  0,                       // maximum object size (high-order DWORD)
									  BUF_SIZE,                // maximum object size (low-order DWORD)
									  szName);                 // name of mapping object

		if (hMapFile == null){
			writefln("Could not create file mapping object (%d).\n", GetLastError());
			return 1;
		}
		pBuf = cast(LPTSTR) MapViewOfFile(hMapFile,   // handle to map object
										  FILE_MAP_ALL_ACCESS, // read/write permission
										  0,
										  0,
										  BUF_SIZE);

		if (pBuf == null)
		{
			writefln("Could not map view of file (%d).\n",
					 GetLastError());

			CloseHandle(hMapFile);

			return 1;
		}
		(cast(char*) pBuf)[0..strlen(szMsg)] = szMsg[];
		//CopyMemoryA(cast(PVOID)pBuf, szMsg.ptr, (strlen(szMsg) * char.sizeof));
		//_getch();

		return 0;

	}
	y();

	hMapFile = OpenFileMappingA(
								FILE_MAP_ALL_ACCESS,   // read/write access
								FALSE,                 // do not inherit the name
								szName);               // name of mapping object

	if (hMapFile == null){
		writefln("Could not open file mapping object (%d).\n", GetLastError());
		return;
	}

	pBuf = cast(LPTSTR) MapViewOfFile(hMapFile, // handle to map object
									  FILE_MAP_ALL_ACCESS,  // read/write permission
									  0,
									  0,
									  BUF_SIZE);

	if (pBuf == null){
		writefln("Could not map view of file (%d).\n", GetLastError());
		CloseHandle(hMapFile);
		return;
	}
	MessageBoxA(null, pBuf, "Process2", MB_OK);
	UnmapViewOfFile(pBuf);
	CloseHandle(hMapFile);
}