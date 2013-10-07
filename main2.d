module main2;
import std.stdio;

import rhodeus.windows.d;

enum TH32CS_SNAPTHREAD = 0x00000004;

import core.memory;

void GetProcessThreads()
{
	DWORD dwCurrentPtocessID = GetCurrentProcessId() ;
	HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) ;
	if(INVALID_HANDLE_VALUE != hThreadSnapshot)
	{
		THREADENTRY32 objThreadEntry32 ;
		objThreadEntry32.dwSize = objThreadEntry32.sizeof ;

		if (Thread32First(hThreadSnapshot, &objThreadEntry32))
		{
			do
			{
				if (dwCurrentPtocessID == objThreadEntry32.th32OwnerProcessID){
					writefln("Thread: %s", objThreadEntry32) ;
					//					char szThread[1024] ;
				}
			}
			while(Thread32Next(hThreadSnapshot, &objThreadEntry32)) ;
		}

		CloseHandle(hThreadSnapshot) ;
	}
}





alias LONG    NTSTATUS;

alias NTSTATUS *pNtQIT (HANDLE, LONG, PVOID, ULONG, PULONG);

enum STATUS_SUCCESS = cast(NTSTATUS)0x00000000L;
enum ThreadQuerySetWin32StartAddress = 9;


extern(Windows){
	alias NTSTATUS function(HANDLE ThreadHandle,LONG ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength) NtQueryInformationThreadForm;

}
DWORD GetThreadStartAddress(HANDLE hThread){
	NTSTATUS ntStatus;
	HANDLE hDupHandle;
	DWORD dwStartAddress;
    HANDLE hCurrentProcess = GetCurrentProcess();
    if(!DuplicateHandle(hCurrentProcess, hThread, hCurrentProcess, &hDupHandle, THREAD_QUERY_INFORMATION, FALSE, 0)){
        
        return 0;
    }

	auto ntdll = LoadLibraryA( "ntdll.dll" );
	scope(exit) FreeLibrary(ntdll);

	NtQueryInformationThreadForm NtQueryInformationThread;

	NtQueryInformationThread = cast(NtQueryInformationThreadForm) GetProcAddress(ntdll, "NtQueryInformationThread");



    ntStatus = NtQueryInformationThread(hDupHandle, ThreadQuerySetWin32StartAddress, &dwStartAddress, dwStartAddress.sizeof, null);
    CloseHandle(hDupHandle);

    if(ntStatus != STATUS_SUCCESS) return 0;
    return dwStartAddress;
}

void main132(){ 
	writeln("??*");
	auto y = GetThreadStartAddress(GetCurrentThread());
	GetProcessThreads();
	writeln(cast(void*) y);
//    writeln((cast(int*) y)[0..100]);
	asm{
		jmp y;
	}
	//writeln(&main);

	GC.disable();
	auto yy32 = cast(int*) GC.calloc(1024*1024*100);
	writeln(yy32);
}



/*
This program demonstrates file mapping, especially how to align a
view with the system file allocation granularity.
*/
enum BUFFSIZE = 1024 ;// size of the memory to examine at any one time

enum FILE_MAP_START= 138240; // starting point within the file of
// the data to examine (135K)

/* The test file. The code below creates the file and populates it,
so there is no need to supply it in advance. */

char* lpcTheFile = cast(char*) "fmtest.txt".ptr; // the file to be manipulated
unittest
{
	HANDLE hMapFile;      // handle for the file's memory-mapped region
	HANDLE hFile;         // the file handle
	BOOL bFlag;           // a result holder
	DWORD dBytesWritten;  // number of bytes written
	DWORD dwFileSize;     // temporary storage for file sizes
	DWORD dwFileMapSize;  // size of the file mapping
	DWORD dwMapViewSize;  // the size of the view
	DWORD dwFileMapStart; // where to start the file map view
	DWORD dwSysGran;      // system allocation granularity
	SYSTEM_INFO SysInfo;  // system information; used to get granularity
	LPVOID lpMapAddress;  // pointer to the base address of the
	// memory-mapped region
	char * pData;         // pointer to the data
	int i;                // loop counter
	int iData;            // on success contains the first int of data
	int iViewDelta;       // the offset into the view where the data
	//shows up

	// Create the test file. Open it "Create Always" to overwrite any
	// existing file. The data is re-created below
	hFile = CreateFileA(lpcTheFile,
					   GENERIC_READ | GENERIC_WRITE,
					   0,
					   null,
					   CREATE_ALWAYS,
					   FILE_ATTRIBUTE_NORMAL,
					   null);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		writefln("hFile is null\n");
		writefln("Target file is %s\n",
				 lpcTheFile);
		return;//4
	}

	// Get the system allocation granularity.
	GetSystemInfo(&SysInfo);
	dwSysGran = SysInfo.dwAllocationGranularity;

	// Now calculate a few variables. Calculate the file offsets as
	// 64-bit values, and then get the low-order 32 bits for the
	// function calls.

	// To calculate where to start the file mapping, round down the
	// offset of the data into the file to the nearest multiple of the
	// system allocation granularity.

	dwFileMapStart = (FILE_MAP_START / dwSysGran) * dwSysGran;
	writefln ("The file map view starts at %s bytes into the file.\n",
			  dwFileMapStart);

	// Calculate the size of the file mapping view.
	dwMapViewSize = (FILE_MAP_START % dwSysGran) + BUFFSIZE;
	writefln (("The file map view is %s bytes large.\n"),
			  dwMapViewSize);

	// How large will the file mapping object be?
	dwFileMapSize = FILE_MAP_START + BUFFSIZE;
	writefln (("The file mapping object is %s bytes large.\n"),
			  dwFileMapSize);

	// The data of interest isn't at the beginning of the
	// view, so determine how far into the view to set the pointer.
	iViewDelta = FILE_MAP_START - dwFileMapStart;
	writefln (("The data is %d bytes into the view.\n"),
			  iViewDelta);

	// Now write a file with data suitable for experimentation. This
	// provides unique int (4-byte) offsets in the file for easy visual
	// inspection. Note that this code does not check for storage
	// medium overflow or other errors, which production code should
	// do. Because an int is 4 bytes, the value at the pointer to the
	// data should be one quarter of the desired offset into the file

	for (i=0; i<cast(int)dwSysGran; i++)
	{
		WriteFile (hFile, &i, i.sizeof, &dBytesWritten, null);
	}

	// Verify that the correct file size was written.
	dwFileSize = GetFileSize(hFile,  null);
	writefln(("hFile size: %10d\n"), dwFileSize);

	// Create a file mapping object for the file
	// Note that it is a good idea to ensure the file size is not zero
	hMapFile = CreateFileMappingA( hFile,          // current file handle
								 null,           // default security
								 PAGE_READWRITE, // read/write permission
								 0,              // size of mapping object, high
								 dwFileMapSize,  // size of mapping object, low
								 null);          // name of mapping object

	if (hMapFile == null)
	{
		writefln(("hMapFile is null: last error: %d\n"), GetLastError() );
		return;//2
	}

	// Map the view and test the results.

	lpMapAddress = MapViewOfFile(hMapFile,            // handle to
								 // mapping object
								 FILE_MAP_ALL_ACCESS, // read/write
								 0,                   // high-order 32
								 // bits of file
								 // offset
								 dwFileMapStart,      // low-order 32
								 // bits of file
								 // offset
								 dwMapViewSize);      // number of bytes
	// to map
	if (lpMapAddress == null)
	{
		writefln(("lpMapAddress is null: last error: %d\n"), GetLastError());
		return;//3
	}

	// Calculate the pointer to the data.
	pData = cast(char *) lpMapAddress + iViewDelta;

	// Extract the data, an int. Cast the pointer pData from a "pointer
	// to char" to a "pointer to int" to get the whole thing
	iData = *cast(int *)pData;

	writefln (("The value at the pointer is %d,\nwhich %s one quarter of the desired file offset.\n"),
			  iData,
			  iData*4 == FILE_MAP_START ? ("is") : ("is not"));

	// Close the file mapping object and the open file

	bFlag = UnmapViewOfFile(lpMapAddress);
	bFlag = CloseHandle(hMapFile); // close the file mapping object

	if(!bFlag)
	{
		writefln(("\nError %ld occurred closing the mapping object!"),
				 GetLastError());
	}

	bFlag = CloseHandle(hFile);   // close the file itself

	if(!bFlag)
	{
		writefln(("\nError %ld occurred closing the file!"),
				 GetLastError());
	}
}


/*int main3()
{
	auto yy = GC.malloc(4_000_000);
    DWORD LastError;
    HANDLE hHeap;
    PROCESS_HEAP_ENTRY Entry;

    //
    // Create a new heap with default parameters.
    //
    hHeap = HeapCreate(0, 0, 0);
    if (hHeap == null) {
        writefln(("Failed to create a new heap with LastError %d.\n"),
                 GetLastError());
        return 1;
    }

    //
    // Lock the heap to prevent other threads from accessing the heap 
    // during enumeration.
    //
    if (HeapLock(hHeap) == FALSE) {
        writefln(("Failed to lock heap with LastError %d.\n"),
                 GetLastError());
        return 1;
    }

    writefln(("Walking heap %s...\n\n"), hHeap);

    Entry.lpData = null;
    while (HeapWalk(hHeap, &Entry) != FALSE) {
        if ((Entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0) {
            writefln(("Allocated block"));

            if ((Entry.wFlags & PROCESS_HEAP_ENTRY_MOVEABLE) != 0) {
                writefln((", movable with HANDLE %s"), Entry.hMem);
            }

            if ((Entry.wFlags & PROCESS_HEAP_ENTRY_DDESHARE) != 0) {
                writefln((", DDESHARE"));
            }
        }
        else if ((Entry.wFlags & PROCESS_HEAP_REGION) != 0) {
            writefln("Region\n  %d bytes committed\n" 
                     "  %d bytes uncommitted\n  First block address: %s\n"
                     "  Last block address: %s\n",
                     Entry.dwCommittedSize,
                     Entry.dwUnCommittedSize,
                     Entry.lpFirstBlock,
                     Entry.lpLastBlock);
        }
        else if ((Entry.wFlags & PROCESS_HEAP_UNCOMMITTED_RANGE) != 0) {
            writefln(("Uncommitted range\n"));
        }
        else {
            writefln(("Block\n"));
        }

        writefln("  Data portion begins at: %s\n  Size: %d bytes\n"
                 "  Overhead: %d bytes\n  Region index: %d\n\n",
                 Entry.lpData,
                 Entry.cbData,
                 Entry.cbOverhead,
                 Entry.iRegionIndex);
    }
    LastError = GetLastError();
    if (LastError != ERROR_NO_MORE_ITEMS) {
        writefln(("HeapWalk failed with LastError %d.\n"), LastError);
    }

    //
    // Unlock the heap to allow other threads to access the heap after 
    // enumeration has completed.
    //
    if (HeapUnlock(hHeap) == FALSE) {
        writefln(("Failed to unlock heap with LastError %d.\n"),
                 GetLastError());
    }

    //
    // When a process terminates, allocated memory is reclaimed by the operating
    // system so it is not really necessary to call HeapDestroy in this example.
    // However, it may be advisable to call HeapDestroy in a longer running
    // application.
    //
    if (HeapDestroy(hHeap) == FALSE) {
        writefln(("Failed to destroy heap with LastError %d.\n"),
                 GetLastError());
    }

	while(1){}

    return 0;
}*/





///Window title
unittest{
	import rhodeus.windows.d;
	auto hwnd = FindWindowA(null, "Cheat Engine 6.3");
	if(hwnd is null) return;
	char[255] name;
	hwnd.GetWindowTextA(name.ptr, 255);
	hwnd.SetWindowTextA("CE 5.6".ptr).writeln ;
	hwnd.GetWindowTextA(name.ptr, 255);
	writeln(name);
}

/*int main2(){


	auto pid = MEM.GetPID("explorer.exe");
	
	PrintMemoryInfo( pid);
	*/

	/*auto lotr = new MEM("Wolfteam.bin");
	int adr = 0x00000000;
	int i;
	int topl;
	//	writeln("vay?");
	while(adr < 0xffffffff){
		i = 0;
		foreach(val; lotr.pointerRead!(int[20_000])(adr)){
			if(val == 4000){
				writeln(topl++);
				writeln(cast(void*) (adr+i*4), " => ",val);
			}
			i++;
		}
		adr += int.sizeof * 20_000;
	}
	writeln("vay?");
	while(1){}*/

	/*	
	while(1){}*/
	/* Defines */
/*auto money = TypeTuple!(0x9F9D90, 0x10, 0x94);

	auto money_write = 0x7AFF93;
	auto lotr = new MEM("game.dat");
	auto y = lotr.write!(ubyte[])(money_write, [0x90,0x90,0x90]);
*/
//	auto y = lotr.pointerRead!int(0x9F9D90, 0x10, 0x94);
//	lotr.pointerWrite(1_000_000, money);
/*	return 0;
}*/