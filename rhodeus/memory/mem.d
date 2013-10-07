module rhodeus.memory;

import rhodeus.windows.d;
import std.stdio;
import core.vararg;
import std.string;
import std.range;
import std.traits;

class MEM{
	private HANDLE hProcess;
	this(string name){
		auto pid = GetPID(name);
		if(pid == 0) throw new Exception("Application hasn't found.");
		hProcess = OpenProcess(0x1F0FFF, 0, pid);
	}
	~this(){
		CloseHandle(hProcess);
	}

	void* cachebase = cast(void*) -1;

	public void* baseAddress(){
		if(cachebase !is cast(void*) -1) return cachebase;
		void* iv_Address = cast(void*) 0x00100000;
		MEMORY_BASIC_INFORMATION mbi;
		VirtualQueryEx(hProcess, iv_Address, &mbi, mbi.sizeof);
		while(mbi.AllocationProtect !is 0x00000080){
			VirtualQueryEx(hProcess, iv_Address, &mbi, mbi.sizeof);
			if(iv_Address is cast(void*) 0x01000000) break;
			iv_Address += 65536;
		}
		cachebase = mbi.AllocationBase;
		return cachebase;
	}

	public static int GetPID(string name){
		PROCESSENTRY32 entry;
		entry.dwSize = PROCESSENTRY32.sizeof;

		HANDLE snapshot = CreateToolhelp32Snapshot(CreateToolhelp32SnapshotFlags.TH32CS_SNAPPROCESS, 0);

		if (Process32First(snapshot, &entry) == TRUE){
			while (Process32Next(snapshot, &entry) == TRUE){
				if (name == entry.szExeFile.ptr.cstr2dstr()){
					return entry.th32ProcessID;
				}
			}
		}
		CloseHandle(snapshot);
		return 0;
	}

	T pointerRead(T)(int static_offset, int[] offsets...){
		if(offsets.length < 1){
			/*static if (!isArray!T){
				return read!(T)(cast(int) baseAddress() + static_offset);
			}else*/
				return read!(T)(cast(int) baseAddress() + static_offset);
		}
		auto adr = read!(void*)(cast(int) baseAddress() + static_offset);
		foreach(offset; offsets[0..$-1]){
			adr = read!(void*)(cast(int) (adr + offset));
		}
		return read!(T)(cast(int) (adr + offsets[$-1]));
	}
	bool pointerWrite(T)(T value,int static_offset, int[] offsets...){
		if(offsets.length < 1) return write(cast(int) baseAddress() + static_offset, value);
		auto adr = read!(void*)(cast(int) baseAddress() + static_offset);
		foreach(offset; offsets[0..$-1]){
			adr = read!(void*)(cast(int) (adr + offset));
		}
		return write(cast(int) (adr + offsets[$-1]), value);
	}

	T read(T)(inout int adr) if (!isArray!T){
		T value;
		auto test = ReadProcessMemory(this.hProcess, cast(LPCVOID) adr, cast(void*) &value, T.sizeof, null);
		return value;
	}

	T read(T)(inout int adr) if (isArray!T){
		T value;
		auto test = ReadProcessMemory(this.hProcess, cast(LPCVOID) adr, cast(void*) value.ptr, (ElementType!T).sizeof * value.length, null);
		return value;
	}

	bool write(T)(inout int adr, T value) if (!isArray!T) {
		return cast(bool) WriteProcessMemory(this.hProcess, cast(LPCVOID) adr, cast(void*) &value, T.sizeof, null);
	}
	bool write(T)(inout int adr, T value) if (isArray!T) {
		return cast(bool) WriteProcessMemory(this.hProcess, cast(LPCVOID) adr, cast(void*) value.ptr, (ElementType!T).sizeof * value.length, null);
	}
}
struct IMAGE_IMPORT_DESCRIPTOR{
	int DUMMYUNIONNAME;
	int TimeDateStamp;
	int ForwarderChain;
	int Name;
	int FirstThunk;
}
void _ChangeHookApi(void* itd, void* newProc){
	MEMORY_BASIC_INFORMATION mbi;
	VirtualQuery(itd, &mbi, MEMORY_BASIC_INFORMATION.sizeof);
	VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &mbi.Protect);
	itd = newProc;//Here is the magic!
	uint randomdword;
	VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &randomdword);
}
auto _AddHookApi(string moduleName, string functionName, void* newProcAddress){
	auto dbghelp = LoadLibraryA( "dbghelp.dll" );
	scope(exit) FreeLibrary(dbghelp);
	auto ImageDirectoryEntryToData = cast(ImageDirectoryEntryToDataForm) GetProcAddress(dbghelp, "ImageDirectoryEntryToData");


	void* hInstance = GetModuleHandleA(null);
	void* modul = GetModuleHandleA(moduleName.toStringz());
	auto OrigAddress = GetProcAddress(modul, functionName.toStringz() );

	ULONG ulSize;
	auto iid = cast(IMAGE_IMPORT_DESCRIPTOR*) ImageDirectoryEntryToData(hInstance, true, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize);
	while(cast(char*) (iid.Name)){
		if(cstr2dstr(( cast(char*) (hInstance + iid.Name) ) ) == moduleName){
			break;
		}
		iid++;
	}

	auto itd = cast(void*) hInstance + iid.FirstThunk;

	while(itd){
		if(cast(typeof(OrigAddress)) itd == OrigAddress){
			MEMORY_BASIC_INFORMATION mbi;
			VirtualQuery(itd, &mbi, MEMORY_BASIC_INFORMATION.sizeof);
			VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &mbi.Protect);
			itd = newProcAddress;//Here is the magic!
			uint randomdword;
			VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &randomdword);
			break;
		}
		itd++;
	}
	return itd;
}
