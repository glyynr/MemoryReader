module main;
import rhodeus.windows.d;
import std.stdio;
import core.memory;
import std.c.string;
import std.string;
import std.conv;
import std.internal.windows.advapi32;
import std.stream; //testing only
import std.c.stdio;
import std.c.stdlib;

enum ERROR_NOT_ALL_ASSIGNED = 0x514;


struct MEMBLOCK{
    HANDLE hProc;
    void* addr;
    int size;
    void* buffer;
    void* searchmask;
    int matches;
    int data_size;
};

enum SEARCH_CONDITION{
    COND_UNCONDITIONAL,
	COND_EQUALS,
	COND_INCREASED,
	COND_DECREASED,
};


// Enable or disable a privilege in an access token
// source: http://msdn.microsoft.com/en-us/library/aa446619(VS.85).aspx
bool SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
){
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if ( !LookupPrivilegeValueA(null,            // lookup privilege on local system
							   lpszPrivilege,   // privilege to lookup
							   &luid ) )        // receives LUID of privilege
	{
		writefln("LookupPrivilegeValue error: %u\n", GetLastError() );
		return false;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege) tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.
	if ( !AdjustTokenPrivileges(hToken, false, &tp, TOKEN_PRIVILEGES.sizeof, null, null) ){
		writefln("AdjustTokenPrivileges error: %u\n", GetLastError() );
		return false;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED){
		writefln("The token does not have the specified privilege. \n");
		return false;
	}
	return true;
}


MEMBLOCK create_memblock (HANDLE hProc, MEMORY_BASIC_INFORMATION *meminfo, int data_size){
	//MEMBLOCK *mb =cast(MEMBLOCK *) new MEMBLOCK(hProc, meminfo.BaseAddress, meminfo.RegionSize, cast(char*) GC.malloc (meminfo.RegionSize), );


	return MEMBLOCK(hProc, meminfo.BaseAddress, meminfo.RegionSize, GC.malloc (meminfo.RegionSize), 
					GC.calloc (meminfo.RegionSize/8), meminfo.RegionSize, data_size);

    MEMBLOCK *mb =cast(MEMBLOCK *) GC.malloc (MEMBLOCK.sizeof);
    if (mb){
        mb.hProc = hProc;
        mb.addr = meminfo.BaseAddress;
        mb.size = meminfo.RegionSize;
        mb.buffer = GC.malloc (meminfo.RegionSize);
        mb.searchmask = GC.calloc (meminfo.RegionSize/8);
        mb.matches = meminfo.RegionSize;
        mb.data_size = data_size;
    }

    return *mb;
}

void free_memblock (MEMBLOCK *mb){
    if (mb){
        if (mb.buffer){
            GC.free (mb.buffer);
        }
        if (mb.searchmask){
            GC.free (mb.searchmask);
        }
        GC.free (mb);
    }
}

void REMOVE_FROM_SEARCH(ref MEMBLOCK mb, size_t offset) {
	(cast(char*) mb.searchmask)[offset/8] &= 1<<(offset%8); 
}

int IS_IN_SEARCH(MEMBLOCK mb, size_t offset){
	return (cast(char*) mb.searchmask)[offset/8] & (1<<(offset%8));
}

void update_memblock (ref MEMBLOCK mb, SEARCH_CONDITION condition, uint val){
    static char tempbuf[128*1024];
    uint bytes_left;
    uint total_read;
    uint bytes_to_read;
    uint bytes_read;

    if (mb.matches > 0){
        bytes_left = mb.size;
        total_read = 0;
        mb.matches = 0;

        while (bytes_left){
            bytes_to_read = (bytes_left > tempbuf.sizeof) ? tempbuf.sizeof : bytes_left;
            ReadProcessMemory (mb.hProc, mb.addr + total_read, cast(void*) tempbuf, bytes_to_read, cast(DWORD*)&bytes_read);
            if (bytes_read != bytes_to_read) break;

            if (condition == SEARCH_CONDITION.COND_UNCONDITIONAL){
                memset (mb.searchmask + (total_read/8), 0xff, bytes_read/8);
                mb.matches += bytes_read;
            }
            else{
                uint offset;

                for (offset = 0; offset < bytes_read; offset += mb.data_size){
                    if (IS_IN_SEARCH(mb,(total_read+offset))){
                        bool is_match = false;
                        uint temp_val;
                        uint prev_val = 0;

                        switch (mb.data_size){
                            case 1:
                                temp_val = tempbuf[offset];
                                prev_val = *(cast(char*)&mb.buffer[total_read+offset]);
                                break;
                            case 2:
                                temp_val = *(cast(ushort*)&tempbuf[offset]);
                                prev_val = *(cast(ushort*)&mb.buffer[total_read+offset]);
                                break;
                            case 4:
                            default:
                                temp_val = *(cast(uint*)&tempbuf[offset]);
                                prev_val = *(cast(uint*)&mb.buffer[total_read+offset]);
                                break;
                        }

                        switch (condition){
                            case SEARCH_CONDITION.COND_EQUALS:
                                is_match = (temp_val == val);
                                break;
                            case SEARCH_CONDITION.COND_INCREASED:
                                is_match = (temp_val > prev_val);
                                break;
                            case SEARCH_CONDITION.COND_DECREASED:
                                is_match = (temp_val < prev_val);
                                break;
                            default:
                                break;
                        }
                        if (is_match){
                            mb.matches++;
                        }else{
							REMOVE_FROM_SEARCH(mb,(total_read+offset));
                        }
                    }
                }
            }
            memcpy (mb.buffer + total_read, tempbuf.ptr, bytes_read);

            bytes_left -= bytes_read;
            total_read += bytes_read;
        }

        mb.size = total_read;
    }
}


enum WRITABLE = (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
MEMBLOCK[] create_scan (uint pid, int data_size){
    MEMBLOCK[] mb_list;
    MEMORY_BASIC_INFORMATION meminfo;
    char* addr = null;

    HANDLE hProc = OpenProcess (PROCESS_ALL_ACCESS, false, pid);
    DWORD error  = GetLastError();

    if (hProc){
        while (VirtualQueryEx(hProc, addr, &meminfo, meminfo.sizeof)){
            if ((meminfo.State & MEM_COMMIT) && (meminfo.Protect & WRITABLE)){
                mb_list ~= create_memblock(hProc, &meminfo, data_size);
            }
            addr = cast(char*)meminfo.BaseAddress + meminfo.RegionSize;
        }
    }
    else writefln ("Failed to open process - error - %d", error);
    return mb_list;
}


void update_scan (ref MEMBLOCK[] mb_list, SEARCH_CONDITION condition, uint val){
	foreach(ref mb; mb_list){
        update_memblock(mb, condition, val);
	}
}


void dump_scan_info (MEMBLOCK[] mb_list){
    foreach(mb; mb_list){
        int i;
        writefln ("0x%08x %d", mb.addr, mb.size);

        for (i = 0; i < mb.size; i++){
            writefln ("%02x", (cast(char*) mb.buffer)[i]);
        }
        writefln ("");
    }
}


void poke (HANDLE hProc, int data_size, uint addr, uint val){
    if (WriteProcessMemory (hProc, cast(void*)addr, &val, data_size, null) == 0){
        writefln ("poke failed");
    }
}

uint peek (HANDLE hProc, int data_size, uint addr){
    uint val = 0;

    if (ReadProcessMemory (hProc, cast(void*)addr, &val, data_size, null) == 0){
        writefln ("peek failed");
    }

    return val;
}


void print_matches(ref MEMBLOCK[] mb_list){
    foreach(ref mb; mb_list){
        for (uint offset = 0; offset < mb.size; offset += mb.data_size){
            if(IS_IN_SEARCH(mb, offset)){
                uint val = peek (mb.hProc, mb.data_size, cast(uint)mb.addr + offset);
                writefln("0x%08x: 0x%08x (%d) ", mb.addr + offset, val, val);
            }
        }
    }
}



uint str2int (char[] y){
	auto s = y.ptr;
    int base = 10;

    if (s[0] == '0' && s[1] == 'x'){
        base = 16;
        s += 2;
    }

    return strtoul (s, null, base);
}
uint str2int (char *s){
    int base = 10;

    if (s[0] == '0' && s[1] == 'x'){
        base = 16;
        s += 2;
    }

    return strtoul (s, null, base);
}


MEMBLOCK[] ui_new_scan(){
    MEMBLOCK[] scan;
    DWORD pid;
    int data_size;
    uint start_val;
    SEARCH_CONDITION start_cond;
    char[20] s;

    while(1){
        writefln ("Enter the pid: ");
        std.c.stdio.fgets(s.ptr,s.sizeof, std.c.stdio.stdin);
        pid = str2int(s);

		writefln ("Enter the data size: ");
        std.c.stdio.fgets (s.ptr,s.sizeof,std.c.stdio.stdin);
        data_size = str2int (s);
        
		writefln ("Enter the start value, or 'u' for unknown: "); 
        std.c.stdio.fgets (s.ptr,s.sizeof,std.c.stdio.stdin);
        if (s[0] == 'u'){
            start_cond = SEARCH_CONDITION.COND_UNCONDITIONAL;
            start_val = 0;
        }else{
            start_cond = SEARCH_CONDITION.COND_EQUALS;
            start_val = str2int (s);
        }
        
		scan = create_scan(pid, data_size);
        if (scan) break;
        writefln ("Invalid scan");
    }

    update_scan (scan, start_cond, start_val);
    writefln ("%d matches found", scan.length);

    return scan;
}


void ui_poke(HANDLE hProc, int data_size){
    uint addr;
    uint val;
    char s[20];

    writefln ("Enter the address: ");
	std.c.stdio.fgets (s.ptr,s.sizeof,std.c.stdio.stdin);
    addr = str2int (s);

    writefln ("Enter the value: ");
	std.c.stdio.fgets (s.ptr,s.sizeof,std.c.stdio.stdin);
    val = str2int (s);
    writefln ("");

    poke (hProc, data_size, addr, val);
}


void ui_run_scan(){
    uint val;
    char s[20];
    MEMBLOCK[] scan = ui_new_scan();
    while (1){
        writefln ("Enter the next value or");
        writefln ("[i] increased");
        writefln ("[d] decreased");
        writefln ("[m] print matches");
        writefln ("[p] poke address");
        writefln ("[n] new scan");
        writefln ("[q] quit");

		std.c.stdio.fgets(s.ptr,s.sizeof,std.c.stdio.stdin);
        writefln ("");

        switch (s[0]){
            case 'i':
                update_scan (scan, SEARCH_CONDITION.COND_INCREASED, 0);
                writefln ("%d matches found", scan.length);
                break;
            case 'd':
                update_scan (scan, SEARCH_CONDITION.COND_DECREASED, 0);
                writefln ("%d matches found", scan.length);
                break;
            case 'm':
                print_matches(scan);
                break;
            case 'p':
                ui_poke(scan[0].hProc, scan[0].data_size);
                break;
            case 'n':
                scan = ui_new_scan();
                break;
            case 'q':
				scan = null;
                return;
            default:
                val = str2int(s);
                update_scan(scan, SEARCH_CONDITION.COND_EQUALS, val);
                writefln ("%d matches found", scan.length);
                break;
        }
    }
}

//Use these for DesiredAccess

enum SE_DEBUG_NAME = "SeDebugPrivilege".ptr;

int main(){
    // get process handle
    HANDLE hProc = GetCurrentProcess();

    // get access token of process
    HANDLE hToken = null;
    if (!OpenProcessToken(hProc, TOKEN_ADJUST_PRIVILEGES, &hToken))
		writefln ("Failed to open access token");

    // set token privileges to SE_DEBUG_NAME to able to access OpenProcess() with PROCESS_ALL_ACCESS
    if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
        writefln ("Failed to set debug privilege");

    ui_run_scan();
    return 0;
}