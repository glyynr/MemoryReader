/**
* Date: October 7, 2013
* Authors: Talha Zekeriya Durmuş, talhazekeriyadurmus@gmail.com
* License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).
* Copyright: Rhodeus 2013
*/

module rhodeus.windows.advapi32;
import rhodeus.windows.d;

enum ANYSIZE_ARRAY        = 1;
enum SE_PRIVILEGE_ENABLED_BY_DEFAULT    = 0x00000001;
enum SE_PRIVILEGE_ENABLED        = 0x00000002;
enum SE_PRIVILEGE_REMOVED        = 0x00000004;
enum SE_PRIVILEGE_USED_FOR_ACCESS    = 0x80000000;

extern(Windows){
	BOOL LookupPrivilegeValueA(LPCTSTR lpSystemName, LPCTSTR lpName, LUID* lpLuid);
	BOOL AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, TOKEN_PRIVILEGES* NewState,
							   DWORD BufferLength, TOKEN_PRIVILEGES* PreviousState, PDWORD ReturnLength
							   );

	BOOL OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess,PHANDLE TokenHandle
						  );

}

public enum TOKEN_ASSIGN_PRIMARY = 0x0001;
public enum TOKEN_DUPLICATE = 0x0002;
public enum TOKEN_IMPERSONATE = 0x0004;
public enum TOKEN_QUERY = 0x0008;
public enum TOKEN_QUERY_SOURCE = 0x0010;
public enum TOKEN_ADJUST_PRIVILEGES = 0x0020;
public enum TOKEN_ADJUST_GROUPS = 0x0040;
public enum TOKEN_ADJUST_DEFAULT = 0x0080;
public enum TOKEN_ADJUST_SESSIONID = 0x0100;
public enum TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
public enum TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
								TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
								TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
								TOKEN_ADJUST_SESSIONID);


public struct LUID {
	public uint LowPart;
	public int HighPart;
}

struct LUID_AND_ATTRIBUTES {
	public LUID Luid;
	public uint Attributes;
}

struct TOKEN_PRIVILEGES {
	DWORD               PrivilegeCount;
	LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY];
};

