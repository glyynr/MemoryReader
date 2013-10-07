module searcher;

import rhodeus.windows.d;
import std.stdio;

bool Compare(const(BYTE)* pData, const(BYTE)* bMask, inout(char)* szMask){
	for(;*szMask;++szMask,++pData,++bMask){
		writeln(pData);
		if(*szMask=='x' && *pData!=*bMask) return 0;
	}
	return cast(char*) (*szMask) is null;
}
DWORD Pattern(DWORD dwAddress,DWORD dwLen,BYTE* bMask,inout(char)* szMask){
	writeln(dwAddress, "--", dwLen, "--", bMask, "--",szMask);
	for(DWORD i=0; i<dwLen; i++)
		if (Compare(cast(BYTE*)(dwAddress+i),bMask,szMask))  return cast(DWORD)(dwAddress+i);
	return 0;
}
bool Finished = false;
DWORD Status;

void GetAddresses (){
	Status = Pattern(cast(DWORD) GetModuleHandleA("CShell.dll"), cast(uint) 0x97D000, cast(PBYTE)"\x71\x37\x50\x94\x71\x37", "xxxxxx");
	if(Status){
		Status -= 0xA;
	}
}

void app(){
	if(Finished == false){
		GetAddresses();
		Finished = true;
		Sleep(300);
	}
	if(Status == 1){
		/*
		Do whatever you want to do. When (Status == 1), It means you are ingame. You can use this method for ANY FindPatterns to get addresses.
		*/
	}
}