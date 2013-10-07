/**
* Date: October 3, 2013
* Authors: Talha Zekeriya Durmuş, talhazekeriyadurmus@gmail.com
* License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).
* Copyright: Rhodeus 2013
*/

module rhodeus.windows.user32;
import rhodeus.windows.d;
import std.stdio;
extern(Windows){
	HWND FindWindowA(LPCTSTR lpClassName, LPCTSTR lpWindowName);
	BOOL SetWindowTextA(HWND hWnd, LPCTSTR lpString);
	int GetWindowTextA(HWND hWnd, LPTSTR lpString, int nMaxCount);
	HWND GetWindowA(HWND hWnd, UINT uCmd);
	HWND FindWindowExA(HWND hwndParent, HWND hwndChildAfter, LPCTSTR lpszClass, LPCTSTR lpszWindow);
	LRESULT SendMessageA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
}

unittest{
	auto hwnd = FindWindowA(null, "Internet Download Manager Configuration");
	if(hwnd is null) {writeln("window didn't found");return;}
	auto button = FindWindowExA(hwnd, null, null, "OK");
	if(button is null) {writeln("button didn't found");return;}
	auto msg = SendMessageA(button, BM_CLICK, 0, 0);//MK_LBUTTON, MAKELPARAM(0, 0)
}
