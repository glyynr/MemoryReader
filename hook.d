module hook;
import rhodeus.memory;

void hook(){
	void* MyTestAddress = null;

	auto orig = null;//_GetProcAddress(_WinAPI_GetModuleHandle("shell32.dll"), "ShellExecuteExW");
	//	auto hook = _AddHookApi("Shell32.dll", "ShellExecuteExW", &test);
	/*
	bug var tahminen normal çalışan kod lazım!
	_ChangeHookApi(hook, &test);
	*/
}