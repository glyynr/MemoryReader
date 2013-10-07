set PATH=C:\digital-mars\dmd2\windows\bin;C:\Program Files (x86)\Microsoft SDKs\Windows\v7.0A\\bin;%PATH%

echo rhodeus\memory\mem.d >Release\MemoryReader.build.rsp
echo rhodeus\windows\advapi32.d >>Release\MemoryReader.build.rsp
echo rhodeus\windows\d.d >>Release\MemoryReader.build.rsp
echo rhodeus\windows\dbghelp.d >>Release\MemoryReader.build.rsp
echo rhodeus\windows\kernel32.d >>Release\MemoryReader.build.rsp
echo rhodeus\windows\Ntdll.d >>Release\MemoryReader.build.rsp
echo rhodeus\windows\psapi.d >>Release\MemoryReader.build.rsp
echo rhodeus\windows\user32.d >>Release\MemoryReader.build.rsp
echo rhodeus\c.d >>Release\MemoryReader.build.rsp
echo hook.d >>Release\MemoryReader.build.rsp
echo main.d >>Release\MemoryReader.build.rsp
echo main2.d >>Release\MemoryReader.build.rsp
echo searcher.d >>Release\MemoryReader.build.rsp

dmd -release -X -Xf"Release\MemoryReader.json" -deps="Release\MemoryReader.dep" -c -of"Release\MemoryReader.obj" @Release\MemoryReader.build.rsp
if errorlevel 1 goto reportError

set LIB=
echo. > Release\MemoryReader.build.lnkarg
echo "Release\MemoryReader.obj","Release\MemoryReader.exe","Release\MemoryReader.map",user32.lib+ >> Release\MemoryReader.build.lnkarg
echo kernel32.lib,,resources\resource.RES/NOMAP/NOI >> Release\MemoryReader.build.lnkarg

"C:\Program Files (x86)\VisualD\pipedmd.exe" -deps Release\MemoryReader.lnkdep link.exe @Release\MemoryReader.build.lnkarg
if errorlevel 1 goto reportError
if not exist "Release\MemoryReader.exe" (echo "Release\MemoryReader.exe" not created! && goto reportError)

goto noError

:reportError
echo Building Release\MemoryReader.exe failed!

:noError
