@set EXFLAGS=-DENABLE_SAVE_TESTS -DENABLE_SAVE_KB
nmake.exe /nologo /f nmake.w32 %1 %2 %3 %4 %5 %6 %7 %8 %9 "EXFLAGS=%EXFLAGS%"
@set EXFLAGS=
