@ECHO OFF
TITLE Windows Driver Kit 7.1.0

REM set target=i386
set target=amd64

set C_LANGUAGE_MODE=/TC
REM set C_LANGUAGE_MODE=/TP

set DDK=C:\WinDDK\7600.16385.1
set MSVC=%DDK%\bin\x86\%target%
set include=/I"%DDK%\inc\crt" /I"%DDK%\inc\api" /I"%CD%\winproject\zlib"
set libs=/LIBPATH:"%DDK%\lib\crt\%target%" /LIBPATH:"%DDK%\lib\wnet\%target%" %src%\winproject\resource.res

set src=%CD%
set output=/OUT:mupen64.exe
set C_FLAGS=/W0 /GL /O1 /Os /Oi /Ob1 /GS- %C_LANGUAGE_MODE% /Fa
set files=%src%\main.c %src%\errors.c %src%\flash_io.c %src%\zs_data.c
set files=%src%\main\win\main_win.c ^
 %src%\main\rom.c ^
 %src%\main\ioapi.c ^
 %src%\main\adler32.c ^
 %src%\main\md5.c ^
 %src%\main\mupenIniApi.c ^
 %src%\main\savestates.c ^
 %src%\main\unzip.c ^
 %src%\memory\memory.c ^
 %src%\memory\pif.c ^
 %src%\memory\dma.c ^
 %src%\memory\tlb.c ^
 %src%\memory\flashram.c ^
 %src%\r4300\r4300.c ^
 %src%\r4300\interupt.c ^
 %src%\r4300\exception.c ^
 %src%\r4300\special.c ^
 %src%\r4300\regimm.c ^
 %src%\r4300\cop0.c ^
 %src%\r4300\tlb.c ^
 %src%\r4300\cop1.c ^
 %src%\r4300\cop1_w.c ^
 %src%\r4300\cop1_s.c ^
 %src%\r4300\cop1_d.c ^
 %src%\r4300\cop1_l.c ^
 %src%\r4300\bc.c ^
 %src%\r4300\pure_interp.c ^
 %src%\r4300\recomp.c ^
 %src%\r4300\x86\gr4300.c ^
 %src%\r4300\x86\assemble.c ^
 %src%\r4300\x86\gspecial.c ^
 %src%\r4300\x86\gregimm.c ^
 %src%\r4300\x86\gcop0.c ^
 %src%\r4300\x86\gtlb.c ^
 %src%\r4300\x86\gcop1.c ^
 %src%\r4300\x86\gbc.c ^
 %src%\r4300\x86\gcop1_s.c ^
 %src%\r4300\x86\gcop1_d.c ^
 %src%\r4300\x86\gcop1_w.c ^
 %src%\r4300\x86\gcop1_l.c ^
 %src%\r4300\x86\rjump.c ^
 %src%\r4300\x86\debug.c ^
 %src%\r4300\x86\regcache.c ^
 %src%\main\vcr.c ^
 %src%\main\win\vcr_compress.c ^
 %src%\main\vcr_resample.c ^
 %src%\main\win\configdialog.c ^
 %src%\main\win\rombrowser.c ^
 %src%\main\win\config.c ^
 %src%\main\win\dumplist.c ^
 %src%\main\win\timers.c ^
 %src%\main\win\inifunctions.c ^
 %src%\main\win\guifuncs.c ^
 %src%\main\win\RomSettings.c ^
 %src%\main\win\translation.c ^
 %src%\main\win\GUI_LogWindow.c ^
 %src%\main\win\kaillera.c ^
 %src%\main\win\commandline.c

%DDK%\bin\x86\rc.exe %include% /fo %src%\winproject\resource.res %src%\winproject\mupen64_private.rc
%MSVC%\cl.exe /MD %include% %C_FLAGS% %files% /link %output% %libs%
pause

rem windres -i  %src%/winproject/mupen64_private.rc --input-format=rc -o $obj/mupen64_private.res -O coff
