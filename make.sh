src="."
obj="$src/compiled"

CC=cc
AS=as
#CC=C:/MinGW/bin/gcc.exe
#AS=C:/MinGW/bin/as.exe

#FLAGS_GTK=pkg-config gtk+-2.0 --cflags -D_GTK2
FLAGS_ANSI="\
 -S \
 -Os \
 -ansi \
 -std=c89 \
 -pedantic \
 -Wall \
 -pipe"
FLAGS_x86_64="\
 -S \
 -masm=att \
 -DX86 \
 -DVCR_SUPPORT \
 -O3 \
 -msse2 \
 -fexpensive-optimizations \
 -fomit-frame-pointer \
 -funroll-loops \
 -ffast-math \
 -fno-strict-aliasing"

C_FLAGS=$FLAGS_x86_64

mkdir -p $obj/main/win
mkdir -p $obj/memory
mkdir -p $obj/r4300/x86

echo Compiling Mupen64 core...
$CC $C_FLAGS -o $obj/main/win/main_win.s $src/main/win/main_win.c
$CC $C_FLAGS -o $obj/main/rom.s $src/main/rom.c
$CC $C_FLAGS -o $obj/main/ioapi.s $src/main/ioapi.c
$CC $C_FLAGS -o $obj/main/adler32.s $src/main/adler32.c
$CC $C_FLAGS -o $obj/main/md5.s $src/main/md5.c
$CC $C_FLAGS -o $obj/main/mupenIniApi.s $src/main/mupenIniApi.c
$CC $C_FLAGS -o $obj/main/savestates.s $src/main/savestates.c
#$CC $C_FLAGS -o $obj/main/plugin.s $src/main/plugin.c
$CC $C_FLAGS -o $obj/main/unzip.s $src/main/unzip.c
$CC $C_FLAGS -o $obj/memory/memory.s $src/memory/memory.c
$CC $C_FLAGS -o $obj/memory/pif.s $src/memory/pif.c
$CC $C_FLAGS -o $obj/memory/dma.s $src/memory/dma.c
$CC $C_FLAGS -o $obj/memory/tlb.s $src/memory/tlb.c
$CC $C_FLAGS -o $obj/memory/flashram.s $src/memory/flashram.c
$CC $C_FLAGS -o $obj/r4300/r4300.s $src/r4300/r4300.c
$CC $C_FLAGS -o $obj/r4300/interupt.s $src/r4300/interupt.c
$CC $C_FLAGS -o $obj/r4300/exception.s $src/r4300/exception.c
$CC $C_FLAGS -o $obj/r4300/special.s $src/r4300/special.c
$CC $C_FLAGS -o $obj/r4300/regimm.s $src/r4300/regimm.c
$CC $C_FLAGS -o $obj/r4300/cop0.s $src/r4300/cop0.c
$CC $C_FLAGS -o $obj/r4300/tlb.s $src/r4300/tlb.c
$CC $C_FLAGS -o $obj/r4300/cop1.s $src/r4300/cop1.c
$CC $C_FLAGS -o $obj/r4300/cop1_w.s $src/r4300/cop1_w.c
$CC $C_FLAGS -o $obj/r4300/cop1_s.s $src/r4300/cop1_s.c
$CC $C_FLAGS -o $obj/r4300/cop1_d.s $src/r4300/cop1_d.c
$CC $C_FLAGS -o $obj/r4300/cop1_l.s $src/r4300/cop1_l.c
$CC $C_FLAGS -o $obj/r4300/bc.s $src/r4300/bc.c
#$CC $C_FLAGS -o $obj/r4300/compare_core.s $src/r4300/compare_core.c
#$CC $C_FLAGS -o $obj/r4300/profile.s $src/r4300/profile.c
$CC $C_FLAGS -o $obj/r4300/pure_interp.s $src/r4300/pure_interp.c
$CC $C_FLAGS -o $obj/r4300/recomp.s $src/r4300/recomp.c

echo Compiling Mupen64 x86 libraries...
$CC $C_FLAGS -o $obj/r4300/x86/gr4300.s $src/r4300/x86/gr4300.c
$CC $C_FLAGS -o $obj/r4300/x86/assemble.s $src/r4300/x86/assemble.c
$CC $C_FLAGS -o $obj/r4300/x86/gspecial.s $src/r4300/x86/gspecial.c
$CC $C_FLAGS -o $obj/r4300/x86/gregimm.s $src/r4300/x86/gregimm.c
$CC $C_FLAGS -o $obj/r4300/x86/gcop0.s $src/r4300/x86/gcop0.c
$CC $C_FLAGS -o $obj/r4300/x86/gtlb.s $src/r4300/x86/gtlb.c
$CC $C_FLAGS -o $obj/r4300/x86/gcop1.s $src/r4300/x86/gcop1.c
$CC $C_FLAGS -o $obj/r4300/x86/gbc.s $src/r4300/x86/gbc.c
$CC $C_FLAGS -o $obj/r4300/x86/gcop1_s.s $src/r4300/x86/gcop1_s.c
$CC $C_FLAGS -o $obj/r4300/x86/gcop1_d.s $src/r4300/x86/gcop1_d.c
$CC $C_FLAGS -o $obj/r4300/x86/gcop1_w.s $src/r4300/x86/gcop1_w.c
$CC $C_FLAGS -o $obj/r4300/x86/gcop1_l.s $src/r4300/x86/gcop1_l.c
$CC $C_FLAGS -o $obj/r4300/x86/rjump.s $src/r4300/x86/rjump.c
$CC $C_FLAGS -o $obj/r4300/x86/debug.s $src/r4300/x86/debug.c
$CC $C_FLAGS -o $obj/r4300/x86/regcache.s $src/r4300/x86/regcache.c

echo Compiling Mupen64 VCR support...
$CC $C_FLAGS -o $obj/main/vcr.s $src/main/vcr.c
$CC $C_FLAGS -o $obj/main/win/vcr_compress.s $src/main/win/vcr_compress.c
$CC $C_FLAGS -o $obj/main/vcr_resample.s $src/main/vcr_resample.c
#$CC $C_FLAGS -o $obj/main/gui_gtk/vcrcomp_dialog.s $src/main/gui_gtk/vcrcomp_dialog.c

#echo Compiling Mupen64 GTK GUI...
#$CC $C_FLAGS -o $obj/main/gui_gtk/main_gtk.s $src/main/gui_gtk/main_gtk.c
#$CC $C_FLAGS -o $obj/main/gui_gtk/translate.s $src/main/gui_gtk/translate.c
#$CC $C_FLAGS -o $obj/main/gui_gtk/messagebox.s $src/main/gui_gtk/messagebox.c
#$CC $C_FLAGS -o $obj/main/gui_gtk/aboutdialog.s $src/main/gui_gtk/aboutdialog.c
#$CC $C_FLAGS -o $obj/main/gui_gtk/configdialog.s $src/main/gui_gtk/configdialog.c
#$CC $C_FLAGS -o $obj/main/gui_gtk/support.s $src/main/gui_gtk/support.c
#$CC $C_FLAGS -o $obj/main/gui_gtk/rombrowser.s $src/main/gui_gtk/rombrowser.c
#$CC $C_FLAGS -o $obj/main/gui_gtk/romproperties.s $src/main/gui_gtk/romproperties.c
#$CC $C_FLAGS -o $obj/main/gui_gtk/config.s $src/main/gui_gtk/config.c
#$CC $C_FLAGS -o $obj/main/gui_gtk/dirbrowser.s $src/main/gui_gtk/dirbrowser.c

echo Compiling Mupen64 GUI...
$CC $C_FLAGS -o $obj/main/win/configdialog.s $src/main/win/configdialog.c
$CC $C_FLAGS -o $obj/main/win/rombrowser.s $src/main/win/rombrowser.c
$CC $C_FLAGS -o $obj/main/win/config.s $src/main/win/config.c
$CC $C_FLAGS -o $obj/main/win/dumplist.s $src/main/win/dumplist.c
$CC $C_FLAGS -o $obj/main/win/timers.s $src/main/win/timers.c
$CC $C_FLAGS -o $obj/main/win/translation.s $src/main/win/translation.c
$CC $C_FLAGS -o $obj/main/win/inifunctions.s $src/main/win/inifunctions.c
$CC $C_FLAGS -o $obj/main/win/guifuncs.s $src/main/win/guifuncs.c
$CC $C_FLAGS -o $obj/main/win/RomSettings.s $src/main/win/RomSettings.c
$CC $C_FLAGS -o $obj/main/win/GUI_LogWindow.s $src/main/win/GUI_LogWindow.c
$CC $C_FLAGS -o $obj/main/win/kaillera.s $src/main/win/kaillera.c
$CC $C_FLAGS -o $obj/main/win/commandline.s $src/main/win/commandline.c
windres -i $src/winproject/mupen64_private.rc --input-format=rc -o $obj/mupen64_private.res -O coff
echo.

echo Assembling compiled sources...
$AS -o $obj/main/win/main_win.o $obj/main/win/main_win.s
$AS -o $obj/main/rom.o $obj/main/rom.s
$AS -o $obj/main/ioapi.o $obj/main/ioapi.s
$AS -o $obj/main/adler32.o $obj/main/adler32.s
$AS -o $obj/main/md5.o $obj/main/md5.s
$AS -o $obj/main/mupenIniApi.o $obj/main/mupenIniApi.s
$AS -o $obj/main/savestates.o $obj/main/savestates.s
$AS -o $obj/main/unzip.o $obj/main/unzip.s
$AS -o $obj/memory/memory.o $obj/memory/memory.s
$AS -o $obj/memory/pif.o $obj/memory/pif.s
$AS -o $obj/memory/dma.o $obj/memory/dma.s
$AS -o $obj/memory/tlb.o $obj/memory/tlb.s
$AS -o $obj/memory/flashram.o $obj/memory/flashram.s
$AS -o $obj/r4300/r4300.o $obj/r4300/r4300.s
$AS -o $obj/r4300/interupt.o $obj/r4300/interupt.s
$AS -o $obj/r4300/exception.o $obj/r4300/exception.s
$AS -o $obj/r4300/special.o $obj/r4300/special.s
$AS -o $obj/r4300/regimm.o $obj/r4300/regimm.s
$AS -o $obj/r4300/cop0.o $obj/r4300/cop0.s
$AS -o $obj/r4300/tlb.o $obj/r4300/tlb.s
$AS -o $obj/r4300/cop1.o $obj/r4300/cop1.s
$AS -o $obj/r4300/cop1_w.o $obj/r4300/cop1_w.s
$AS -o $obj/r4300/cop1_s.o $obj/r4300/cop1_s.s
$AS -o $obj/r4300/cop1_d.o $obj/r4300/cop1_d.s
$AS -o $obj/r4300/cop1_l.o $obj/r4300/cop1_l.s
$AS -o $obj/r4300/bc.o $obj/r4300/bc.s
$AS -o $obj/r4300/pure_interp.o $obj/r4300/pure_interp.s
$AS -o $obj/r4300/recomp.o $obj/r4300/recomp.s
$AS -o $obj/r4300/x86/gr4300.o $obj/r4300/x86/gr4300.s
$AS -o $obj/r4300/x86/assemble.o $obj/r4300/x86/assemble.s
$AS -o $obj/r4300/x86/gspecial.o $obj/r4300/x86/gspecial.s
$AS -o $obj/r4300/x86/gregimm.o $obj/r4300/x86/gregimm.s
$AS -o $obj/r4300/x86/gcop0.o $obj/r4300/x86/gcop0.s
$AS -o $obj/r4300/x86/gtlb.o $obj/r4300/x86/gtlb.s
$AS -o $obj/r4300/x86/gcop1.o $obj/r4300/x86/gcop1.s
$AS -o $obj/r4300/x86/gbc.o $obj/r4300/x86/gbc.s
$AS -o $obj/r4300/x86/gcop1_s.o $obj/r4300/x86/gcop1_s.s
$AS -o $obj/r4300/x86/gcop1_d.o $obj/r4300/x86/gcop1_d.s
$AS -o $obj/r4300/x86/gcop1_w.o $obj/r4300/x86/gcop1_w.s
$AS -o $obj/r4300/x86/gcop1_l.o $obj/r4300/x86/gcop1_l.s
$AS -o $obj/r4300/x86/rjump.o $obj/r4300/x86/rjump.s
$AS -o $obj/r4300/x86/debug.o $obj/r4300/x86/debug.s
$AS -o $obj/r4300/x86/regcache.o $obj/r4300/x86/regcache.s
$AS -o $obj/main/vcr.o $obj/main/vcr.s
$AS -o $obj/main/win/vcr_compress.o $obj/main/win/vcr_compress.s
$AS -o $obj/main/vcr_resample.o $obj/main/vcr_resample.s
$AS -o $obj/main/win/configdialog.o $obj/main/win/configdialog.s
$AS -o $obj/main/win/rombrowser.o $obj/main/win/rombrowser.s
$AS -o $obj/main/win/config.o $obj/main/win/config.s
$AS -o $obj/main/win/dumplist.o $obj/main/win/dumplist.s
$AS -o $obj/main/win/timers.o $obj/main/win/timers.s
$AS -o $obj/main/win/translation.o $obj/main/win/translation.s
$AS -o $obj/main/win/inifunctions.o $obj/main/win/inifunctions.s
$AS -o $obj/main/win/guifuncs.o $obj/main/win/guifuncs.s
$AS -o $obj/main/win/RomSettings.o $obj/main/win/RomSettings.s
$AS -o $obj/main/win/GUI_LogWindow.o $obj/main/win/GUI_LogWindow.s
$AS -o $obj/main/win/kaillera.o $obj/main/win/kaillera.s
$AS -o $obj/main/win/commandline.o $obj/main/win/commandline.s
echo.

OBJ_LIST="\
 $obj/main/rom.o \
 $obj/memory/memory.o \
 $obj/r4300/x86/debug.o \
 $obj/main/win/configdialog.o \
 $obj/r4300/r4300.o \
 $obj/main/unzip.o \
 $obj/r4300/interupt.o \
 $obj/memory/tlb.o \
 $obj/memory/dma.o \
 $obj/memory/pif.o \
 $obj/r4300/exception.o \
 $obj/r4300/recomp.o \
 $obj/r4300/pure_interp.o \
 $obj/r4300/x86/rjump.o \
 $obj/main/ioapi.o \
 $obj/r4300/x86/assemble.o \
 $obj/r4300/x86/gr4300.o \
 $obj/r4300/special.o \
 $obj/r4300/x86/gspecial.o \
 $obj/r4300/regimm.o \
 $obj/r4300/x86/gregimm.o \
 $obj/r4300/tlb.o \
 $obj/r4300/x86/gtlb.o \
 $obj/r4300/cop0.o \
 $obj/r4300/x86/gcop0.o \
 $obj/r4300/bc.o \
 $obj/r4300/x86/gbc.o \
 $obj/r4300/cop1_s.o \
 $obj/r4300/x86/gcop1_s.o \
 $obj/r4300/cop1_d.o \
 $obj/r4300/x86/gcop1_d.o \
 $obj/r4300/cop1_w.o \
 $obj/r4300/x86/gcop1_w.o \
 $obj/r4300/cop1_l.o \
 $obj/r4300/x86/gcop1_l.o \
 $obj/r4300/cop1.o \
 $obj/r4300/x86/gcop1.o \
 $obj/memory/flashram.o \
 $obj/main/md5.o \
 $obj/main/mupenIniApi.o \
 $obj/main/win/dumplist.o \
 $obj/main/win/rombrowser.o \
 $obj/main/win/timers.o \
 $obj/main/win/translation.o \
 $obj/main/win/main_win.o \
 $obj/main/win/inifunctions.o \
 $obj/main/savestates.o \
 $obj/main/win/Config.o \
 $obj/main/win/guifuncs.o \
 $obj/main/win/RomSettings.o \
 $obj/main/win/GUI_LogWindow.o \
 $obj/main/win/kaillera.o \
 $obj/main/win/commandline.o \
 $obj/main/vcr.o \
 $obj/r4300/x86/regcache.o \
 $obj/main/win/vcr_compress.o \
 $obj/main/vcr_resample.o \
 $obj/main/adler32.o \
 $obj/mupen64_private.res"

echo Linking assembled object files...
$CC -mwindows $OBJ_LIST -o $obj/mupen64 -s -lz -lcomctl32 -lwinmm -lvfw_avi32 -lvfw_ms32
