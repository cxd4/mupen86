/**
 * Mupen64 - plugin.h
 * Copyright (C) 2002 Hacktarux
 *
 * Mupen64 homepage: http://mupen64.emulation64.com
 * email address: hacktarux@yahoo.fr
 * 
 * If you want to contribute to the project please contact
 * me first (maybe someone is already making what you are
 * planning to do).
 *
 *
 * This program is free software; you can redistribute it and/
 * or modify it under the terms of the GNU General Public Li-
 * cence as published by the Free Software Foundation; either
 * version 2 of the Licence, or any later version.
 *
 * This program is distributed in the hope that it will be use-
 * ful, but WITHOUT ANY WARRANTY; without even the implied war-
 * ranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public Licence for more details.
 *
 * You should have received a copy of the GNU General Public
 * Licence along with this program; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139,
 * USA.
 *
**/

#ifndef PLUGIN_H
#define PLUGIN_H

void  plugin_scan_directory(const char *directory);
void  plugin_load_plugins(const char *gfx_name, 
			  const char *audio_name, 
			  const char *input_name,
			  const char *RSP_name);
char *plugin_next();
int   plugin_type();
void  plugin_rewind();
char *plugin_filename_by_name(const char *name);
char *plugin_name_by_filename(const char *filename);

void  plugin_exec_config(const char *name);
void  plugin_exec_test(const char *name);
void  plugin_exec_about(const char *name);

/* Plugin types */
#define PLUGIN_TYPE_RSP			1
#define PLUGIN_TYPE_GFX			2
#define PLUGIN_TYPE_AUDIO               3
#define PLUGIN_TYPE_CONTROLLER          4

/*** Controller plugin's ****/
#define PLUGIN_NONE                             1
#define PLUGIN_MEMPAK                           2
#define PLUGIN_RUMBLE_PAK			3 /* not implemeted for non raw data */
#define PLUGIN_TANSFER_PAK			4 /* not implemeted for non raw data */
#define PLUGIN_RAW				5 /* the controller plugin is passed in raw data */

/*** Audio plugin system types ***/
#define SYSTEM_NTSC					0
#define SYSTEM_PAL					1
#define SYSTEM_MPAL					2

#include "../memory/memory.h"

/***** Structures *****/
typedef struct {
	u16 Version;
	u16 Type;
	char Name[100];       /* Name of the DLL */

	/* If DLL supports memory these memory options then set them to TRUE or FALSE
	   if it does not support it */
	Boolean NormalMemory;    /* a normal BYTE array */ 
	Boolean MemoryBswaped;   /* a normal BYTE array where the memory has been pre
	                         bswap on a dword (32 bits) boundry */
} PLUGIN_INFO;

typedef struct {
	HINSTANCE hInst;
	Boolean MemoryBswaped;    /* If this is set to TRUE, then the memory has been pre
	                          bswap on a dword (32 bits) boundry */
	u8 * RDRAM;
	u8 * DMEM;
	u8 * IMEM;

	u32 * MI_INTR_REG;

	u32 * SP_MEM_ADDR_REG;
	u32 * SP_DRAM_ADDR_REG;
	u32 * SP_RD_LEN_REG;
	u32 * SP_WR_LEN_REG;
	u32 * SP_STATUS_REG;
	u32 * SP_DMA_FULL_REG;
	u32 * SP_DMA_BUSY_REG;
	u32 * SP_PC_REG;
	u32 * SP_SEMAPHORE_REG;

	u32 * DPC_START_REG;
	u32 * DPC_END_REG;
	u32 * DPC_CURRENT_REG;
	u32 * DPC_STATUS_REG;
	u32 * DPC_CLOCK_REG;
	u32 * DPC_BUFBUSY_REG;
	u32 * DPC_PIPEBUSY_REG;
	u32 * DPC_TMEM_REG;

	void (*CheckInterrupts)( void );
	void (*ProcessDlistList)( void );
	void (*ProcessAlistList)( void );
	void (*ProcessRdpList)( void );
	void (*ShowCFB)( void );
} RSP_INFO;

typedef struct {
	HWND hWnd;	       /* Render window */
	HWND hStatusBar;       /* if render window does not have a status bar then this is NULL */

	Boolean MemoryBswaped; /* If this is set to TRUE, then the memory has been pre-
	                        *   bswap on a dword (32 bits) boundary.
			   	* e.g., the first 8 bytes are stored like this:
	                        *        4 3 2 1   8 7 6 5 */

	u8 * HEADER;	       /* This is the rom header (first 40h bytes of the rom). */
			       /* This will be in the same memory format as the rest of the memory. */
	u8 * RDRAM;
	u8 * DMEM;
	u8 * IMEM;

	u32 * MI_INTR_REG;

	u32 * DPC_START_REG;
	u32 * DPC_END_REG;
	u32 * DPC_CURRENT_REG;
	u32 * DPC_STATUS_REG;
	u32 * DPC_CLOCK_REG;
	u32 * DPC_BUFBUSY_REG;
	u32 * DPC_PIPEBUSY_REG;
	u32 * DPC_TMEM_REG;

	u32 * VI_STATUS_REG;
	u32 * VI_ORIGIN_REG;
	u32 * VI_WIDTH_REG;
	u32 * VI_INTR_REG;
	u32 * VI_V_CURRENT_LINE_REG;
	u32 * VI_TIMING_REG;
	u32 * VI_V_SYNC_REG;
	u32 * VI_H_SYNC_REG;
	u32 * VI_LEAP_REG;
	u32 * VI_H_START_REG;
	u32 * VI_V_START_REG;
	u32 * VI_V_BURST_REG;
	u32 * VI_X_SCALE_REG;
	u32 * VI_Y_SCALE_REG;

	void (*CheckInterrupts)( void );
} GFX_INFO;

typedef struct {
	HWND hwnd;
	HINSTANCE hinst;

	Boolean MemoryBswaped; /* If this is set to TRUE, then the memory has been pre-
	                        *   bswap on a dword (32 bits) boundary.
				* e.g., the first 8 bytes are stored like this:
	                        *        4 3 2 1   8 7 6 5 */
	u8 * HEADER;	/* This is the rom header (first 40h bytes of the rom */
				/* This will be in the same memory format as the rest of the memory. */
	u8 * RDRAM;
	u8 * DMEM;
	u8 * IMEM;

	u32 * MI_INTR_REG;

	u32 * AI_DRAM_ADDR_REG;
	u32 * AI_LEN_REG;
	u32 * AI_CONTROL_REG;
	u32 * AI_STATUS_REG;
	u32 * AI_DACRATE_REG;
	u32 * AI_BITRATE_REG;

	void (*CheckInterrupts)( void );
} AUDIO_INFO;

typedef struct {
	Boolean Present;
	Boolean RawData;
	int  Plugin;
} CONTROL;

typedef union {
	u32 Value;
	struct {
		unsigned R_DPAD       : 1;
		unsigned L_DPAD       : 1;
		unsigned D_DPAD       : 1;
		unsigned U_DPAD       : 1;
		unsigned START_BUTTON : 1;
		unsigned Z_TRIG       : 1;
		unsigned B_BUTTON     : 1;
		unsigned A_BUTTON     : 1;

		unsigned R_CBUTTON    : 1;
		unsigned L_CBUTTON    : 1;
		unsigned D_CBUTTON    : 1;
		unsigned U_CBUTTON    : 1;
		unsigned R_TRIG       : 1;
		unsigned L_TRIG       : 1;
		unsigned Reserved1    : 1;
		unsigned Reserved2    : 1;

		signed   Y_AXIS       : 8;

		signed   X_AXIS       : 8;
	};
} BUTTONS;

typedef struct {
	HWND hMainWindow;
	HINSTANCE hinst;

	Boolean MemoryBswaped;		/* If this is set to TRUE, then the memory has been pre-
					 *   bswap on a dword (32 bits) boundary, only effects header.
					 * e.g., the first 8 bytes are stored like this:
					 *        4 3 2 1   8 7 6 5 */
	u8 * HEADER;			/* This is the rom header (first 40h bytes of the rom). */
	CONTROL *Controls;		/* A pointer to an array of 4 controllers .. e.g.:
					 * CONTROL Controls[4]; */
} CONTROL_INFO;

extern CONTROL Controls[4];

extern void (*getDllInfo)(PLUGIN_INFO *PluginInfo);
extern void (*dllConfig)(HWND hParent);
extern void (*dllTest)(HWND hParent);
extern void (*dllAbout)(HWND hParent);

extern void (*changeWindow)();
extern void (*closeDLL_gfx)();
extern Boolean (*initiateGFX)(GFX_INFO Gfx_Info);
extern void (*processDList)();
extern void (*processRDPList)();
extern void (*romClosed_gfx)();
extern void (*romOpen_gfx)();
extern void (*showCFB)();
extern void (*updateScreen)();
extern void (*viStatusChanged)();
extern void (*viWidthChanged)();
extern void (*readScreen)(void **dest, long *width, long *height);

extern void (*aiDacrateChanged)(int SystemType);
extern void (*aiLenChanged)();
extern u32 (*aiReadLength)();
#if 0
extern void (*aiUpdate)(Boolean Wait);
#endif
extern void (*closeDLL_audio)();
extern Boolean (*initiateAudio)(AUDIO_INFO Audio_Info);
extern void (*processAList)();
extern void (*romClosed_audio)();
extern void (*romOpen_audio)();

extern void (*closeDLL_input)();
extern void (*controllerCommand)(int Control, u8 * Command);
extern void (*getKeys)(int Control, BUTTONS *Keys);
extern void (*initiateControllers)(CONTROL_INFO ControlInfo);
extern void (*readController)(int Control, u8 *Command);
extern void (*romClosed_input)();
extern void (*romOpen_input)();
extern void (*keyDown)(WPARAM wParam, LPARAM lParam);
extern void (*keyUp)(WPARAM wParam, LPARAM lParam);

extern void (*closeDLL_RSP)();
extern u32 (*doRspCycles)(u32 Cycles);
extern void (*initiateRSP)(RSP_INFO Rsp_Info, u32 * CycleCount);
extern void (*romClosed_RSP)();

/* frame buffer plugin spec extension */

typedef struct {
    u32 addr;
    u32 size;
    u32 width;
    u32 height;
} FrameBufferInfo;

extern void (*fBRead)(u32 addr);
extern void (*fBWrite)(u32 addr, u32 size);
extern void (*fBGetFrameBufferInfo)(void *p);

#endif
