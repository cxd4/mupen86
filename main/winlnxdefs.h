/**
 * Mupen64 - winlnxdefs.h
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

#ifndef WINLNXDEFS_H
#define WINLNXDEFS_H

/* cxd4 -- To do--possibly delete tihs to replace with the below? */
#include "../memory/memory.h"

#include <stddef.h>
#undef ssize_t

#ifdef _WIN64
typedef s64 ssize_t;
#elif defined(_WIN32)
typedef signed long ssize_t;
#else
#include <stdio.h>
#endif

#ifndef _WIN32

typedef void* HINSTANCE;
typedef void* HWND;
typedef size_t WPARAM;
typedef ssize_t LPARAM;

#define __declspec(dllexport)
#define _cdecl
#define __stdcall
#define WINAPI

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#endif

typedef int Boolean;

/* for compatibility with MSVC */
#if defined(_MSC_VER)
#define inline __inline
#endif

#endif
