/**
 * Mupen64 - rom.h
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

#ifndef ROM_H
#define ROM_H

#include "winlnxdefs.h"

int rom_read(const char *argv);
int fill_header(const char *argv);
void calculateMD5(const char *argv, u8 digest[16]);

extern u8 *rom;
extern int taille_rom;

typedef struct _rom_header
{
   u8 init_PI_BSB_DOM1_LAT_REG;
   u8 init_PI_BSB_DOM1_PGS_REG;
   u8 init_PI_BSB_DOM1_PWD_REG;
   u8 init_PI_BSB_DOM1_PGS_REG2;

   u32 ClockRate;
   u32 PC;
   u32 Release;
   u32 CRC1;
   u32 CRC2;

   u32 Unknown[2];
   u8 nom[20];
   u32 unknown;

   u32 Manufacturer_ID;
   u16 Cartridge_ID;
   u16 Country_code;

   u32 Boot_Code[1008];
} rom_header;
extern rom_header *ROM_HEADER;

typedef struct _rom_settings
{
   char goodname[256];
   int eeprom_16kb;
   char MD5[33];
} rom_settings;
extern rom_settings ROM_SETTINGS;

#endif
