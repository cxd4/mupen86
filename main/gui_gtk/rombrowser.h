/***************************************************************************
                          rombrowser.h  -  description
                             -------------------
    begin                : Sat Nov 9 2002
    copyright            : (C) 2002 by blight
    email                : blight@Ashitaka
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#ifndef __ROMBROWSER_H__
#define __ROMBROWSER_H__

#include <gtk/gtk.h>

#include "../mupenIniApi.h"

int create_romBrowser( void );
void rombrowser_refresh( void );

/* cache */
void rombrowser_readCache( void );
void rombrowser_writeCache( void );

/** global rom list */
typedef struct {
    char cFilename[PATH_MAX];

    char cName[100];
    char cSize[20];
    char cCountry[20];

    /* ROM info */
    struct {
        char          cName[21];		/* ROM name */
        int           iSize;			/* size in bytes */
        short         sCartID;			/* cartridge ID */
        int           iManufacturer;		/* manufacturer */
        unsigned char cCountry;			/* country ID */
        unsigned int  iCRC1;			/* CRC part 1 */
        unsigned int  iCRC2;			/* CRC part 2 */
        char          cMD5[33];			/* MD5 code */
        char          cGoodName[100];		/* from INI */
        char          cComments[200];		/* from INI */

#if 0
        char     Status[60];                    /* from INI */
        char     FileName[200];
        char     PluginNotes[250];              /* from INI */
        char     CoreNotes[250];                /* from INI */
        char     UserNotes[250];                /* from INI */
        char     Developer[30];                 /* from INI */
        char     ReleaseDate[30];               /* from INI */
        char     Genre[15];                     /* from INI */
#endif
    } info;	/* data saved in cache */

    /* other data */
    GtkWidget  *flag;                   /* flag GtkPixmap */
    mupenEntry *iniEntry;               /* INI entry of this ROM */
} SRomEntry;
extern GList *g_RomList;

#endif /* __ROMBROWSER_H__ */
