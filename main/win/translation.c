/***************************************************************************
                          translation.c  -  description
                             -------------------
    copyright            : (C) 2003 by ShadowPrince (shadow@emulation64.com)
    modifications        : linker (linker@mail.bg)
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include <windows.h>
#include <stdlib.h>
#include <dirent.h>
#include <stdio.h>
#define _WIN32_IE 0x0500
#include <commctrl.h>
#include "translation.h"
#include "../../winproject/resource.h"
#include "main_win.h"

static int LastLang = -1; 

typedef struct _languages  languages;
struct _languages
{
    char *file_name;
    char *language_name;
    languages *next;
};
static languages *lang_list = NULL, *current_lang = NULL;

void insert_lang( languages *p, char *file_name, char *language_name)
{
    while (p->next) 
        {
            p=p->next;
        }
        p->next = malloc(sizeof(languages));
        p->next->file_name = malloc(strlen(file_name)+1);
        strcpy( p->next->file_name, file_name);
        p->next->language_name = malloc(strlen(language_name)+7);
        strcpy( p->next->language_name, language_name);
        p->next->next=NULL;
        return;
}

void rewind_lang()
{
   current_lang = lang_list;
}

void search_languages()
{
    DIR *dir;
    char cwd[MAX_PATH];
    char name[MAX_PATH];
    struct dirent *entry;
    char String[800];
    
    lang_list = malloc( sizeof(languages));
    lang_list->next = NULL;
    
    sprintf(cwd, "%slang",AppPath);
    
    dir = opendir(cwd);
    if (dir==NULL)  { 
        return;
    }
    while((entry = readdir(dir)) != NULL)
    {
              
        strcpy(name, cwd);
        strcat(name, "\\");
        strcat(name, entry->d_name);
        if (getExtension(entry->d_name) != NULL && strcmp(getExtension(entry->d_name),"lng")==0) 
        {
             memset(String,0,sizeof(String));
             GetPrivateProfileSectionNames( String, sizeof(String), name);
             if ( String) 
             {
                insert_lang( lang_list, name, String );
             }                     
        }
    }
}

void SetCurrentLangByName(char *language_name)
{
    languages *p;
	p = lang_list->next;
	while(p)
	{
	    if ( strcmp(p->language_name, language_name)==0) {
             current_lang = p;
             return;
        }	
        p=p->next;
    } 
}

void SelectLang(HWND hWnd, int LangMenuID) {
	char String[800];
	HMENU hMenu = GetMenu(hWnd);
	MENUITEMINFO menuinfo;
	menuinfo.cbSize = sizeof(MENUITEMINFO);
	menuinfo.fMask = MIIM_TYPE;
	menuinfo.fType = MFT_STRING;
	menuinfo.dwTypeData = String;
	menuinfo.cch = sizeof(String);
	GetMenuItemInfo(hMenu,LangMenuID,FALSE,&menuinfo);

	sprintf(Config.DefaultLanguage,String);
    //WritePrivateProfileString("Default","Language",String,LngFilePath());
	if (LastLang != -1) {
		CheckMenuItem( hMenu, LastLang, MF_BYCOMMAND | MFS_UNCHECKED );
	}
	LastLang = LangMenuID;
	CheckMenuItem( hMenu, LastLang, MF_BYCOMMAND | MFS_CHECKED );
	SetCurrentLangByName( Config.DefaultLanguage);
}

void SetupLanguages( HWND hWnd )
{
    char String[800];
    HMENU hMenu = GetMenu(hWnd), hSubMenu;
	MENUITEMINFO menuinfo;
	int count;
	count = 1;
	languages *p;
	search_languages();
	p = lang_list->next;
	hSubMenu = GetSubMenu(hMenu,0);
	hSubMenu = GetSubMenu(hSubMenu,6);
	menuinfo.cbSize = sizeof(MENUITEMINFO);
	menuinfo.fMask = MIIM_TYPE|MIIM_ID;
	menuinfo.fType = MFT_STRING;
	menuinfo.fState = MFS_ENABLED;
	menuinfo.dwTypeData = String;
	menuinfo.cch = sizeof(hSubMenu);
	while ( p ) 
    {
		if (strcmp(p->language_name,"English") == 0) { 
		    if (strcmp(Config.DefaultLanguage, "English") == 0) {
		  		    CheckMenuItem(hSubMenu, ID_LANG_ENGLISH, MF_BYCOMMAND | MFS_CHECKED );
		            LastLang = ID_LANG_ENGLISH;
		            current_lang = p;
		        }
        }
        else {
		        menuinfo.dwTypeData = p->language_name;
		        menuinfo.cch = strlen(p->language_name) + 1;
		        menuinfo.wID = ID_LANG_ENGLISH + count;
		        InsertMenuItem(hSubMenu, count++, TRUE, &menuinfo);
		        if (strcmp(Config.DefaultLanguage, p->language_name) == 0) {
		              CheckMenuItem(hSubMenu, menuinfo.wID, MF_BYCOMMAND | MFS_CHECKED );
		              LastLang = menuinfo.wID;
		              current_lang = p;
		        }
       }
          p = p->next ;
     }
     SetCurrentLangByName( Config.DefaultLanguage);  
}

void freeLanguages()
{
    languages *p,*temp;
    p=lang_list;
    while(p)
    {
       temp = p->next;
       free( p);
       p=temp;
    }
}

void Translate(char* GuiWord,char* Ret)
{
   TranslateDefault( GuiWord, GuiWord, Ret);
}

void TranslateDefault(char* GuiWord,char *Default,char* Ret)
{
   if (current_lang) {
      GetPrivateProfileString(current_lang->language_name,GuiWord,Default,Ret,200,current_lang->file_name); 
   }
   else {
      sprintf( Ret, GuiWord) ;
   }
}

void SetItemTranslatedString(HWND hwnd,int ElementID,char* Str)
{
    char String[800];
    Translate(Str,String);  
    SetDlgItemText( hwnd, ElementID, String );
}

void SetItemTranslatedStringDefault(HWND hwnd,int ElementID,char* Str,char*Def)
{
    char String[800];
    TranslateDefault(Str,Def,String);
    SetDlgItemText( hwnd, ElementID, String );
}


void SetStatusTranslatedString(HWND hStatus,int section,char* Str)
{
    char String[800];
    Translate(Str,String);  
    if (section == 0) strcpy( statusmsg, String );
    SendMessage( hStatus, SB_SETTEXT, section, (LPARAM)String ); 
}

void SetMenuTranslatedString(HMENU hMenu,int elementID,char* Str,char* Acc)
{
    char String[800];
    MENUITEMINFO menuinfo;
    Translate(Str,String);
    if (strcmp(Acc,"")) sprintf(String, "%s   \t%s", String, Acc);
            
    memset(&menuinfo, 0, sizeof(MENUITEMINFO));
    menuinfo.cbSize = sizeof(MENUITEMINFO);
    menuinfo.fMask = MIIM_TYPE;
    menuinfo.fType = MFT_STRING;
    menuinfo.dwTypeData = String;
    menuinfo.cch = sizeof(String);
    SetMenuItemInfo(hMenu,elementID,TRUE,&menuinfo);
}

void TranslateMenu(HMENU hMenu,HWND mainHWND)
{
    HMENU submenu,subsubmenu;
    //Main menu
    SetMenuTranslatedString(hMenu,0,"File","");
    SetMenuTranslatedString(hMenu,1,"Run","");
    SetMenuTranslatedString(hMenu,2,"Options","");
    SetMenuTranslatedString(hMenu,3,"Utilities","");
    SetMenuTranslatedString(hMenu,4,"Help","");
    
    //File menu
    submenu = GetSubMenu(hMenu,0) ;
    SetMenuTranslatedString(submenu,0,"Load ROM...","Ctrl+O");
    SetMenuTranslatedString(submenu,1,"Close ROM","F4");
    SetMenuTranslatedString(submenu,2,"Refresh ROM List","Ctrl+R");
    SetMenuTranslatedString(submenu,4,"Recent ROMs","");
    subsubmenu = GetSubMenu(submenu,4) ;
    SetMenuTranslatedString(subsubmenu,0,"Reset","");
    SetMenuTranslatedString(subsubmenu,1,"Freeze","");
    
    SetMenuTranslatedString(submenu,6,"Language","");
    SetMenuTranslatedString(submenu,7,"Language Information...","");
    SetMenuTranslatedString(submenu,9,"Exit","");

    
    //Run menu
    submenu = GetSubMenu(hMenu,1);
    //SetMenuTranslatedString(submenu,0,"Reset","F1");
    SetMenuTranslatedString(submenu,0,"Pause","F2");
    SetMenuTranslatedString(submenu,1,"Generate Bitmap","F3");
    SetMenuTranslatedString(submenu,3,"Save State","F5");
    SetMenuTranslatedString(submenu,4,"Save As...","Ctrl+A");
    SetMenuTranslatedString(submenu,5,"Load State","F7");
    SetMenuTranslatedString(submenu,6,"Load As...","Ctrl+L");
    SetMenuTranslatedString(submenu,8,"Current Save State","");
    
    //Options menu
    submenu = GetSubMenu(hMenu,2);
    SetMenuTranslatedString(submenu,0,"Full Screen","Alt+Enter");
    SetMenuTranslatedString(submenu,2,"Video Settings...","");
    SetMenuTranslatedString(submenu,3,"Input Settings...","");
    SetMenuTranslatedString(submenu,4,"Audio Settings...","");
    SetMenuTranslatedString(submenu,5,"RSP Settings...","");
    SetMenuTranslatedString(submenu,7 ,"Show Toolbar","Alt+T");
    SetMenuTranslatedString(submenu,8 ,"Show Statusbar","Alt+S");
    SetMenuTranslatedString(submenu,10 ,"Settings...","Ctrl+S");

    //Utility menu
    submenu = GetSubMenu(hMenu,3);
    SetMenuTranslatedString(submenu,0,"ROM Properties...","Ctrl+P");
    SetMenuTranslatedString(submenu,2,"Audit ROMs...","");
    //SetMenuTranslatedString(submenu,3,"Benchmark...","");
    SetMenuTranslatedString(submenu,3,"Generate ROM Info...","");
    SetMenuTranslatedString(submenu,4,"Show Log Window","");
    //SetMenuTranslatedString(submenu,5,"Kaillera...","");
    SetMenuTranslatedString(submenu,6,"Record","");
    subsubmenu = GetSubMenu(submenu,6);
    SetMenuTranslatedString(subsubmenu,0,"Start Recording...","F8");
    SetMenuTranslatedString(subsubmenu,1,"Stop Recording","Ctrl+F8");
    SetMenuTranslatedString(subsubmenu,2,"Start Playback...","F9");
    SetMenuTranslatedString(subsubmenu,3,"Stop Playback","Ctrl+F9");
    SetMenuTranslatedString(subsubmenu,5,"Start Capture (REC2AVI)...","F10");
    SetMenuTranslatedString(subsubmenu,6,"Stop Capture","Ctrl+F10");
            
    //Help menu
    submenu = GetSubMenu(hMenu,4);
    SetMenuTranslatedString(submenu,0,"Contents...","");
    SetMenuTranslatedString(submenu,1,"Whats new...","");
    SetMenuTranslatedString(submenu,3,"About...","");
    DrawMenuBar(mainHWND);
}

void TranslateConfigDialog(HWND hwnd)
{
       
    SetItemTranslatedString(hwnd,IDC_GFXPLUGIN,"Video Plugin");
    SetItemTranslatedString(hwnd,IDGFXCONFIG,"Config");
    SetItemTranslatedString(hwnd,IDGFXTEST,"Test");
    SetItemTranslatedString(hwnd,IDGFXABOUT,"Plugin About");
    
    SetItemTranslatedString(hwnd,IDC_INPUTPLUGIN,"Input Plugin");
    SetItemTranslatedString(hwnd,IDINPUTCONFIG,"Config");
    SetItemTranslatedString(hwnd,IDINPUTTEST,"Test");
    SetItemTranslatedString(hwnd,IDINPUTABOUT,"Plugin About");
    
    SetItemTranslatedString(hwnd,IDC_SOUNDPLUGIN,"Sound Plugin");
    SetItemTranslatedString(hwnd,IDSOUNDCONFIG,"Config");
    SetItemTranslatedString(hwnd,IDSOUNDTEST,"Test");
    SetItemTranslatedString(hwnd,IDSOUNDABOUT,"Plugin About");
    
    SetItemTranslatedString(hwnd,IDC_RSPPLUGIN,"RSP Plugin");
    SetItemTranslatedString(hwnd,IDRSPCONFIG,"Config");
    SetItemTranslatedString(hwnd,IDRSPTEST,"Test");
    SetItemTranslatedString(hwnd,IDRSPABOUT,"Plugin About");
  
}

void TranslateDirectoriesConfig(HWND hwnd)
{
    SetItemTranslatedString(hwnd,IDC_ROMS_DIRECTORIES,"ROMs Directories");
    SetItemTranslatedString(hwnd,IDC_RECURSION,"Use directory recursion");
    SetItemTranslatedString(hwnd,IDC_ADD_BROWSER_DIR,"Add");
    SetItemTranslatedString(hwnd,IDC_REMOVE_BROWSER_DIR,"Remove");
    SetItemTranslatedString(hwnd,IDC_REMOVE_BROWSER_ALL,"Remove All");
    
    SetItemTranslatedString(hwnd,IDC_PLUGINS_GROUP,"Plugins Directory");
    //SetItemTranslatedString(hwnd,IDC_DEFAULT_PLUGINS_CHECK,"Default Plugins Check");
    SetItemTranslatedString(hwnd,IDC_CHOOSE_PLUGINS_DIR, "Choose" );
        
    SetItemTranslatedString(hwnd,IDC_SAVES_GROUP,"Saves Directory");
    //SetItemTranslatedString(hwnd,IDC_DEFAULT_SAVES_CHECK,"Default Saves Check");
    SetItemTranslatedString(hwnd,IDC_CHOOSE_SAVES_DIR,"Choose");
     
    SetItemTranslatedString(hwnd,IDC_SCREENSHOTS_GROUP,"Screenshots Directory");
    //SetItemTranslatedString(hwnd,IDC_DEFAULT_SCREENSHOTS_CHECK,"Default Screenshots Check");
    SetItemTranslatedString(hwnd,IDC_CHOOSE_SCREENSHOTS_DIR,"Choose");
}

void TranslateGeneralDialog(HWND hwnd)
{
    SetItemTranslatedString(hwnd,IDC_MESSAGES,"Alerts");
    SetItemTranslatedString(hwnd,IDC_ALERTBADROM,"Alert Bad ROM");
    SetItemTranslatedString(hwnd,IDC_ALERTHACKEDROM,"Alert Hacked ROM");
    SetItemTranslatedString(hwnd,IDC_ALERTSAVESERRORS,"Alert Saves errors");

    SetItemTranslatedString(hwnd,IDC_FPSTITLE,"Fps / VIs");

    SetItemTranslatedString(hwnd,IDC_LIMITFPS,"Limit fps (auto)");
    SetItemTranslatedString(hwnd,IDC_SPEEDMODIFIER,"Use Speed Modifier");
    SetItemTranslatedString(hwnd,IDC_SHOWFPS,"Show FPS");
    SetItemTranslatedString(hwnd,IDC_SHOWVIS,"Show VIs");
    
    SetItemTranslatedString(hwnd,IDC_INTERP,"Interpreter");
    SetItemTranslatedString(hwnd,IDC_RECOMP,"Dynamic Recompiler");
    SetItemTranslatedString(hwnd,IDC_PURE_INTERP,"Pure Interpreter");
    SetItemTranslatedString(hwnd,IDC_CPUCORE,"CPU Core");
    SetItemTranslatedString(hwnd,IDC_INIFILE,"Ini File");
    SetItemTranslatedString(hwnd,IDC_INI_COMPRESSED,"Use compressed file");
    
}

void TranslateRomInfoDialog(HWND hwnd)
{
    char tmp[200];
    SetItemTranslatedStringDefault(hwnd,IDC_ROM_HEADER_INFO_TEXT,"RP ROM Information","ROM Information:");
    SetItemTranslatedStringDefault(hwnd,IDC_ROM_FULLPATH_TEXT,"RP File Location","File Location:");
    SetItemTranslatedStringDefault(hwnd,IDC_ROM_GOODNAME_TEXT,"RP Good Name","Good Name:");
    SetItemTranslatedStringDefault(hwnd,IDC_ROM_INTERNAL_NAME_TEXT,"RP Internal Name","Internal Name:");
    SetItemTranslatedStringDefault(hwnd,IDC_ROM_SIZE_TEXT,"RP Size","Size:");
    SetItemTranslatedStringDefault(hwnd,IDC_ROM_COUNTRY_TEXT,"RP Country","Country:");
    SetItemTranslatedStringDefault(hwnd,IDC_ROM_INICODE_TEXT,"RP Ini Code","Ini Code:");
    SetItemTranslatedStringDefault(hwnd,IDC_ROM_MD5_TEXT,"RP MD5 Checksum","MD5 Checksum:");
    SetItemTranslatedStringDefault(hwnd,IDC_MD5_CALCULATE,"RP Calculate","Calculate");

    SetItemTranslatedStringDefault(hwnd,IDC_ROM_PLUGINS,"RP Plugins","Plugins:");
    SetItemTranslatedStringDefault(hwnd,IDC_GFXPLUGIN,"RP Video Plugin","Video  Plugin:");
    SetItemTranslatedStringDefault(hwnd,IDC_SOUNDPLUGIN,"RP Sound Plugin","Sound Plugin:");
    SetItemTranslatedStringDefault(hwnd,IDC_INPUTPLUGIN,"RP Input Plugin","Input Plugin:");
    SetItemTranslatedStringDefault(hwnd,IDC_RSPPLUGIN,"RP RSP Plugin","RSP Plugin:");
    SetItemTranslatedStringDefault(hwnd,IDC_SAVE_PROFILE,"RP Save Plugins","Save Plugins");
    
    SetItemTranslatedStringDefault(hwnd,IDC_INI_COMMENTS_TEXT,"RP Comments","Comments:");

    SetItemTranslatedString(hwnd,IDC_OK,"Ok");
    SetItemTranslatedString(hwnd,IDC_CANCEL,"Cancel");
    TranslateDefault("ROM Properties","ROM Properties",tmp);
    SetWindowText(hwnd,tmp);
}

void TranslateRomBrowserMenu(HMENU hMenu)
{
    SetMenuTranslatedString(hMenu,0,"Play Game","Enter");
    SetMenuTranslatedString(hMenu,1,"ROM Properties...","Ctrl+P");
    SetMenuTranslatedString(hMenu,3,"Refresh ROM List","Ctrl+R");
}

void TranslateAuditDialog(HWND hwnd)
{
    char tmp[200];
    SetItemTranslatedString(hwnd,IDC_TOTAL_ROMS_TEXT,"Audit Total ROMs");
    SetItemTranslatedString(hwnd,IDC_CURRENT_ROM_TEXT,"Audit Current ROM");
    SetItemTranslatedString(hwnd,IDC_ROM_FULLPATH_TEXT,"Audit File Location");
    SetItemTranslatedString(hwnd,IDC_START,"Start");
    SetItemTranslatedString(hwnd,IDC_STOP,"Stop");
    SetItemTranslatedString(hwnd,IDC_CLOSE,"Close");
    TranslateDefault("Audit ROMs","Audit ROMs",tmp);
    SetWindowText(hwnd,tmp);
}

void TranslateLangInfoDialog( HWND hwnd )
{
    char tmp[200];
    SetItemTranslatedString(hwnd,IDC_LANG_AUTHOR_TEXT,"Translation Author TEXT");
    SetItemTranslatedString(hwnd,IDC_LANG_VERSION_TEXT,"Version TEXT");
    SetItemTranslatedString(hwnd,IDC_LANG_DATE_TEXT,"Creation Date TEXT");
    SetItemTranslatedString(hwnd,IDC_LANG_AUTHOR,"Translation Author");
    SetItemTranslatedString(hwnd,IDC_LANG_VERSION,"Version");
    SetItemTranslatedString(hwnd,IDC_LANG_DATE,"Creation Date");
    SetItemTranslatedString(hwnd,IDOK, "Ok");
    TranslateDefault("Language Information Dialog","Language Information",tmp);
    SetWindowText(hwnd,tmp);
}

void TranslateAdvancedDialog(HWND hwnd) 
{
    SetItemTranslatedString(hwnd,IDC_COMMON,"Common Options");
    SetItemTranslatedString(hwnd,IDC_STARTFULLSCREEN,"Start game in full screen");
    SetItemTranslatedString(hwnd,IDC_PAUSENOTACTIVE,"Pause when not active");
    SetItemTranslatedString(hwnd,IDC_PLUGIN_OVERWRITE,"Use global plugins settings");
    SetItemTranslatedString(hwnd,IDC_GUI_TOOLBAR,"Show toolbar");
    SetItemTranslatedString(hwnd,IDC_GUI_STATUSBAR,"Show statusbar");
        
    SetItemTranslatedString(hwnd,IDC_COMPATIBILITY,"Compatibility Options");
    SetItemTranslatedString(hwnd,IDC_NO_AUDIO_DELAY,"No audio delay");
    SetItemTranslatedString(hwnd,IDC_NO_COMPILED_JUMP,"No compiled jump");
        
    SetItemTranslatedString(hwnd,IDC_ROMBROWSERCOLUMNS,"Rombrowser Columns");
    SetItemTranslatedString(hwnd,IDC_COLUMN_GOODNAME,"GoodName");
    SetItemTranslatedString(hwnd,IDC_COLUMN_INTERNALNAME,"Internal Name");
    SetItemTranslatedString(hwnd,IDC_COLUMN_COUNTRY,"Country");
    SetItemTranslatedString(hwnd,IDC_COLUMN_SIZE,"ROM size");
    SetItemTranslatedString(hwnd,IDC_COLUMN_COMMENTS,"Comments");
    SetItemTranslatedString(hwnd,IDC_COLUMN_FILENAME,"File Name");
    SetItemTranslatedString(hwnd,IDC_COLUMN_MD5,"MD5");
         
}

