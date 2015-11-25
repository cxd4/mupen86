/***************************************************************************
                          configdialog.c  -  description
                             -------------------
    copyright            : (C) 2003 by ShadowPrince
    email                : shadow@emulation64.com
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
#include <shlobj.h>
#include <stdio.h>
#include "main_win.h"
#include "../../winproject/resource.h"
#include "configdialog.h"
#include "../plugin.h"
#include "rombrowser.h"
#include "../guifuncs.h"
#include "../md5.h"
#include "timers.h"
#include "translation.h"
#include "Config.h"
#include "../rom.h"
#include "inifunctions.h"


HWND romInfoHWND;
static DWORD dwExitCode;
static DWORD Id;
BOOL stopScan = FALSE;
HWND WINAPI CreateTrackbar( HWND hwndDlg, UINT iMin, UINT iMax,  UINT iSelMin, UINT iSelMax);
HWND hwndTrack ; 

extern int no_audio_delay;
extern int no_compiled_jump;

void WriteCheckBoxValue( HWND hwnd, int resourceID , int value)
{
    if  (value) {
                  SendMessage(GetDlgItem(hwnd,resourceID),BM_SETCHECK, BST_CHECKED,0);
                }
}

int ReadCheckBoxValue( HWND hwnd, int resourceID)
{
    return SendDlgItemMessage(hwnd,resourceID,BM_GETCHECK , 0,0) == BST_CHECKED?TRUE:FALSE;
}

void WriteComboBoxValue(HWND hwnd,int ResourceID,char *PrimaryVal,char *DefaultVal)
{
     int index;
     index = SendDlgItemMessage(hwnd, ResourceID, CB_FINDSTRINGEXACT, 0, (LPARAM)PrimaryVal);
     if (index!=CB_ERR) {
                SendDlgItemMessage(hwnd, ResourceID, CB_SETCURSEL, index, 0);
                return;
     }
     index = SendDlgItemMessage(hwnd, ResourceID, CB_FINDSTRINGEXACT, 0, (LPARAM)DefaultVal);
     if (index!=CB_ERR) { 
                SendDlgItemMessage(hwnd, ResourceID, CB_SETCURSEL, index, 0);
                return;
     }
     SendDlgItemMessage(hwnd, ResourceID, CB_SETCURSEL, 0, 0);
     
}

void ReadComboBoxValue(HWND hwnd,int ResourceID,char *ret)
{
    int index;
    index = SendDlgItemMessage(hwnd, ResourceID, CB_GETCURSEL, 0, 0);
    SendDlgItemMessage(hwnd, ResourceID, CB_GETLBTEXT, index, (LPARAM)ret);
}

void ChangeSettings(HWND hwndOwner) {
    PROPSHEETPAGE psp[4];
    PROPSHEETHEADER psh;
	char ConfigStr[200],DirectoriesStr[200],titleStr[200],settingsStr[200];
    char AdvSettingsStr[200];
    psp[0].dwSize = sizeof(PROPSHEETPAGE);
    psp[0].dwFlags = PSP_USETITLE;
    psp[0].hInstance = app_hInstance;
    psp[0].pszTemplate = MAKEINTRESOURCE(IDD_MAIN);
    psp[0].pfnDlgProc = PluginsCfg;
	TranslateDefault("Config Plugins","Config Plugins",ConfigStr);
	psp[0].pszTitle = ConfigStr;
    psp[0].lParam = 0;
    psp[0].pfnCallback = NULL;

    psp[1].dwSize = sizeof(PROPSHEETPAGE);
    psp[1].dwFlags = PSP_USETITLE;
    psp[1].hInstance = app_hInstance;
    psp[1].pszTemplate = MAKEINTRESOURCE(IDD_DIRECTORIES);
    psp[1].pfnDlgProc = DirectoriesCfg;
	TranslateDefault("Directories","Directories",DirectoriesStr);
    psp[1].pszTitle = DirectoriesStr;
    psp[1].lParam = 0;
    psp[1].pfnCallback = NULL;

    psp[2].dwSize = sizeof(PROPSHEETPAGE);
    psp[2].dwFlags = PSP_USETITLE;
    psp[2].hInstance = app_hInstance;
    psp[2].pszTemplate = MAKEINTRESOURCE(IDD_MESSAGES);
    psp[2].pfnDlgProc = GeneralCfg;
	TranslateDefault("General","General",settingsStr);
    psp[2].pszTitle = settingsStr;
    psp[2].lParam = 0;
    psp[2].pfnCallback = NULL;
    
    psp[3].dwSize = sizeof(PROPSHEETPAGE);
    psp[3].dwFlags = PSP_USETITLE;
    psp[3].hInstance = app_hInstance;
    psp[3].pszTemplate = MAKEINTRESOURCE(IDD_ADVANCED_OPTIONS);
    psp[3].pfnDlgProc = AdvancedSettingsProc;
	TranslateDefault("Advanced Settings","Advanced Settings",AdvSettingsStr);
    psp[3].pszTitle = AdvSettingsStr;
    psp[3].lParam = 0;
    psp[3].pfnCallback = NULL;
  
    psh.dwSize = sizeof(PROPSHEETHEADER);
    psh.dwFlags = PSH_PROPSHEETPAGE | PSH_NOAPPLYNOW;
    psh.hwndParent = hwndOwner;
    psh.hInstance = app_hInstance;
    TranslateDefault("Settings","Settings",titleStr);
    psh.pszCaption = (LPSTR) titleStr;
    psh.nPages = sizeof(psp) / sizeof(PROPSHEETPAGE);
    psh.nStartPage = 0;
    psh.ppsp = (LPCPROPSHEETPAGE) &psp;
    psh.pfnCallback = NULL;

	PropertySheet(&psh);
	return;
}

BOOL CALLBACK AboutDlgProc(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam)
{
    switch(Message)
    {
        case WM_INITDIALOG:
             SendDlgItemMessage(hwnd, IDB_LOGO, STM_SETIMAGE, IMAGE_BITMAP, 
                (LPARAM)LoadImage (GetModuleHandle(NULL), MAKEINTRESOURCE(IDB_LOGO), 
                            IMAGE_BITMAP, 0, 0, 0));
                      
 //            MessageBox( hwnd, "", "", MB_OK );
        return TRUE;
        
        case WM_CLOSE:
              EndDialog(hwnd, IDOK);  
        break;
        
        case WM_COMMAND:
            switch(LOWORD(wParam))
            {
                case IDOK:
                    EndDialog(hwnd, IDOK);
                break;
                
                case IDC_WEBSITE:
                     ShellExecute(NULL, "open", "http://mupen64.emulation64.com", NULL, NULL, SW_SHOWNORMAL);
                break;
            }
        break;
        default:
            return FALSE;
    }
    return TRUE;
}

BOOL CALLBACK DirectoriesCfg(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam)
{
  char Buffer[MAX_PATH], Directory[255];
    LPITEMIDLIST pidl;
	BROWSEINFO bi;
    char RomBrowserDir[_MAX_PATH]; 
    HWND RomBrowserDirListBox;
    int count;
    int selected;
    switch(Message)
    {
        case WM_INITDIALOG:
                FillRomBrowserDirBox(hwnd);
                TranslateDirectoriesConfig(hwnd);
                if  (Config.RomBrowserRecursion) {
                  SendMessage(GetDlgItem(hwnd,IDC_RECURSION),BM_SETCHECK, BST_CHECKED,0);
                }
                
                if (Config.DefaultPluginsDir)
                {
                     SendMessage(GetDlgItem(hwnd,IDC_DEFAULT_PLUGINS_CHECK),BM_SETCHECK, BST_CHECKED,0);
                     EnableWindow( GetDlgItem(hwnd,IDC_PLUGINS_DIR), FALSE );
                     EnableWindow( GetDlgItem(hwnd,IDC_CHOOSE_PLUGINS_DIR), FALSE );           
                }
                if (Config.DefaultSavesDir)
                {
                     SendMessage(GetDlgItem(hwnd,IDC_DEFAULT_SAVES_CHECK),BM_SETCHECK, BST_CHECKED,0);            
                     EnableWindow( GetDlgItem(hwnd,IDC_SAVES_DIR), FALSE );
                     EnableWindow( GetDlgItem(hwnd,IDC_CHOOSE_SAVES_DIR), FALSE );                
                }
                if (Config.DefaultScreenshotsDir)
                {
                     SendMessage(GetDlgItem(hwnd,IDC_DEFAULT_SCREENSHOTS_CHECK),BM_SETCHECK, BST_CHECKED,0);            
                     EnableWindow( GetDlgItem(hwnd,IDC_SCREENSHOTS_DIR), FALSE );
                     EnableWindow( GetDlgItem(hwnd,IDC_CHOOSE_SCREENSHOTS_DIR), FALSE );                
                }                
                
                SetDlgItemText( hwnd, IDC_PLUGINS_DIR, Config.PluginsDir );
                SetDlgItemText( hwnd, IDC_SAVES_DIR, Config.SavesDir );
                SetDlgItemText( hwnd, IDC_SCREENSHOTS_DIR, Config.ScreenshotsDir );
                              
                break;                 
        case WM_NOTIFY:
                if (((NMHDR FAR *) lParam)->code == PSN_APPLY) {
                    SaveRomBrowserDirs();
                    selected = SendDlgItemMessage( hwnd, IDC_DEFAULT_PLUGINS_CHECK, BM_GETCHECK, 0, 0) == BST_CHECKED?TRUE:FALSE;    
                    GetDlgItemText( hwnd, IDC_PLUGINS_DIR, TempMessage, MAX_PATH );
                    if (strcasecmp(TempMessage,Config.PluginsDir)!=0 || Config.DefaultPluginsDir !=selected)  
                                  //if plugin dir changed,search for plugins in new dir
					           {
					   		        sprintf(Config.PluginsDir,TempMessage);
                                    Config.DefaultPluginsDir =  selected ;       
                                    search_plugins();		                         
                               } 
                    else       {            
                                    sprintf(Config.PluginsDir,TempMessage);
                                    Config.DefaultPluginsDir =  selected ;                                                
                                } 
                                                   
                    selected = SendDlgItemMessage( hwnd, IDC_DEFAULT_SAVES_CHECK, BM_GETCHECK, 0, 0) == BST_CHECKED?TRUE:FALSE;    
                    GetDlgItemText( hwnd, IDC_SAVES_DIR, Config.SavesDir, MAX_PATH );
                    Config.DefaultSavesDir =  selected ;
                    
                    selected = SendDlgItemMessage( hwnd, IDC_DEFAULT_SCREENSHOTS_CHECK, BM_GETCHECK, 0, 0) == BST_CHECKED?TRUE:FALSE;    
                    GetDlgItemText( hwnd, IDC_SCREENSHOTS_DIR, Config.ScreenshotsDir, MAX_PATH );
                    Config.DefaultScreenshotsDir =  selected ;                
                }
                break;
        case WM_COMMAND:
		        switch (LOWORD(wParam)) 
                { 
		         case IDC_RECURSION :
		               Config.RomBrowserRecursion = SendDlgItemMessage(hwnd,IDC_RECURSION,BM_GETCHECK , 0,0) == BST_CHECKED?TRUE:FALSE;
                       break;      
                 case IDC_ADD_BROWSER_DIR : 
		               bi.hwndOwner = hwnd;
					   bi.pidlRoot = NULL;
				       bi.pszDisplayName = Buffer;
				       Translate("Select Current Rom Browser Directory",TempMessage);
				       bi.lpszTitle = TempMessage;
				       bi.ulFlags = BIF_RETURNFSANCESTORS | BIF_RETURNONLYFSDIRS;
				       bi.lpfn = NULL;
				       bi.lParam = 0;
                       if ((pidl = SHBrowseForFolder(&bi)) != NULL) {
                                        
					   if (SHGetPathFromIDList(pidl, Directory)) {
					     int len = strlen(Directory);
                		 if (Directory[len - 1] != '\\') 
                              { 
                                strcat(Directory,"\\"); 
                              }
                                if (addDirectoryToLinkedList(Directory)) {
                                      SendDlgItemMessage(hwnd, IDC_ROMBROWSER_DIR_LIST, LB_ADDSTRING, 0, (LPARAM)Directory);  
			                          AddDirToList(Directory,TRUE);
			                          }
                              
                        }
                       }       
				  break; 
				  
				  case IDC_REMOVE_BROWSER_DIR :
                  	RomBrowserDirListBox = GetDlgItem(hwnd, IDC_ROMBROWSER_DIR_LIST);
					count = SendMessage(RomBrowserDirListBox, LB_GETSELCOUNT, 0, 0);
					if(count != 0)
						{
							selected = SendMessage(RomBrowserDirListBox, LB_GETCURSEL , 0, 0);
	        				SendMessage(RomBrowserDirListBox, LB_GETTEXT, selected, (LPARAM)RomBrowserDir);		
                            removeDirectoryFromLinkedList(RomBrowserDir);
                            SendMessage(RomBrowserDirListBox, LB_DELETESTRING, selected, 0);
						    RefreshRomBrowser();
                   		}
						else 
						{
							MessageBox(hwnd, "No items selected.", "Warning", MB_OK);
						}
 				  break;
				  
				  case IDC_REMOVE_BROWSER_ALL :
				        SendDlgItemMessage(hwnd, IDC_ROMBROWSER_DIR_LIST, LB_RESETCONTENT, 0, 0);
				        freeRomDirList();
				        RefreshRomBrowser();
				  break;
				  
				  case IDC_DEFAULT_PLUGINS_CHECK:
				  {      
                        selected = SendMessage( GetDlgItem(hwnd,IDC_DEFAULT_PLUGINS_CHECK), BM_GETCHECK, 0, 0 );
				        if (!selected)
				        {
                            MessageBox(NULL, "Warning: changing the plugin folder can introduce bugs in many plugins", "Warning", MB_OK);
                            EnableWindow( GetDlgItem(hwnd,IDC_PLUGINS_DIR), TRUE );
                            EnableWindow( GetDlgItem(hwnd,IDC_CHOOSE_PLUGINS_DIR), TRUE );
                        }else
                        {
                            EnableWindow( GetDlgItem(hwnd,IDC_PLUGINS_DIR), FALSE );
                            EnableWindow( GetDlgItem(hwnd,IDC_CHOOSE_PLUGINS_DIR), FALSE );
                        }
                  }
                  break;
                  case IDC_CHOOSE_PLUGINS_DIR:
                  {
                       bi.hwndOwner = hwnd;
					   bi.pidlRoot = NULL;
				       bi.pszDisplayName = Buffer;
				       bi.lpszTitle = TempMessage;
				       bi.ulFlags = BIF_RETURNFSANCESTORS | BIF_RETURNONLYFSDIRS;
				       bi.lpfn = NULL;
				       bi.lParam = 0;
                       if ((pidl = SHBrowseForFolder(&bi)) != NULL) {
					    if (SHGetPathFromIDList(pidl, Directory)) {
						 int len = strlen(Directory);
                		 if (Directory[len - 1] != '\\') 
                              { strcat(Directory,"\\"); }
                                                           
                               SetDlgItemText( hwnd, IDC_PLUGINS_DIR, Directory );
                                                        
                          }
                       }
                        
                  }
                  break;
				  case IDC_DEFAULT_SAVES_CHECK:
				  {      
                        selected = SendMessage( GetDlgItem(hwnd,IDC_DEFAULT_SAVES_CHECK), BM_GETCHECK, 0, 0 );
				        if (!selected)
				        {
                            EnableWindow( GetDlgItem(hwnd,IDC_SAVES_DIR), TRUE );
                            EnableWindow( GetDlgItem(hwnd,IDC_CHOOSE_SAVES_DIR), TRUE );
                        }else
                        {
                            EnableWindow( GetDlgItem(hwnd,IDC_SAVES_DIR), FALSE );
                            EnableWindow( GetDlgItem(hwnd,IDC_CHOOSE_SAVES_DIR), FALSE );
                        }
                  }
                  break;
                  case IDC_CHOOSE_SAVES_DIR:
                  {
                       bi.hwndOwner = hwnd;
					   bi.pidlRoot = NULL;
				       bi.pszDisplayName = Buffer;
				       bi.lpszTitle = TempMessage;
				       bi.ulFlags = BIF_RETURNFSANCESTORS | BIF_RETURNONLYFSDIRS;
				       bi.lpfn = NULL;
				       bi.lParam = 0;
                       if ((pidl = SHBrowseForFolder(&bi)) != NULL) {
					    if (SHGetPathFromIDList(pidl, Directory)) {
						 int len = strlen(Directory);
                		 if (Directory[len - 1] != '\\') 
                              { strcat(Directory,"\\"); 
                                SetDlgItemText( hwnd, IDC_SAVES_DIR, Directory );
                              }
                          }
                       }
                  }
                  break;
				  case IDC_DEFAULT_SCREENSHOTS_CHECK:
				  {      
                        selected = SendMessage( GetDlgItem(hwnd,IDC_DEFAULT_SCREENSHOTS_CHECK), BM_GETCHECK, 0, 0 );
				        if (!selected)
				        {
                            EnableWindow( GetDlgItem(hwnd,IDC_SCREENSHOTS_DIR), TRUE );
                            EnableWindow( GetDlgItem(hwnd,IDC_CHOOSE_SCREENSHOTS_DIR), TRUE );
                        }else
                        {
                            EnableWindow( GetDlgItem(hwnd,IDC_SCREENSHOTS_DIR), FALSE );
                            EnableWindow( GetDlgItem(hwnd,IDC_CHOOSE_SCREENSHOTS_DIR), FALSE );
                        }
                  }
                  break;                
                  case IDC_CHOOSE_SCREENSHOTS_DIR:
                  {
                       bi.hwndOwner = hwnd;
					   bi.pidlRoot = NULL;
				       bi.pszDisplayName = Buffer;
				       bi.lpszTitle = TempMessage;
				       bi.ulFlags = BIF_RETURNFSANCESTORS | BIF_RETURNONLYFSDIRS;
				       bi.lpfn = NULL;
				       bi.lParam = 0;
                       if ((pidl = SHBrowseForFolder(&bi)) != NULL) {
					    if (SHGetPathFromIDList(pidl, Directory)) {
						 int len = strlen(Directory);
                		 if (Directory[len - 1] != '\\') 
                              { strcat(Directory,"\\"); 
                                SetDlgItemText( hwnd, IDC_SCREENSHOTS_DIR, Directory );
                              }
                          }
                       }
                  }
                  break;
                }
	    break;
    
    }	        
    return FALSE;
}

BOOL CALLBACK PluginsCfg(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam)
{
    char path_buffer[_MAX_PATH];
    int index;
                          
    switch(Message)
    {
        case WM_CLOSE:
              EndDialog(hwnd, IDOK);  
        break;
        case WM_INITDIALOG:
            rewind_plugin();           
            while(get_plugin_type() != -1) {
                switch (get_plugin_type())
                {
                case PLUGIN_TYPE_GFX:
                    SendDlgItemMessage(hwnd, IDC_COMBO_GFX, CB_ADDSTRING, 0, (LPARAM)next_plugin());
                    break;
                case PLUGIN_TYPE_CONTROLLER:
                    SendDlgItemMessage(hwnd, IDC_COMBO_INPUT, CB_ADDSTRING, 0, (LPARAM)next_plugin());
                    break;
                case PLUGIN_TYPE_AUDIO:
                    SendDlgItemMessage(hwnd, IDC_COMBO_SOUND, CB_ADDSTRING, 0, (LPARAM)next_plugin());
                    break;
                case PLUGIN_TYPE_RSP:
                    SendDlgItemMessage(hwnd, IDC_COMBO_RSP, CB_ADDSTRING, 0, (LPARAM)next_plugin());
                    break;                                
                default:
                    next_plugin();
                }
             }   
            // Set gfx plugin
            index = SendDlgItemMessage(hwnd, IDC_COMBO_GFX, CB_FINDSTRINGEXACT, 0, (LPARAM)gfx_name);
            if (index!=CB_ERR) {
                SendDlgItemMessage(hwnd, IDC_COMBO_GFX, CB_SETCURSEL, index, 0);
            }
            else   {
                SendDlgItemMessage(hwnd, IDC_COMBO_GFX, CB_SETCURSEL, 0, 0);
                SendDlgItemMessage(hwnd, IDC_COMBO_GFX, CB_GETLBTEXT, 0, (LPARAM)gfx_name);
                }
            // Set input plugin
            index = SendDlgItemMessage(hwnd, IDC_COMBO_INPUT, CB_FINDSTRINGEXACT, 0, (LPARAM)input_name);
            if (index!=CB_ERR) {
                 SendDlgItemMessage(hwnd, IDC_COMBO_INPUT, CB_SETCURSEL, index, 0);
            }
            else    {
                 SendDlgItemMessage(hwnd, IDC_COMBO_INPUT, CB_SETCURSEL, 0, 0);
                 SendDlgItemMessage(hwnd, IDC_COMBO_INPUT, CB_GETLBTEXT, 0, (LPARAM)input_name);
                }   
            // Set sound plugin
            index = SendDlgItemMessage(hwnd, IDC_COMBO_SOUND, CB_FINDSTRINGEXACT, 0, (LPARAM)sound_name);
            if (index!=CB_ERR) {
            SendDlgItemMessage(hwnd, IDC_COMBO_SOUND, CB_SETCURSEL, index, 0);
            }
            else    {
                  SendDlgItemMessage(hwnd, IDC_COMBO_SOUND, CB_SETCURSEL, 0, 0);
                  SendDlgItemMessage(hwnd, IDC_COMBO_SOUND, CB_GETLBTEXT, 0, (LPARAM)sound_name);
                }
            // Set RSP plugin
            index = SendDlgItemMessage(hwnd, IDC_COMBO_RSP, CB_FINDSTRINGEXACT, 0, (LPARAM)rsp_name);
            if (index!=CB_ERR) {
            SendDlgItemMessage(hwnd, IDC_COMBO_RSP, CB_SETCURSEL, index, 0);
            }
            else    {
                  SendDlgItemMessage(hwnd, IDC_COMBO_RSP, CB_SETCURSEL, 0, 0);
                  SendDlgItemMessage(hwnd, IDC_COMBO_RSP, CB_GETLBTEXT, 0, (LPARAM)rsp_name);
                }
                
                        
            TranslateConfigDialog(hwnd);
            if(emu_launched) {
                EnableWindow( GetDlgItem(hwnd,IDC_COMBO_GFX), FALSE );
                EnableWindow( GetDlgItem(hwnd,IDC_COMBO_INPUT), FALSE );
                EnableWindow( GetDlgItem(hwnd,IDC_COMBO_SOUND), FALSE );
                EnableWindow( GetDlgItem(hwnd,IDC_COMBO_RSP), FALSE );   
            }
            
            //Show the images
            SendDlgItemMessage(hwnd, IDB_DISPLAY, STM_SETIMAGE, IMAGE_BITMAP, 
                (LPARAM)LoadImage (GetModuleHandle(NULL), MAKEINTRESOURCE(IDB_DISPLAY), 
                IMAGE_BITMAP, 0, 0, 0));
            SendDlgItemMessage(hwnd, IDB_CONTROL, STM_SETIMAGE, IMAGE_BITMAP, 
                (LPARAM)LoadImage (GetModuleHandle(NULL), MAKEINTRESOURCE(IDB_CONTROL), 
                IMAGE_BITMAP, 0, 0, 0));
             SendDlgItemMessage(hwnd, IDB_SOUND, STM_SETIMAGE, IMAGE_BITMAP, 
                (LPARAM)LoadImage (GetModuleHandle(NULL), MAKEINTRESOURCE(IDB_SOUND), 
                IMAGE_BITMAP, 0, 0, 0));
             SendDlgItemMessage(hwnd, IDB_RSP, STM_SETIMAGE, IMAGE_BITMAP, 
                (LPARAM)LoadImage (GetModuleHandle(NULL), MAKEINTRESOURCE(IDB_RSP), 
                IMAGE_BITMAP, 0, 0, 0));
             return TRUE;
        case WM_COMMAND:
            switch(LOWORD(wParam))
            {
                case IDGFXCONFIG:
                     hwnd_plug = hwnd;
                     ReadComboBoxValue( hwnd, IDC_COMBO_GFX, path_buffer);
                     exec_config(path_buffer);
                     break;
                case IDGFXTEST:
                     hwnd_plug = hwnd;
                     ReadComboBoxValue( hwnd, IDC_COMBO_GFX, path_buffer);
                     exec_test(path_buffer);
                     break;
                case IDGFXABOUT:
                     hwnd_plug = hwnd;
                     ReadComboBoxValue( hwnd, IDC_COMBO_GFX, path_buffer);
                     exec_about(path_buffer);
                     break;
                case IDINPUTCONFIG:
                     hwnd_plug = hwnd;
                     ReadComboBoxValue( hwnd, IDC_COMBO_INPUT, path_buffer);
                     exec_config(path_buffer);
                     break;
                case IDINPUTTEST:
                     hwnd_plug = hwnd;
                     ReadComboBoxValue( hwnd, IDC_COMBO_INPUT, path_buffer);
                     exec_test(path_buffer);
                     break;
                case IDINPUTABOUT:
                     hwnd_plug = hwnd;
                     ReadComboBoxValue( hwnd, IDC_COMBO_INPUT, path_buffer);
                     exec_about(path_buffer);
                     break;
                case IDSOUNDCONFIG:
                     hwnd_plug = hwnd;
                     ReadComboBoxValue( hwnd, IDC_COMBO_SOUND, path_buffer);
                     exec_config(path_buffer);
                     break;
                case IDSOUNDTEST:
                     hwnd_plug = hwnd;
                     ReadComboBoxValue( hwnd, IDC_COMBO_SOUND, path_buffer);
                     exec_test(path_buffer);
                     break;
                case IDSOUNDABOUT:
                     hwnd_plug = hwnd;
                     ReadComboBoxValue( hwnd, IDC_COMBO_SOUND, path_buffer);
                     exec_about(path_buffer);
                     break;
                case IDRSPCONFIG:
                     hwnd_plug = hwnd;
                     ReadComboBoxValue( hwnd, IDC_COMBO_RSP, path_buffer);
                     exec_config(path_buffer);
                     break;
                case IDRSPTEST:
                     hwnd_plug = hwnd;
                     ReadComboBoxValue( hwnd, IDC_COMBO_RSP, path_buffer);
                     exec_test(path_buffer);
                     break;
                case IDRSPABOUT:
                     hwnd_plug = hwnd;
                     ReadComboBoxValue( hwnd, IDC_COMBO_RSP, path_buffer);
                     exec_about(path_buffer);
                     break;    
            }
            break;
        case WM_NOTIFY:
		             if (((NMHDR FAR *) lParam)->code == PSN_APPLY) {
		                 
                         ReadComboBoxValue( hwnd, IDC_COMBO_GFX, gfx_name);
                         WriteCfgString("Plugins","Graphics",gfx_name);
                         
                         ReadComboBoxValue( hwnd, IDC_COMBO_INPUT, input_name);
                         WriteCfgString("Plugins","Input",input_name);
                         
                         ReadComboBoxValue( hwnd, IDC_COMBO_SOUND, sound_name);
                         WriteCfgString("Plugins","Sound",sound_name);
                         
                         ReadComboBoxValue( hwnd, IDC_COMBO_RSP, rsp_name);
                         WriteCfgString("Plugins","RSP",rsp_name);
                     }
                     break;
        default:
            return FALSE;
    }
    return TRUE;
}


void SwitchModifier(HWND hwnd) {
    if ( ReadCheckBoxValue(hwnd,IDC_SPEEDMODIFIER)) {  
                   EnableWindow(hwndTrack,TRUE);             
                }
                else {
                   EnableWindow(hwndTrack,FALSE);
                } 
}

void SwitchLimitFPS(HWND hwnd) {
    if ( ReadCheckBoxValue(hwnd,IDC_LIMITFPS)) {
                  EnableWindow(GetDlgItem(hwnd,IDC_SPEEDMODIFIER), TRUE);
                  SwitchModifier(hwnd) ;               
                }
                else {
                  EnableWindow(GetDlgItem(hwnd,IDC_SPEEDMODIFIER), FALSE); 
                  EnableWindow(hwndTrack,FALSE); 
                }  
}

void FillModifierValue(HWND hwnd,int value ) {
    char temp[10];
    sprintf( temp, "%d%%", value);
    SetDlgItemText( hwnd, IDC_SPEEDMODIFIER_VALUE, temp); 
}

BOOL CALLBACK GeneralCfg(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam)
{
        
    switch(Message) {
    case WM_INITDIALOG:
         WriteCheckBoxValue( hwnd, IDC_SHOWFPS, Config.showFPS) ;
         WriteCheckBoxValue( hwnd, IDC_SHOWVIS, Config.showVIS) ;       
         WriteCheckBoxValue( hwnd, IDC_ALERTBADROM, Config.alertBAD);
         WriteCheckBoxValue( hwnd, IDC_ALERTHACKEDROM, Config.alertHACK);  
         WriteCheckBoxValue( hwnd, IDC_ALERTSAVESERRORS, Config.savesERRORS);  
         WriteCheckBoxValue( hwnd, IDC_LIMITFPS, Config.limitFps);  
         WriteCheckBoxValue( hwnd, IDC_INI_COMPRESSED, Config.compressedIni);
         WriteCheckBoxValue( hwnd, IDC_SPEEDMODIFIER, Config.UseFPSmodifier  );
               
         switch (Config.guiDynacore)    
            {        
               case 0:
                     CheckDlgButton(hwnd, IDC_INTERP, BST_CHECKED);
                     break;
               case 1:
                     CheckDlgButton(hwnd, IDC_RECOMP, BST_CHECKED);
                     break;             
               case 2:
                     CheckDlgButton(hwnd, IDC_PURE_INTERP, BST_CHECKED);             
                     break;      
             }       
         
         if (emu_launched) {
                  EnableWindow( GetDlgItem(hwnd,IDC_INTERP), FALSE );
                  EnableWindow( GetDlgItem(hwnd,IDC_RECOMP), FALSE );
                  EnableWindow( GetDlgItem(hwnd,IDC_PURE_INTERP), FALSE );
         }
         
         CreateTrackbar(hwnd,1,200,Config.FPSmodifier,200) ; 
         
         SwitchLimitFPS(hwnd);
         FillModifierValue( hwnd, Config.FPSmodifier);        
         TranslateGeneralDialog(hwnd) ;                           
         return TRUE;
         
    case WM_COMMAND:
        switch(LOWORD(wParam))
        {
           case IDC_INTERP:
                if (!emu_launched) {
                   Config.guiDynacore = 0;
                   }
           break;
           case IDC_RECOMP:
                if (!emu_launched) {
                   Config.guiDynacore = 1;
                   }
           break;
           case IDC_PURE_INTERP:
                if (!emu_launched) {
                   Config.guiDynacore = 2;
                   }
           break;
           case IDC_LIMITFPS:
                SwitchLimitFPS(hwnd) ;
           break;
           case  IDC_SPEEDMODIFIER:
                SwitchModifier(hwnd)  ;
           break; 
                    
        }
        break;

    case WM_NOTIFY:
		       if (((NMHDR FAR *) lParam)->code == NM_RELEASEDCAPTURE)  {
                    FillModifierValue( hwnd, SendMessage( hwndTrack , TBM_GETPOS, 0, 0));        
               }     
               if (((NMHDR FAR *) lParam)->code == PSN_APPLY)  {
                              Config.showFPS = ReadCheckBoxValue( hwnd, IDC_SHOWFPS);
                              Config.showVIS = ReadCheckBoxValue( hwnd, IDC_SHOWVIS);
                              Config.alertBAD = ReadCheckBoxValue(hwnd,IDC_ALERTBADROM);
                              Config.alertHACK = ReadCheckBoxValue(hwnd,IDC_ALERTHACKEDROM);
                              Config.savesERRORS = ReadCheckBoxValue(hwnd,IDC_ALERTSAVESERRORS);
                              Config.limitFps = ReadCheckBoxValue(hwnd,IDC_LIMITFPS);
                              Config.compressedIni = ReadCheckBoxValue(hwnd,IDC_INI_COMPRESSED);
                              Config.FPSmodifier = SendMessage( hwndTrack , TBM_GETPOS, 0, 0);
                              Config.UseFPSmodifier = ReadCheckBoxValue( hwnd , IDC_SPEEDMODIFIER );
                              if (emu_launched) SetStatusMode( 2 );
                              else SetStatusMode( 0 );
                              InitTimer();
                              }
            break;                     
     default:
            return FALSE;       
     }
     return TRUE;            
}

DWORD WINAPI ScanThread(LPVOID lpParam) {
    
    int i;
    ROM_INFO *pRomInfo;
    md5_byte_t digest[16];
    char tempname[100];
    EnableWindow(GetDlgItem(romInfoHWND,IDC_STOP),TRUE);
    EnableWindow(GetDlgItem(romInfoHWND,IDC_START),FALSE);
    EnableWindow(GetDlgItem(romInfoHWND,IDC_CLOSE),FALSE);
     for (i=0;i<ItemList.ListCount;i++)
        {
          if (stopScan) break;
          pRomInfo = &ItemList.List[i];
          sprintf(TempMessage,"%d",i+1);
          SetDlgItemText(romInfoHWND,IDC_CURRENT_ROM,TempMessage);
          SetDlgItemText(romInfoHWND,IDC_ROM_FULLPATH,pRomInfo->szFullFileName);
          //SendMessage( GetDlgItem(romInfoHWND, IDC_TOTAL_ROMS_PROGRESS), PBM_STEPIT, 0, 0 ); 
          SendMessage( GetDlgItem(romInfoHWND, IDC_TOTAL_ROMS_PROGRESS), PBM_SETPOS, i+1, 0 );
                 
          strcpy(TempMessage,pRomInfo->MD5);
          if (!strcmp(TempMessage,"")) {
                    calculateMD5(pRomInfo->szFullFileName,digest);
                    MD5toString(digest,TempMessage);
          }
          strcpy(pRomInfo->MD5,TempMessage);
          getIniGoodNameByMD5(TempMessage,tempname);
          strcpy(pRomInfo->GoodName,tempname);
        }
     //SendMessage( GetDlgItem(romInfoHWND, IDC_TOTAL_ROMS_PROGRESS), PBM_SETPOS, 0, 0 );
     EnableWindow(GetDlgItem(romInfoHWND,IDC_STOP),FALSE);
     EnableWindow(GetDlgItem(romInfoHWND,IDC_START),TRUE);
     EnableWindow(GetDlgItem(romInfoHWND,IDC_CLOSE),TRUE);
    ExitThread(dwExitCode);
}

BOOL CALLBACK AuditDlgProc(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam) {
    ROM_INFO *pRomInfo;
    HWND hwndPB1, hwndPB2;    //Progress Bar
    
    switch(Message) {
    case WM_INITDIALOG:
         pRomInfo = &ItemList.List[0];
         SetDlgItemText(hwnd,IDC_ROM_FULLPATH,pRomInfo->szFullFileName);
         sprintf(TempMessage,"%d",ItemList.ListCount);
         SetDlgItemText(hwnd,IDC_TOTAL_ROMS,TempMessage);
         SetDlgItemText(hwnd,IDC_CURRENT_ROM,"");
         
         hwndPB1 = GetDlgItem( hwnd, IDC_CURRENT_ROM_PROGRESS );
         hwndPB2 = GetDlgItem( hwnd, IDC_TOTAL_ROMS_PROGRESS );
         SendMessage( hwndPB1, PBM_SETRANGE, 0, MAKELPARAM(0, 100) ); 
         SendMessage( hwndPB1, PBM_SETSTEP, (WPARAM) 1, 0 ); 
         SendMessage( hwndPB2, PBM_SETRANGE, 0, MAKELPARAM(0, ItemList.ListCount) ); 
         SendMessage( hwndPB2, PBM_SETSTEP, (WPARAM) 1, 0 ); 
        
         
         TranslateAuditDialog(hwnd);
         return TRUE;
    case WM_COMMAND:
          switch(LOWORD(wParam))
            {
                case IDC_START:
                    romInfoHWND = hwnd;
                    stopScan = FALSE;
                    EmuThreadHandle = CreateThread(NULL, 0, ScanThread, NULL, 0, &Id);
                break;
                case IDC_STOP:
                     stopScan = TRUE; 
                break;
                case IDCANCEL:
                case IDC_CLOSE:
                     stopScan = TRUE;
                     romInfoHWND = NULL;
                     //FastRefreshBrowser();
                     if (!emu_launched) {
                        ShowWindow( hRomList, FALSE ); 
                        ShowWindow( hRomList, TRUE );
                     }
                     
                     EndDialog(hwnd, IDOK);
                break;
            }             
     default:
            return FALSE;       
     }       
}
BOOL CALLBACK LangInfoProc(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam) {
    switch(Message) {
    case WM_INITDIALOG:
         TranslateLangInfoDialog(hwnd);
         return TRUE;
    case WM_COMMAND:
          switch(LOWORD(wParam))
            {
                case IDOK:
                case IDCANCEL:
                case IDC_CLOSE:
                     EndDialog(hwnd, IDOK);
                break;
            }             
     default:
            return FALSE;       
     }       
}

BOOL CALLBACK AdvancedSettingsProc(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam)
{
        
    switch(Message) {
      case WM_INITDIALOG:
         WriteCheckBoxValue( hwnd, IDC_STARTFULLSCREEN, Config.StartFullScreen);
         WriteCheckBoxValue( hwnd, IDC_PAUSENOTACTIVE, Config.PauseWhenNotActive);
         WriteCheckBoxValue( hwnd, IDC_PLUGIN_OVERWRITE, Config.OverwritePluginSettings);      
         WriteCheckBoxValue( hwnd, IDC_GUI_TOOLBAR, Config.GuiToolbar);
         WriteCheckBoxValue( hwnd, IDC_GUI_STATUSBAR, Config.GuiStatusbar);
         WriteCheckBoxValue( hwnd, IDC_AUTOINCSAVESLOT, Config.AutoIncSaveSlot);
                  
         WriteCheckBoxValue( hwnd, IDC_NO_AUDIO_DELAY, no_audio_delay);
         WriteCheckBoxValue( hwnd, IDC_NO_COMPILED_JUMP, no_compiled_jump);
         
         WriteCheckBoxValue( hwnd, IDC_COLUMN_GOODNAME, Config.Column_GoodName);
         WriteCheckBoxValue( hwnd, IDC_COLUMN_INTERNALNAME, Config.Column_InternalName);
         WriteCheckBoxValue( hwnd, IDC_COLUMN_COUNTRY, Config.Column_Country);
         WriteCheckBoxValue( hwnd, IDC_COLUMN_SIZE, Config.Column_Size);
         WriteCheckBoxValue( hwnd, IDC_COLUMN_COMMENTS, Config.Column_Comments);
         WriteCheckBoxValue( hwnd, IDC_COLUMN_FILENAME, Config.Column_FileName);
         WriteCheckBoxValue( hwnd, IDC_COLUMN_MD5, Config.Column_MD5);
         
         TranslateAdvancedDialog(hwnd) ;                           
         return TRUE;
         
      case WM_COMMAND:
        switch(LOWORD(wParam))
        {
          
        }
        break;

       case WM_NOTIFY:
           if (((NMHDR FAR *) lParam)->code == PSN_APPLY)  {
                Config.StartFullScreen = ReadCheckBoxValue( hwnd, IDC_STARTFULLSCREEN);
                Config.PauseWhenNotActive =  ReadCheckBoxValue( hwnd, IDC_PAUSENOTACTIVE); 
                Config.OverwritePluginSettings =  ReadCheckBoxValue( hwnd, IDC_PLUGIN_OVERWRITE);
                Config.GuiToolbar =  ReadCheckBoxValue( hwnd, IDC_GUI_TOOLBAR);
                Config.GuiStatusbar = ReadCheckBoxValue( hwnd, IDC_GUI_STATUSBAR);
	        Config.AutoIncSaveSlot = ReadCheckBoxValue( hwnd, IDC_AUTOINCSAVESLOT);
                                                                                               
                no_audio_delay = ReadCheckBoxValue( hwnd, IDC_NO_AUDIO_DELAY);
                no_compiled_jump = ReadCheckBoxValue( hwnd, IDC_NO_COMPILED_JUMP);
                
                Config.Column_GoodName = ReadCheckBoxValue( hwnd, IDC_COLUMN_GOODNAME);
                Config.Column_InternalName = ReadCheckBoxValue( hwnd, IDC_COLUMN_INTERNALNAME);
                Config.Column_Country = ReadCheckBoxValue( hwnd, IDC_COLUMN_COUNTRY);
                Config.Column_Size = ReadCheckBoxValue( hwnd, IDC_COLUMN_SIZE);
                Config.Column_Comments = ReadCheckBoxValue( hwnd, IDC_COLUMN_COMMENTS);
                Config.Column_FileName = ReadCheckBoxValue( hwnd, IDC_COLUMN_FILENAME);
                Config.Column_MD5 = ReadCheckBoxValue( hwnd, IDC_COLUMN_MD5); 
                
                EnableToolbar(); 
                EnableStatusbar();
                FastRefreshBrowser();                
           }
       break;
                            
       default:
           return FALSE;       
    }
    return TRUE;            
}

HWND WINAPI CreateTrackbar( 
    HWND hwndDlg,  // handle of dialog box (parent window) 
    UINT iMin,     // minimum value in trackbar range 
    UINT iMax,     // maximum value in trackbar range 
    UINT iSelMin,  // minimum value in trackbar selection 
    UINT iSelMax)  // maximum value in trackbar selection 
{ 

    
    hwndTrack = CreateWindowEx( 
        0,                             // no extended styles 
        TRACKBAR_CLASS,                // class name 
        "Trackbar Control",            // title (caption) 
        WS_CHILD | WS_VISIBLE | 
         /*TBS_TOOLTIPS |*/ TBS_FIXEDLENGTH ,  // style 
        30, 184,                        // position 
        300, 30,                       // size 
        hwndDlg,                       // parent window 
        (HMENU)ID_FPSTRACKBAR,               // control identifier 
        app_hInstance,                 // instance 
        NULL) ;                          // no WM_CREATE parameter 
         

    SendMessage(hwndTrack, TBM_SETRANGE, 
        (WPARAM) TRUE,                   // redraw flag 
        (LPARAM) MAKELONG(iMin, iMax));  // min. & max. positions 
    SendMessage(hwndTrack, TBM_SETPAGESIZE, 
        0, (LPARAM) 10);                  // new page size 
    SendMessage(hwndTrack, TBM_SETLINESIZE, 
        0, (LPARAM) 10);
    SendMessage(hwndTrack, TBM_SETTIC, 
        0, (LPARAM) 100);              
/*
    SendMessage(hwndTrack, TBM_SETSEL, 
        (WPARAM) FALSE,                  // redraw flag 
        (LPARAM) MAKELONG(iSelMin, iSelMax)); 
*/        
    SendMessage(hwndTrack, TBM_SETPOS, 
        (WPARAM) TRUE,                   // redraw flag 
        (LPARAM) iSelMin); 

    SetFocus(hwndTrack); 

    return hwndTrack; 
} 

