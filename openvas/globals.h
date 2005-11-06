 
#ifndef _NESSUSC_GLOBALS_H
#define _NESSUSC_GLOBALS_H

extern struct arglist * Plugins;
extern struct arglist * Scanners;
extern struct arglist * Dependencies;
#ifdef CLIENTSIDE_PLUGINS
extern struct arglist * Upload;
#endif
extern harglst * NetMap;
extern int PluginsNum;
extern int ScannersNum;
extern struct arglist * Prefs;
extern struct arglist * MainDialog;
extern struct arglist * ArgSock;
extern char * Alt_rcfile;
extern int GlobalSocket;
extern struct plugin_filter Filter;

#ifdef ENABLE_SAVE_TESTS
extern harglst * Sessions;
extern int Sessions_saved;
extern int Detached_sessions_saved;
#endif

#ifdef ENABLE_SAVE_KB
extern int DetachedMode;
#endif
extern int F_show_pixmaps;
extern int F_quiet_mode;
extern int F_nessusd_running;
extern int First_time;
extern int ListOnly;

#ifdef _WIN32
# include "globals.w32"
/* #define _NO_PIES */
#else /* _WIN32 */
# define closesocket(x) close (x)
#endif /* _WIN32 */

# define HANDLE int

#define nulstr(x) (!(x) || ((x)[0] == '\0'))

#endif
