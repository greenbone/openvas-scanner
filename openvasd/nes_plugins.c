/* OpenVAS
* $Id$
* Description: Compiles old-style OpenVAS plugins, implemented as shared libraries.
*
* Authors: - Renaud Deraison <deraison@nessus.org> (Original pre-fork develoment)
*          - Tim Brown <mailto:timb@openvas.org> (Initial fork)
*          - Laban Mwangi <mailto:labanm@openvas.org> (Renaming work)
*          - Tarik El-Yassem <mailto:tarik@openvas.org> (Headers section)
*
* Copyright:
* Portions Copyright (C) 2006 Software in the Public Interest, Inc.
* Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2,
* as published by the Free Software Foundation
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*
*
*/

#include <includes.h>
#include "pluginload.h"
#include "plugs_hash.h"
#include "processes.h"
#include "log.h"
#include "preferences.h"

static int nes_thread(struct arglist *);

#ifdef HAVE_SHL_LOAD	/* this is HP/UX */
ext_library_t dlopen(name)
 char* name;
{
 return (ext_library_t)shl_load(name, BIND_IMMEDIATE|BIND_VERBOSE|BIND_NOSTART, 0L);
}

void * 
dlsym(lib, name)
 shl_t lib;
 char * name;
{
 void* ret;
 int status;
 status = shl_findsym((shl_t *)&lib, name, TYPE_PROCEDURE, &ret);
 if((status == -1) && (errno == 0))
 {
  status = shl_findsym((shl_t *)&lib, name, TYPE_DATA, &ret);
 }
 
 return (status == -1 ) ? NULL : ret;
}

void
dlclose(x)
 shl_t * x;
{
 shl_unload(x);
}

char*
dlerror()
{
 return strerror(errno);
}

#else /* HAVE_SHL_LOAD */
#ifdef HAVE_NSCREATEOBJECTFILEIMAGEFROMFILE /* Darwin */
#if defined(HAVE_DL_LIB) || defined(HAVE_DLFNC_H)
#define dlopen macosx_dlopen
#define dlsym macosx_dlsym
#define dlclose macosx_dlclose
#define dlerror macosx_dlerror
#undef HAVE_DL_LIB
#endif
#include <mach-o/dyld.h>

ext_library_t
dlopen(name)
 char* name;
{
 NSObjectFileImage ofile;
 
 if(NSCreateObjectFileImageFromFile(name, &ofile) != NSObjectFileImageSuccess)
 {
  fprintf(stderr, "NSCreateObjectFileImageFromFile(%s) failed\n", name);
  return NULL;
 }

 return NSLinkModule(ofile, name, NSLINKMODULE_OPTION_PRIVATE|
				  NSLINKMODULE_OPTION_BINDNOW);
}

void * 
dlsym(lib, name)
 void* lib;
 char * name;
{
 NSSymbol nsSymbol = NSLookupSymbolInModule((NSModule)lib, name); 
 if(nsSymbol == NULL)
 {
  /* fprintf(stderr, "NSLookupSymbolInModule(%x, %s) failed\n", lib, name); */
  return NULL;
 }
 return NSAddressOfSymbol(nsSymbol);
}

void
dlclose(x)
 void * x;
{
 NSUnLinkModule((NSModule)(x), NSUNLINKMODULE_OPTION_NONE);
}

char*
dlerror()
{
 return strerror(errno);
}
#endif /* Darwin */
#endif

/*
 *  Initialize this class
 */
pl_class_t* nes_plugin_init(struct arglist* prefs, struct arglist* args) {
    return &nes_plugin_class;
}

/*
 * add *one* .nes (shared lib) plugin to the server list
 */
struct arglist * 
nes_plugin_add(folder, name, plugins, preferences)
     char * folder;
     char * name;
     struct arglist * plugins;
     struct arglist * preferences;
{
 ext_library_t ptr = NULL; 
 char fullname[PATH_MAX+1];
 struct arglist * prev_plugin = NULL;
 struct arglist * args = NULL;
 
 
 snprintf(fullname, sizeof(fullname), "%s/%s", folder, name);
 
 args = store_load_plugin(folder, name, preferences);
 if( args == NULL )
 {
  if((ptr = LOAD_LIBRARY(fullname))== NULL){
    log_write("Couldn't load %s - %s\n", name, LIB_LAST_ERROR());
  }
  else {
    plugin_init_t  f_init;
   
    if((f_init = (plugin_init_t)LOAD_FUNCTION(ptr, "plugin_init")) ||
    	(f_init = (plugin_init_t)LOAD_FUNCTION(ptr, "_plugin_init")))
      {
	int e;
      	args = emalloc(sizeof(struct arglist));
      	arg_add_value(args, "preferences", ARG_ARGLIST, -1, (void*)preferences);
      	e = (*f_init)(args);
	if(e >= 0)
	{  
	 plug_set_path(args, fullname);
	 store_plugin(args, name); 
 	 args = store_load_plugin(folder, name, preferences);
	}
	else
	{
	 arg_set_value(args, "preferences", -1, NULL);
	 arg_free_all(args);
	 args = NULL;
	}
      }
    else log_write("Couldn't find the entry point in %s [%s]\n", name,LIB_LAST_ERROR());
    CLOSE_LIBRARY(ptr);
   }
  }
  
  if( args != NULL )
  {
   prev_plugin = arg_get_value(plugins, name);
   plug_set_launch(args, LAUNCH_DISABLED);
   if( prev_plugin == NULL )
          arg_add_value(plugins, name, ARG_ARGLIST, -1, args);
    else
         {
          plugin_free(prev_plugin);
          arg_set_value(plugins, name, -1, args);
         }
  }
   return args;
}


int
nes_plugin_launch(globals, plugin, hostinfos, preferences, kb, name)
	struct arglist * globals;
	struct arglist * plugin;
	struct arglist * hostinfos;
	struct arglist * preferences;
	struct kb_item ** kb; /* knowledge base */
	char * name;
{
 nthread_t module;
 plugin_run_t func = NULL;
 ext_library_t ptr = NULL;

 
 
 ptr = LOAD_LIBRARY(name);
 if( ptr == NULL)
	{
    	log_write("Couldn't load %s - %s\n", name, LIB_LAST_ERROR());
 	return -1;
	}
	
	
 func = (plugin_run_t)LOAD_FUNCTION(ptr, "plugin_run");
 if( func == NULL)
 	func = (plugin_run_t)LOAD_FUNCTION(ptr, "_plugin_run");
	
 if( func == NULL )
 	{
 	log_write("no 'plugin_run()' function in %s\n", name);
	return -1;
	}


 arg_add_value(plugin, "globals", ARG_ARGLIST, -1, globals);
 arg_add_value(plugin, "HOSTNAME", ARG_ARGLIST, -1, hostinfos);
 arg_add_value(plugin, "func", ARG_PTR, -1, func);
 arg_add_value(plugin, "name", ARG_STRING, strlen(name), name);
 arg_set_value(plugin, "preferences", -1, preferences);
 arg_add_value(plugin, "key", ARG_PTR, -1, kb);
 module = create_process((process_func_t)nes_thread, plugin);
 CLOSE_LIBRARY(ptr);
 return module;
}

static int nes_thread(args)
 struct arglist * args;
{
 int soc = (int)arg_get_value(args, "SOCKET");
 struct arglist * globals = arg_get_value(args, "globals");
 int i;
 plugin_run_t func;
 int e;

 if(preferences_benice(NULL))nice(-5);


 soc = dup2(soc, 4);
 if ( soc < 0 )
 { 
  log_write("dup2() failed ! Can't launch socket!\n");
 }
 /* XXX ugly hack */
 
 arg_set_value(globals, "global_socket", sizeof(int), (void*)soc);
 arg_set_value(args, "SOCKET", sizeof(int), (void*)soc);
 for(i=5;i<getdtablesize();i++)
 {
    close(i);
 }
 
 setproctitle("testing %s (%s)", (char*)arg_get_value(arg_get_value(args, "HOSTNAME"), "NAME"), (char*)arg_get_value(args, "name"));
 func = arg_get_value(args, "func");
 signal(SIGTERM, _exit);
 e = func(args);
 internal_send(soc, NULL, INTERNAL_COMM_MSG_TYPE_CTRL | INTERNAL_COMM_CTRL_FINISHED);
 return e;
}

pl_class_t nes_plugin_class = {
    NULL,
    ".nes",
    nes_plugin_init,
    nes_plugin_add,
    nes_plugin_launch,
};
