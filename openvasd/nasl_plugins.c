/* OpenVAS
* $Id$
* Description: Launches NASL plugins.
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

#include <glib.h>

#include <nasl.h>
#include "pluginload.h"
#include "plugs_hash.h"
#include "preferences.h"
#include "processes.h"
#include "log.h"
/*
 *  Initialize the nasl system
 */
static pl_class_t* nasl_plugin_init(struct arglist* prefs,
				    struct arglist* nasl) {
    return &nasl_plugin_class;
}



static void nasl_thread(struct arglist *);


/** 
 * Add *one* .nasl plugin to the plugin list and return the pointer to it.
 * The plugin is first attempted to be loaded from the cache (.desc) calling
 * load_store_plugin. If that fails, it is parsed (via exec_nasl_script).
 * @param folder Path to the plugin folder.
 * @param name File-name of the plugin.
 * @param plugins The arglist that the plugin shall be added to.
 * @param preferences The plugins preferences.
 * @return Pointer to the plugin (as arglist). NULL in case of errors.
 */
static struct arglist *
nasl_plugin_add(char* folder, char* name, struct arglist* plugins, 
               struct arglist* preferences)
{
 char fullname[PATH_MAX+1];
 struct arglist *plugin_args;
 struct arglist * prev_plugin = NULL;
 char * lang = "english";
 int nasl_mode;
 nasl_mode = NASL_EXEC_DESCR;

 snprintf(fullname, sizeof(fullname), "%s/%s", folder, name);

 if ( preferences_nasl_no_signature_check(preferences) > 0 )
  {
    nasl_mode |= NASL_ALWAYS_SIGNED;
  }
 

 if(arg_get_type(preferences, "language")>=0)
  lang = arg_get_value(preferences, "language");

 plugin_args = store_load_plugin(folder, name, preferences);
 if ( plugin_args == NULL )
 {
   char* sign_fprs = nasl_extract_signature_fprs( fullname );
   // If server accepts signed plugins only, discard if signature file missing.
   if(preferences_nasl_no_signature_check(preferences) == 0 && sign_fprs == NULL)
   {
    printf("%s: nvt is not signed and thus ignored\n", fullname);
    return NULL;
   }
   else if(sign_fprs == NULL)
   {
    sign_fprs = "";
   }

  
   plugin_args = emalloc(sizeof(struct arglist));
   arg_add_value(plugin_args, "preferences", ARG_ARGLIST, -1, (void*)preferences);
   
   if(exec_nasl_script(plugin_args, fullname, nasl_mode) < 0)
   {
    printf("%s could not be loaded\n", fullname);
    arg_set_value(plugin_args, "preferences", -1, NULL);
    arg_free_all(plugin_args);
    return NULL;
   }

   plug_set_path(plugin_args, fullname);

   plug_set_sign_key_ids(plugin_args, sign_fprs);
   
   if(plug_get_oid(plugin_args) != NULL)
   {
    store_plugin(plugin_args, name);
    plugin_args = store_load_plugin(folder, name, preferences);
   }
 }
 
 if ( plugin_args == NULL ) 
 {
  /* Discard invalid plugins */
  fprintf(stderr, "%s failed to load\n", name);
  return NULL;
 }

 if(plug_get_oid(plugin_args) == NULL)
 {
  plugin_free(plugin_args);
  return NULL;
 }
 
 
 plug_set_launch(plugin_args, LAUNCH_DISABLED);
 prev_plugin = arg_get_value(plugins, name);
 if( prev_plugin == NULL )
  arg_add_value(plugins, name, ARG_ARGLIST, -1, plugin_args);
 else
 {
  plugin_free(prev_plugin);
  arg_set_value(plugins, name, -1, plugin_args);
 }
 
 return plugin_args;
}

/**
 * Launch a NASL plugin
 */
int
nasl_plugin_launch(globals, plugin, hostinfos, preferences, kb, name)
 	struct arglist * globals;
	struct arglist * plugin;
	struct arglist * hostinfos;
	struct arglist * preferences;
	struct kb_item ** kb;
	char * name;
{
 int timeout;
 int category = 0;
 nthread_t module;
 struct arglist * d = emalloc(sizeof(struct arglist));
 
 arg_add_value(plugin, "HOSTNAME", ARG_ARGLIST, -1, hostinfos);
 if(arg_get_value(plugin, "globals"))
   arg_set_value(plugin, "globals", -1, globals);
 else    
   arg_add_value(plugin, "globals", ARG_ARGLIST, -1, globals);
 
 
 arg_set_value(plugin, "preferences", -1, preferences);
 arg_add_value(plugin, "key", ARG_PTR, -1, kb);

 arg_add_value(d, "args", ARG_ARGLIST, -1, plugin);
 arg_add_value(d, "name", ARG_STRING, -1, name);
 arg_add_value(d, "preferences", ARG_STRING, -1, preferences);
 
 category = plug_get_category(plugin); 
 timeout = preferences_plugin_timeout(preferences, plug_get_oid(plugin));
 if( timeout == 0 )
 {
  if(category == ACT_SCANNER)
  	timeout = -1;
  else 
  	timeout = preferences_plugins_timeout(preferences);
 }

 module = create_process((process_func_t)nasl_thread, d); 
 arg_free(d);
 return module;
}


static void 
nasl_thread(g_args) 
 struct arglist * g_args;
{
 struct arglist * args = arg_get_value(g_args, "args");
 struct arglist * globals = arg_get_value(args, "globals");
 struct arglist * preferences = arg_get_value(g_args, "preferences");
 char * name = arg_get_value(g_args, "name");
 int soc = GPOINTER_TO_SIZE(arg_get_value(args, "SOCKET"));
 int i;
 int nasl_mode;
 
 
 if(preferences_benice(NULL))nice(-5);
 /* XXX ugly hack */
 soc = dup2(soc, 4);
 if ( soc < 0 )
 {
  log_write("dup2() failed ! - can not launch the plugin\n");
  return;
 }
 arg_set_value(args, "SOCKET", sizeof(gpointer), GSIZE_TO_POINTER(soc));
 arg_set_value(globals, "global_socket", sizeof(gpointer), GSIZE_TO_POINTER(soc));
 for(i=5;i<getdtablesize();i++)
 {
  close(i);
 }
 #ifdef RLIMIT_RSS	 
  {	 
  struct rlimit rlim;	 
  getrlimit(RLIMIT_RSS, &rlim);	 
  rlim.rlim_cur = 1024*1024*512;	 
  rlim.rlim_max = 1024*1024*512;	 
  setrlimit(RLIMIT_RSS, &rlim);	 
  }	 
 #endif	 
 	 
 #ifdef RLIMIT_AS	 
  {	 
  struct rlimit rlim;	 
  getrlimit(RLIMIT_AS, &rlim);	 
  rlim.rlim_cur = 1024*1024*512;	 
  rlim.rlim_max = 1024*1024*512;	 
  setrlimit(RLIMIT_AS, &rlim);	 
  }	 
 #endif	 
 	 
 #ifdef RLIMIT_DATA	 
  {	 
  struct rlimit rlim;	 
  getrlimit(RLIMIT_DATA, &rlim);	 
  rlim.rlim_cur = 1024*1024*512;	 
  rlim.rlim_max = 1024*1024*512;	 
  setrlimit(RLIMIT_DATA, &rlim);	 
  }	 
 #endif
 setproctitle("testing %s (%s)", (char*)arg_get_value(arg_get_value(args, "HOSTNAME"), "NAME"), (char*)arg_get_value(g_args, "name"));
 signal(SIGTERM, _exit);
 
 nasl_mode = NASL_EXEC_DONT_CLEANUP;
 if ( preferences_nasl_no_signature_check(preferences) > 0 )
	nasl_mode |= NASL_ALWAYS_SIGNED;

 exec_nasl_script(args, name, nasl_mode);
 internal_send(soc, NULL, INTERNAL_COMM_MSG_TYPE_CTRL | INTERNAL_COMM_CTRL_FINISHED);
}

/**
 * The NASL NVT class.
 */
pl_class_t nasl_plugin_class = {
    NULL,
    ".nasl",
    nasl_plugin_init,
    nasl_plugin_add,
    nasl_plugin_launch,
};
