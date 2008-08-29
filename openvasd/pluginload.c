/* OpenVAS
* $Id$
* Description: Loads plugins from disk into memory.
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
#include "utils.h"
#include "pluginload.h"
#include "log.h"
#include "preferences.h"
#include "users.h"

static pl_class_t* plugin_classes = NULL;


struct files {
	char * fname;
	struct files * next;
	};
	

#define MAX_FILES 5731


struct files ** files_init()
{
 struct files ** ret;
 int i;
 srand(MAX_FILES);
 ret = emalloc(sizeof(*ret) * (MAX_FILES + 1));
 for(i=0;i<MAX_FILES;i++)
 	ret[i] = NULL;
 return ret;
}

void files_add(struct files ** files, char * fname)
{
 struct files * f;
 int idx;

 f = emalloc(sizeof(*f));
 idx = rand() % MAX_FILES;
 f->fname = estrdup(fname);
 f->next = files[idx];
 files[idx] = f;
}

char * files_walk(struct files ** files, int * idx)
{
 int i = *idx;
 struct files * myfile;
 static char ret[1024];
 
 while(files[i] == NULL)
 {
  i ++;
  if(i >= MAX_FILES)break;
 }
 
 if(files[i] == NULL)
  return NULL;

 *idx = i;
 
 myfile = files[i];
 files[i] = myfile->next;
 strncpy(ret, myfile->fname, sizeof(ret) - 1);
 ret[sizeof(ret) - 1] = '\0';
 

 efree(&myfile->fname);
 efree(&myfile);
 return ret;
}

void files_close(struct files ** files)
{
 int i;
 for(i=0;i<MAX_FILES;i++)
  if(files[i])printf("Warning, forgot some files!!\n");
 
 efree(&files);
 srand(time(NULL));
}





/*
 * main function for loading all the
 * plugins that are in folder <folder>
 */
struct arglist * 
plugins_init(preferences, be_quiet)
 struct arglist * preferences;
 int be_quiet;
{

 
 return plugins_reload(preferences, emalloc(sizeof(struct arglist)), be_quiet);
}

static void
init_plugin_classes(struct arglist * preferences)
{
  if (plugin_classes == NULL)
    {
      pl_class_t ** cl_pptr = &plugin_classes;
      pl_class_t * cl_ptr;
      int i;
      pl_class_t* classes[] = {&nes_plugin_class, &nasl_plugin_class, &oval_plugin_class, NULL};

      for (i = 0; (cl_ptr = classes[i]); ++i)
	{
	  if ((*cl_ptr->pl_init)(preferences, NULL))
	    {
	      *cl_pptr = cl_ptr;
	      cl_ptr->pl_next = NULL;
	      cl_pptr = &cl_ptr->pl_next;
	    }
	}
    }
}


static struct arglist * 
plugins_reload_from_dir(preferences, plugins, folder, be_quiet)
 struct arglist * preferences;
 struct arglist * plugins;
 char * folder;
 int be_quiet;
{
  DIR * dir;
  struct dirent * dp;
  struct files ** files;
  char * name;
  int idx = 0;
  int n = 0, total = 0, num_files = 0;

  init_plugin_classes(preferences);

  if( folder == NULL)
    {
#ifdef DEBUG
      log_write("%s:%d : folder == NULL\n", __FILE__, __LINE__);
#endif
      printf("Could not determine the value of <plugins_folder>. Check %s\n",
      	(char *)arg_get_value(preferences, "config_file"));
      return plugins;
    }

  if((dir = opendir(folder)) == NULL)
    {
      printf("Couldn't open the directory called \"%s\" - %s\nCheck %s\n", 
      		   folder,
		   strerror(errno),
      		   (char *)arg_get_value(preferences, "config_file"));
		   
      return plugins;
    }
 
 
  files = files_init();
  while( (dp = readdir(dir)) != NULL )
  {
   if(dp->d_name[0] != '.')
	{
   	files_add(files, dp->d_name);
	num_files ++;
	}
  }
  
  rewinddir(dir);
  closedir(dir);
  
  /*
   * Add the the plugins
   */

  if ( be_quiet == 0 ) {
	printf("Loading the OpenVAS plugins...");
	fflush(stdout);
	}
  while((name = files_walk(files, &idx)) != NULL) {
	int len = strlen(name);
	pl_class_t * cl_ptr = plugin_classes;
	

	n ++;
	total ++;
	if ( n > 50 && be_quiet == 0 )
	{
	  n = 0;
	  printf("\rLoading the plugins... %d (out of %d)", total, num_files);
	  fflush(stdout);
	}
	  
	  
	if(preferences_log_plugins_at_load(preferences))
	 log_write("Loading %s\n", name);
	while(cl_ptr) {
         int elen = strlen(cl_ptr->extension);
	 if((len > elen) && !strcmp(cl_ptr->extension, name+len-elen)) {
	 	struct arglist * pl = (*cl_ptr->pl_add)(folder, name,plugins,
							preferences);
   		if(pl) {
			arg_add_value(pl, "PLUGIN_CLASS", ARG_PTR,
			sizeof(cl_ptr), cl_ptr);
		}
		break;
	}
	cl_ptr = cl_ptr->pl_next;
      }
    }
    
  files_close(files);  

  if ( be_quiet == 0 )
	  printf("\rAll plugins loaded                                   \n");
   
 
  return plugins;
}


struct arglist *
plugins_reload(preferences, plugins, be_quiet)
 struct arglist * preferences;
 struct arglist * plugins;
 int be_quiet;
{
 return plugins_reload_from_dir(preferences, plugins, arg_get_value(preferences, "plugins_folder"), be_quiet);
}

struct arglist *
plugins_reload_user(globals, preferences, plugins)
 struct arglist * globals;
 struct arglist * preferences;
 struct arglist * plugins;
{
 char * home = user_home(globals);
 char * plugdir = emalloc(strlen(home) + strlen("plugins") + 2);
 struct arglist * ret;
 sprintf(plugdir, "%s/plugins", home);
 efree(&home);
 ret = plugins_reload_from_dir(preferences, plugins, plugdir, 1);
 efree(&plugdir);
 return ret;
}

void 
plugin_set_socket(struct arglist * plugin, int soc)
{
 if(arg_get_value(plugin, "SOCKET") != NULL)
  arg_set_value(plugin, "SOCKET", sizeof(int), (void*)soc);
 else
  arg_add_value(plugin, "SOCKET", ARG_INT, sizeof(int), (void *)soc);
}

int
plugin_get_socket(struct arglist * plugin)
{
  return (int)arg_get_value(plugin, "SOCKET");
}



void plugin_unlink(plugin)
 struct arglist * plugin;
{
  if(plugin == NULL)
   {
    fprintf(stderr, "Error in plugin_unlink - args == NULL\n");
    return;
   }
  arg_set_value(plugin, "preferences", -1, NULL);
}


void
plugin_free(plugin)
 struct arglist * plugin;
{
 plugin_unlink(plugin);
 arg_free_all(plugin);
}

void
plugins_free(plugins)
 struct arglist * plugins;
{
 struct arglist * p = plugins;
 if(p == NULL)
  return;
 
 while(p->next)
 {
  plugin_unlink(p->value);
  p = p->next;
 }
 arg_free_all(plugins);
}
/*
 * Put our socket somewhere in the plugins
 * arguments
 */
void 
plugins_set_socket(struct arglist * plugins, int soc)
{
  struct arglist * t;

  t = plugins;
  while(t && t->next)
    {
     plugin_set_socket(t->value, soc);
     t = t->next;
    }
}
