/* Nessus
 * Copyright (C) 1998 - 2001 Renaud Deraison
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * In addition, as a special exception, Renaud Deraison
 * gives permission to link the code of this program with any
 * version of the OpenSSL library which is distributed under a
 * license identical to that listed in the included COPYING.OpenSSL
 * file, and distribute linked combinations including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * this file, you may extend this exception to your version of the
 * file, but you are not obligated to do so.  If you do not wish to
 * do so, delete this exception statement from your version.
 *
 * Preferences  -- maps the content of the openvasd.conf file to memory
 *
 */
 
#include <includes.h>
#include "preferences.h"
#include "globals.h"
#include "nessus.h"
#include "error_dialog.h"
static int preferences_new();
static int prefs_buffer_parse(char *, struct arglist *);
static int prefs_add_subcategory(struct arglist *, FILE *);
static void new_pluginset(struct arglist *, struct arglist *);

static int
plugin_id(plugin)
 struct arglist * plugin;
{
 return (int)arg_get_value(plugin, "ID");
}

char *
plugin_asc_id(plugin)
 struct arglist * plugin;
{
 static char asc_id[21];
 char * ret;
 if((ret = arg_get_value(plugin, "ASC_ID")))
  return ret;
 else
 {
  bzero(asc_id, sizeof(asc_id));
  sprintf(asc_id, "%d", plugin_id(plugin));
  arg_add_value(plugin, "ASC_ID", ARG_STRING, strlen(asc_id), asc_id);
  return asc_id;
 }
}



int preferences_init(prefs)
	struct arglist ** prefs;
{
  char * filename;
  int result;
  *prefs = emalloc(sizeof(struct arglist));
  filename = preferences_get_filename();
  result = preferences_process(filename, *prefs);
  /*ENABLE_CRYPTO_LAYER*/
  efree(&filename);
  if (result && getenv ("NESSUSHOME") == 0)
    show_error_and_wait (CANNOT_SET_HOMEVAR);
  return(result);
}

/*
 * TODO : Under NT, the preference file should be put
 * at a propper place 
 * FIXED: nt used peks, which supports that feature
 */


char * 
preferences_get_filename()
{
 if(Alt_rcfile)
 	return estrdup(Alt_rcfile);
 else
  {
    /*ENABLE_CRYPTO_LAYER*/
  char* home;
  char * ret;
  struct passwd * pwd;
  
  home = getenv("NESSUSHOME");
  if ( home == NULL ) home = getenv("HOME");
  if(home)
  {
   ret = emalloc(strlen(home)+strlen("/.nessusrc")+1);
   sprintf(ret, "%s/.nessusrc", home);
   return(ret);
  }
  pwd = getpwuid(getuid());
  if (pwd && pwd->pw_dir)
  {
   ret = emalloc(strlen(pwd->pw_dir)+strlen("/.nessusrc")+1);
   sprintf(ret, "%s/.nessusrc", pwd->pw_dir);
   return(ret);
  } 
  return(NULL);
 }
}


char * 
preferences_get_altname(ext)
     const char	*ext;
{
  char* home;
  char * ret;
  struct passwd * pwd;
  int	l = (ext == NULL) ? 0 : strlen(ext) + 1;
  
  home = getenv("NESSUSHOME");
  if ( home == NULL ) home = getenv("HOME");
  if(home == NULL)
    {
      pwd = getpwuid(getuid());
      if (pwd != NULL && pwd->pw_dir != NULL)
	home = pwd->pw_dir;
      else
	return NULL;
    }

  ret = emalloc(strlen(home)+strlen("/.nessusrc")+l+1);
  if (ret == NULL)
    return NULL;
  if (ext == NULL)
    sprintf(ret, "%s/.nessusrc", home);
  else
    sprintf(ret, "%s/.nessusrc.%s", home, ext);
  return ret;
}


 
static int preferences_new()
{
  FILE * f;
  char * fn = preferences_get_filename();
  if(!fn)return(-1);
 
  if(!(f = fopen(fn, "w")))
      {
        show_error_and_wait(strerror(errno));
	return -1;
      }
  fprintf(f,"# Nessus Client Preferences File\n\n");
  fprintf(f, "trusted_ca = %s/cacert.pem\n", NESSUSD_CA);
  fprintf(f, "begin(SCANNER_SET)\n");
  fprintf(f, "10180 = yes\n");
  fprintf(f, "10278 = no\n");
  fprintf(f, "10331 = no\n");
  fprintf(f, "10335 = yes\n");
  fprintf(f, "10841 = no\n");
  fprintf(f, "10336 = no\n");
  fprintf(f, "10796 = no\n");
  fprintf(f, "11219 = no\n");
  fprintf(f, "14259 = no\n");
  fprintf(f, "14272 = no\n");
  fprintf(f, "14274 = no\n");
  fprintf(f, "14663 = no\n");
  fprintf(f, "end(SCANNER_SET)\n\n");


  fprintf(f, "begin(SERVER_PREFS)\n");
  fprintf(f, " max_hosts = 20\n");
  fprintf(f, " max_checks = 4\n");
  fprintf(f, "end(SERVER_PREFS)\n");


  fclose(f);
  chmod(fn, 0600);
  efree(&fn);
  return(0);
}

int preferences_process(filename,prefs)
     char * filename;
     struct arglist * prefs;
{
  FILE * fd;
  char * buffer;
    if(filename)
      {
        chmod(filename, 0600);
	if(!(fd = fopen(filename, "r"))) {
#ifndef NESSUSNT
	 if(errno == EACCES)
	 {
	  char * buf = malloc(255 + strlen(filename));
	  sprintf(buf,
	  	"The Nessus client doesn't have the right to read %s\n", filename);
	  show_error_and_wait(buf);
	  exit(1);
	 }
#endif
#ifdef DEBUG
	  printf("Couldn't find any prefs file... Creating a new one...\n");
#endif 
	  if((preferences_new())<0){
	    char * buf = malloc(255 + strlen(preferences_get_filename()) + strlen(strerror(errno)));
	    sprintf(buf, "Error creating %s : %s", preferences_get_filename(), strerror(errno));
	     show_error_and_wait(buf);
	    return(1);
	  }
	  else
	    if(!(fd = fopen(filename, "r")))
	      {
	      char * buf = malloc(255 + strlen(preferences_get_filename()) + strlen(strerror(errno)));
	      sprintf(buf, "Error creating %s : %s", preferences_get_filename(), strerror(errno));
	      show_error_and_wait(buf);
	      exit(2);
	      }     

		   
	}
	buffer = emalloc(4096);
	while(!feof(fd) && fgets(buffer, 4096,fd))
	  {
	   if(strchr(buffer, '='))
	    prefs_buffer_parse(buffer, prefs);
	   else if(!strncmp(buffer, "begin(", strlen("begin(")))
	   {
	    char * t = buffer+(strlen("begin(")*sizeof(char));
	    char * end = strchr(t, ')');
	    char * category_name;
	    
	    if(!end)
	    fprintf(stderr, "Parse error in %s : %s\n", filename, buffer);
	    else
	    {
	     struct arglist * subcategory;
	     end[0]=0;
	     category_name = emalloc(strlen(t)+1);
	     strncpy(category_name, t, strlen(t));
	     subcategory = emalloc(sizeof(struct arglist));
	     if(prefs_add_subcategory(subcategory, fd))
	       fprintf(stderr, "Missing 'end' in %s\n", filename);
	     else
	     arg_add_value(prefs, category_name, ARG_ARGLIST, -1, subcategory);
	     }
	    }
     	 }
     fclose(fd);
    return(0);
    }
   else return(1);
}
 
 
static int 
prefs_add_subcategory(arglist, fd)
 struct arglist * arglist;
 FILE * fd;
{
 char * buffer = emalloc(4096);
 int flag = 0;
 
 while(!flag && !feof(fd) && fgets(buffer, 4096,fd))
 {
  if(!strlen(buffer))return(1);
  if((!strcmp(buffer, "end\n"))||(!strncmp(buffer, "end(", 4)))flag = 1;
  else prefs_buffer_parse(buffer, arglist);
  bzero(buffer, 255);
 }
 efree(&buffer);
 return(0);
}
   
static int 
prefs_buffer_parse(buffer, arglist)
 char * buffer;
 struct arglist * arglist;
{
 char * t;
 char * opt;
 char * value;
 int val = -1;
 if(buffer[strlen(buffer)-1]=='\n')buffer[strlen(buffer)-1]=0;
 if(buffer[0]=='#')return(1);
 opt = buffer;
 /* remove the spaces before the pref name */
 if(opt[0]==' ' && opt[0])opt+=sizeof(char);
 if((t = strchr(buffer, '=')))
 {
  t[0]=0;
  t+=sizeof(char);
  while(t[0]==' ' && t[0])t+=sizeof(char);
  if(!t[0])return(1);
  /* remove the spaces after the pref name */
  while(opt[strlen(opt)-1]==' ')opt[strlen(opt)-1]=0;
  
  /* char to int conversion if necessary */
  if(!strcmp(t, "yes"))val = 1;
  if(!strcmp(t, "no"))val = 0;
  
  if(!strcmp(opt, "paranoia_level"))
  {
   arg_add_value(arglist, opt, ARG_INT, sizeof(int), (void*)atoi(t));
  }
  else
  {
  if(val == -1)
  {
   /* the string is not 'yes' nor 'no' so we take it as a string */
   value=emalloc(strlen(t)+1);
   strncpy(value, t, strlen(t));
   arg_add_value(arglist, opt, ARG_STRING, strlen(value), value);
  }
  else arg_add_value(arglist, opt, ARG_INT, sizeof(int), (void *)val);
  }
  return(0);
 }
 else return(1);
}


void
preferences_save_fname(filename, plugins)
 char * filename;
 struct arglist * plugins;
{
 FILE * fd;
 struct arglist * t;
 fd = fopen(filename , "w");
 if(!fd)
  {
  fprintf(stderr, "%s could not be opened write only\n", filename);
  efree(&filename);
  return;
  }
 chmod(filename, 0600);
 fprintf(fd, "# This file was automagically created by nessus\n");
 t = Prefs;

 while(t && t->next)
 {
  if((int)t->type==ARG_INT)
   {
   if(!strcmp(t->name, "paranoia_level"))
    fprintf(fd, "%s = %d\n", t->name, (int)t->value);
   else
    fprintf(fd, "%s = %s\n", t->name, t->value?"yes":"no");
   }
  else if((t->type == ARG_STRING)&&(strlen(t->value)))
  	fprintf(fd, "%s = %s\n",t->name, (char *)t->value);
  t = t->next;
 }
 
 t = Prefs;
 
 while(t && t->next)
 {
  if(t->type == ARG_ARGLIST)
  {
   struct arglist * v;
   v = t->value;
   fprintf(fd, "begin(%s)\n", t->name);
   while(v && v->next)
   {
    if(!strcmp(v->name, "plugin_set")){
      v = v->next;
      continue;
      }
    if(v->type==ARG_INT)
     fprintf(fd, " %s = %s\n", v->name, v->value?"yes":"no");
    else 
     {
      if((v->type == ARG_STRING)&&v->value)
       {
        if(!strcmp(t->name, "PLUGINS_PREFS"))
    		fprintf(fd, " %s = %s\n", v->name, (char *)v->value);
        else 
	{
	 if(strlen((char*)v->value))
		fprintf(fd, " %s = %s\n", v->name, (char *)v->value);
	}
       }
     }
     v = v->next;
   }
  fprintf(fd, "end(%s)\n\n", t->name);
  }
  t = t->next;
 }
  fclose(fd);
}
void
preferences_save(plugins)
 struct arglist * plugins;
{
 preferences_save_fname(preferences_get_filename(), plugins);
}


int
pluginset_apply(plugins, name)
 struct arglist * plugins;
 char * name;
{
 int ret = 0;
 while(plugins && plugins->next)
 {
  int flag = 0;
  struct arglist * t = arg_get_value(Prefs, name);
  
  
  if(!t)return 1;
  
  while(!flag && t && t->next)
  {
   if(!strcmp(plugin_asc_id(plugins->value), t->name))
    {
     plug_set_launch(plugins->value, (int)t->value);
     flag = 1;
    }
    t = t->next;
   }
   /* we do not know anything about this current plugin */
   if(!flag)
   {
    char * c = arg_get_value(plugins->value, "CATEGORY");
    printf("%s is unknown to us\n", plugins->name);
    if(c && (!strcmp(c, "denial")||
	     ! strcmp(c, "kill_host") ||
	     ! strcmp(c, "flood") ||
	     ! strcmp(c, "scanner") ||
    	     !strcmp(c, "destructive_attack")))plug_set_launch(plugins->value, 0);
    else plug_set_launch(plugins->value, 1);
    ret++;
   }
   plugins = plugins->next;
  }
  return ret;
 }
 

#define MAGIC 8197
struct hash {
	int name;
	struct arglist * v;
	struct hash * next;
};

static struct arglist * hash_get ( struct hash ** hash, int id )
{
 int idx = id % MAGIC;
 struct hash * h = hash[idx];
 while ( h != NULL ) 
 {
  if ( h->name == id ) return h->v;
  h = h->next;
 }
 return NULL;
}



void
pluginset_reload(plugins, scanners)
 struct arglist * plugins;
 struct arglist * scanners;
{
  struct arglist * t = arg_get_value(Prefs, "PLUGIN_SET");
  static struct hash ** p_hash = NULL, ** s_hash = NULL;
  int flag = 0;

  
  if(!t){
   t = emalloc(sizeof(struct arglist));
   new_pluginset(t, plugins);
   arg_add_value(Prefs, "PLUGIN_SET", ARG_ARGLIST, -1, t);
   }

 if ( p_hash == NULL )
 {
 p_hash  = emalloc ( MAGIC * sizeof(struct hash*));
 while ( t->next != NULL )
  {
  struct hash * h; 
  int id = atoi(t->name);
  int idx = id % MAGIC;

  h = emalloc(sizeof(struct hash));
  h->name = id;
  h->v = t;
  h->next =  p_hash[idx];
  p_hash[idx] = h;
  t = t->next;
  if ( ( t == NULL || t->next == NULL )  && flag == 0 )
	{
	t = arg_get_value(Prefs, "SCANNER_SET");
	if ( t == NULL ) break;
	flag ++;
	}
  }
 }
  
if ( plugins != NULL ) 
 while( plugins->next != NULL )
 {
  int p_id = (int)arg_get_value(plugins->value, "ID");
  struct arglist * al = hash_get(p_hash, p_id);
  if ( al != NULL )
	al->value = (void*)plug_get_launch(plugins->value);
  plugins = plugins->next;
 }
  
 
 t = arg_get_value(Prefs, "SCANNER_SET");
 if( t == NULL ){
   t = emalloc(sizeof(struct arglist));
   new_pluginset(t, scanners);
   arg_add_value(Prefs, "SCANNER_SET", ARG_ARGLIST, -1, t);
   }
 if ( s_hash == NULL )
 {
 s_hash  = emalloc ( MAGIC * sizeof(struct hash*));
 while ( t->next != NULL )
  {
  struct hash * h; 
  int id = atoi(t->name);
  int idx = id % MAGIC;

  h = emalloc(sizeof(struct hash));
  h->name = id;
  h->v = t;
  h->next =  s_hash[idx];
  s_hash[idx] = h;
  t = t->next;
  }
 }

 if ( scanners != NULL )
   while( scanners->next != NULL )
 {
  int p_id = (int)arg_get_value(scanners->value, "ID");
  struct arglist * al = hash_get(p_hash, p_id);
  if ( al != NULL )
	al->value = (void*)plug_get_launch(scanners->value);
  scanners =  scanners->next;
 }


}


static void new_pluginset(pluginset, plugins)
 struct arglist * pluginset;
 struct arglist * plugins;
{
 while(plugins && plugins->next)
 {
  char * name = emalloc(20);
  sprintf(name, "%d", plugin_id(plugins->value));
  arg_add_value(pluginset, name, ARG_INT, sizeof(int),
  	 (void *)plug_get_launch(plugins->value));
  plugins = plugins->next;
 }
}


void prefs_check_defaults(prefs)
 struct arglist * prefs;
{
}


int
preferences_generate_new_file()
{
 preferences_new();
 preferences_init(&Prefs);
 pluginset_reload(Plugins, Scanners);
 preferences_save(Prefs);
 return 0;
}
 
