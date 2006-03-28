/* Nessus
 * Copyright (C) 1998 - 2004 Renaud Deraison
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
 *
 * Preferences  -- maps the content of the nessusd.conf file to memory
 *
 */
 
#include <includes.h>
#include "comm.h"
#include "preferences.h"
#include "log.h"
#include "utils.h"
#include "hosts_gatherer.h"

#ifdef USE_AF_UNIX
#undef NESSUS_ON_SSL
#endif


#define inited(x) ((x) >= 0)

/* 
 * Initializes the preferences structure 
 */
int preferences_init(config_file, prefs)
	char * config_file;
	struct arglist ** prefs;
{
  int result;
  *prefs = emalloc(sizeof(struct arglist));
  result = preferences_process(config_file, *prefs);
  return(result);
}

 
/*
 * Creates a new preferences file
 */
int preferences_new(char * name)
{
  FILE * fd;
  int f;

  if((f = open(name, O_CREAT | O_RDWR | O_EXCL, 0660))<0){
    perror("preferences_new():open ");
    return(-1);
  }

  fd = fdopen(f, "w");
  
 fprintf(fd, "# Configuration file of the Nessus Security Scanner\n\n\n\n");
 fprintf(fd, "# Every line starting with a '#' is a comment\n\n");
 fprintf(fd, "# Path to the security checks folder : \n");
 fprintf(fd, "plugins_folder = %s\n\n", NESSUSD_PLUGINS);
 fprintf(fd, "# Maximum number of simultaneous hosts tested : \n");
 fprintf(fd, "max_hosts = 30\n\n");
 fprintf(fd, "# Maximum number of simultaneous checks against each host tested : \n");
 fprintf(fd, "max_checks = 10\n\n");
 fprintf(fd, "# Niceness. If set to 'yes', nessusd will renice itself to 10.\n");
 fprintf(fd, "be_nice = no\n\n");


 fprintf(fd, "# Log file : \n");
 fprintf(fd, "logfile = %s\n\n", NESSUSD_MESSAGES);
 fprintf(fd, "# Shall we log every details of the attack ?\n");
 fprintf(fd, "log_whole_attack = yes\n\n");
 fprintf(fd, "# Log the name of the plugins that are loaded by the server ?\n");
 fprintf(fd, "log_plugins_name_at_load = no\n\n");
 fprintf(fd, "# Dump file for debugging output, use `-' for stdout\n");
 fprintf(fd, "dumpfile = %s\n\n", NESSUSD_DEBUGMSG);
 fprintf(fd, "# Rules file : \n");
 fprintf(fd, "rules = %s\n\n", NESSUSD_RULES);
 fprintf(fd, "# Users database : \n");
 fprintf(fd, "users = %s\n\n", NESSUSD_USERS);
 fprintf(fd, "# CGI paths to check for (cgi-bin:/cgi-aws:/ can do)\n");
 fprintf(fd, "cgi_path = /cgi-bin:/scripts\n\n");
 fprintf(fd, "# Range of the ports the port scanners will scan : \n");
 fprintf(fd, "# 'default' means that Nessus will scan ports found in its\n");
 fprintf(fd, "# services file.\n");
 fprintf(fd, "port_range = default\n\n");
 fprintf(fd, "# Optimize the test (recommanded) : \n");
 fprintf(fd, "optimize_test = yes\n\n");
 fprintf(fd, "# Language of the plugins :\n");
 fprintf(fd, "language = %s\n\n", NESSUSD_LANGUAGE);

 fprintf(fd, "\n\n# Optimization : \n");
 fprintf(fd, "# Read timeout for the sockets of the tests : \n");
 fprintf(fd, "checks_read_timeout = 5\n");
 fprintf(fd, "# Ports against which two plugins should not be run simultaneously :\n");
 fprintf(fd, "# non_simult_ports = Services/www, 139, Services/finger\n");
 fprintf(fd, "non_simult_ports = 139, 445\n");
 fprintf(fd, "# Maximum lifetime of a plugin (in seconds) : \n");
 fprintf(fd, "plugins_timeout = %d\n", PLUGIN_TIMEOUT);
 fprintf(fd, "\n\n# Safe checks rely on banner grabbing :\n");
 fprintf(fd, "safe_checks = yes\n");
 fprintf(fd, "\n\n# Automatically activate the plugins that are depended on\n");
 fprintf(fd, "auto_enable_dependencies = yes\n");
 fprintf(fd, "\n\n# Do not echo data from plugins which have been automatically enabled\n");
 fprintf(fd, "silent_dependencies = yes\n");
 fprintf(fd, "\n\n# Designate hosts by MAC address, not IP address (useful for DHCP networks)\n");
 fprintf(fd, "use_mac_addr = no\n");
 
 fprintf(fd, "\n\n#--- Knowledge base saving (can be configured by the client) :\n");
 fprintf(fd, "# Save the knowledge base on disk : \n");
 fprintf(fd, "save_knowledge_base = no\n");
 fprintf(fd, "# Restore the KB for each test :\n");
 fprintf(fd, "kb_restore = no\n");
 fprintf(fd, "# Only test hosts whose KB we do not have :\n");
 fprintf(fd, "only_test_hosts_whose_kb_we_dont_have = no\n");
 fprintf(fd, "# Only test hosts whose KB we already have :\n");
 fprintf(fd, "only_test_hosts_whose_kb_we_have = no\n");
 fprintf(fd, "# KB test replay :\n");
 fprintf(fd, "kb_dont_replay_scanners = no\n");
 fprintf(fd, "kb_dont_replay_info_gathering = no\n");
 fprintf(fd, "kb_dont_replay_attacks = no\n");
 fprintf(fd, "kb_dont_replay_denials = no\n");
 fprintf(fd, "kb_max_age = 864000\n");
 fprintf(fd, "#--- end of the KB section\n\n");
 fprintf(fd, "# Can users upload their plugins ?\n");
 fprintf(fd, "plugin_upload = no\n");
 fprintf(fd, "# Suffixes of the plugins the user can upload :\n");
 fprintf(fd, "plugin_upload_suffixes = .nasl, .inc\n");
 fprintf(fd, "# Name of the user who can remotely update the plugins\n");
 fprintf(fd, "admin_user = root\n");
 
 fprintf(fd, "\n\n");
 fprintf(fd, "# If this option is set, Nessus will not scan a network incrementally\n");
 fprintf(fd, "# (10.0.0.1, then 10.0.0.2, 10.0.0.3 and so on..) but will attempt to\n");
 fprintf(fd, "# slice the workload throughout the whole network (ie: it will scan\n");
 fprintf(fd, "# 10.0.0.1, then 10.0.0.127, then 10.0.0.2, then 10.0.0.128 and so on...\n");
 fprintf(fd, "slice_network_addresses = no\n\n");
 
 fprintf(fd, "# Should consider all the NASL scripts as being signed ? (unsafe if set to 'yes')\n");
 fprintf(fd, "nasl_no_signature_check = no\n\n");
 fprintf(fd, "#end.\n");
 
  fclose(fd);
  close(f);
  return(0);
}


/*
 * Copies the content of the prefs file to
 * a special arglist
 */
int preferences_process(filename,prefs)
     char * filename;
     struct arglist * prefs;
{
  FILE * fd;
  char buffer[1024];
  char * opt, *value;
    if(filename)
      {
        check_symlink(filename);
	if(!(fd = fopen(filename, "r"))) {
#ifndef NESSUSNT
	 if(errno == EACCES)
	 {
	  print_error(
	  	"The Nessus daemon doesn't have the right to read %s\n", filename);
	  DO_EXIT(1);
	 }
#endif

#ifdef DEBUG
	  print_error("Couldn't find any prefs file... Creating a new one...\n");
#endif 
	  if(preferences_new(filename)){
	    print_error("Error creating %s\n", filename);
	    exit(1);
	    arg_add_value(prefs, "plugins_folder", ARG_STRING,
			  strlen("./plugins"), "./plugins");
	    return(1);
	  }
	  else
	    if(!(fd = fopen(filename, "r")))
	      {
	        perror("preferences_process():open ");
		print_error("Could not open %s -- now quitting\n", filename);
		DO_EXIT(2);
	      }
	}
	
	while(!feof(fd) && fgets(buffer, sizeof(buffer) - 1,fd))
	  {
	   char * t;
	   int len;
	   
	   buffer[sizeof(buffer) - 1] = '\0';
	   len = strlen(buffer);
	   
	   if(buffer[len-1]=='\n')
	    {
	     buffer[len-1]=0;
	     len --;
	    }
	   
	    if(buffer[0]=='#')continue;
	    opt = buffer;
	    t = strchr(buffer, '=');
	    if( t == NULL )continue;
	    else {
	      t[0]=0;
	      t+=sizeof(char);
	      while(t[0]==' ')t+=sizeof(char);
	      len = strlen(opt);
	      while(opt[len-1]==' ')
	      {
	       opt[len-1]= '\0';
	       len --;
	      }
	      
	      len = strlen(t);
	      while(t[len-1]==' ')
	      {
	       t[len-1]= '\0';
	       len --;
	      }
	      
	      value = emalloc(len + 1);
	      strncpy(value, t, len);
	      arg_add_value(prefs, opt, ARG_STRING, strlen(value), value);
#ifdef DEBUGMORE
	      printf("%s = %s\n", opt, value);
#endif
	    }
     	 }
    fclose(fd);	 
    return(0);
    }
   else return(1);
}
 
 
int preferences_get_host_expansion(preferences)
	struct arglist * preferences;
{
 char * pref;
 static int ret = -1;

 
 if(!preferences)
  {
   ret = -1;
   return -1;
  }
  
 if( ret >= 0 )
  return ret;
 
 ret = 0;
 pref = arg_get_value(preferences, "host_expansion");
 if(!pref)ret = HG_SUBNET;
 else
 {
 if(strstr(pref, "dns"))ret = ret | HG_DNS_AXFR;
 if(strstr(pref, "nfs"))ret = ret | HG_NFS;
 if(strstr(pref, "ip"))ret = ret |  HG_SUBNET;
 }
 
 pref = arg_get_value(preferences, "reverse_lookup");
 if(pref && strstr(pref, "yes"))ret = ret | HG_REVLOOKUP;
 return ret;
}

int preferences_get_slice_network_addresses(preferences)
 struct arglist * preferences;
{
 char * str;
 
 if( preferences == NULL )
 	return 0;
	
 str  = arg_get_value(preferences, "slice_network_addresses");
 if( str == NULL ) 
 	return 0;
	
 return strcmp(str, "yes" ) == 0;
}


int preferences_get_checks_read_timeout(preferences)
 struct arglist *preferences;
{
 char * pref;
 static int ret = -1;
 
  if(!preferences)
  {
   ret = -1;
   return -1;
  }
  
  
 if(ret >= 0)
  return ret;
 
 pref = arg_get_value(preferences, "checks_read_timeout");
 if(pref){
 	ret = atoi(pref);
	if(!ret)ret = 15;
	}
 else ret = 15;
 return ret;
}


int preferences_log_whole_attack(preferences)
 struct arglist * preferences;
{
 char * value;
 static int yes = -1;
 
  if(!preferences)
  {
   yes = -1;
   return -1;
  }
  
  
 if(yes >= 0)
  return yes;
  
 value = arg_get_value(preferences, "log_whole_attack");
 if(value && strcmp(value, "yes"))
 {
  yes = 0;
 }
 else yes = 1;
 
 return yes;
}

int preferences_optimize_test(preferences)
 struct arglist * preferences;
{
  static int yes = -1;
  char * optimize_asc;
  
   if(!preferences)
  {
   yes = -1;
   return -1;
  }
  
  
  if(yes >= 0)
   return yes;
   
  optimize_asc =  arg_get_value(preferences, "optimize_test");
  if(optimize_asc && !strcmp(optimize_asc, "no"))
  	yes = 0;
  else 
  	yes = 1;	
	
  return yes;
}




int
preferences_log_plugins_at_load(preferences)
  struct arglist * preferences;
{
  static int yes = -1;
  char * pref;
  
  if(!preferences)
  {
   yes = -1;
   return -1;
  }
  
  
  if(yes >= 0)
   return yes;
   
  pref = arg_get_value(preferences, "log_plugins_name_at_load");
  if(pref && !strcmp(pref, "yes"))
  	yes = 1;
  else
  	yes = 0;

  return yes;
}
int   
preferences_ntp_show_end(preferences)
 struct arglist * preferences;
{
 static int yes = -1;
 char * pref;
 
  if(!preferences)
  {
   yes = -1;
   return -1;
  }
  
  
 if(yes >= 0)
  return yes;
  
 pref = arg_get_value(preferences, "ntp_opt_show_end");
 if(pref && !strcmp(pref, "yes"))
  yes = 1;
 else
  yes = 0;
  
 return yes;
}

int
preferences_plugins_timeout(preferences)
 struct arglist * preferences;
{
 static int to = -1;
 char * pref;
 
 if(!preferences)
  {
   to = -1;
   return -1;
  }
  
  
 if(to >= 0)
  return to;
  
 pref = arg_get_value(preferences, "plugins_timeout");
 if(pref)
 {
   to = atoi(pref);
   if( to == 0 ) to = PLUGIN_TIMEOUT;
 }
 else
   to = PLUGIN_TIMEOUT;
   
 return to;
}


int
preferences_plugin_timeout(preferences, id)
 struct arglist * preferences;
 int id;
{
 int ret = 0;
 char * pref_name = emalloc(strlen("timeout.") + 40);
 
 sprintf(pref_name, "timeout.%d", id);
 if(arg_get_type(preferences, pref_name) == ARG_STRING)
 {
  int to = atoi(arg_get_value(preferences, pref_name));
  if(to)ret = to;
 }
 efree(&pref_name);
 return ret;
}

int
preferences_benice(preferences)
 struct arglist * preferences;
{
 char * pref;
 static int yes = -1;
 
 if( preferences == NULL )
  {
   return yes;
  }
  
  
 if(yes >= 0) 
  return yes;
 
 pref = arg_get_value(preferences, "be_nice");
 if(pref && !strcmp(pref, "yes"))
 	 yes = 1;
 else
 	 yes = 0;

 return yes;
}


int 
preferences_save_session(preferences)
 struct arglist * preferences;
{
 static int yes = -1;
 char * pref;
 
 if(!preferences)
  {
   yes = -1;
   return -1;
  }
  
  
 if(yes >= 0)
  return yes;
  
 pref = arg_get_value(preferences, "save_session");
 if(pref && !strcmp(pref, "yes"))
  yes = 1;
 else
  yes = 0;
  
  return yes;
}

int 
preferences_save_empty_sessions(preferences)
 struct arglist * preferences;
{
 static int yes = -1;
 char * pref;
 
 if(!preferences)
  {
   yes = -1;
   return -1;
  }
  
  
 if(yes >= 0)
  return yes;
  
 pref = arg_get_value(preferences, "save_empty_sessions");
 if(pref && !strcmp(pref, "yes"))
  yes =  1;
 else
  yes = 0;
  
 return yes == 1;
}


int
preferences_autoload_dependencies(preferences)
 struct arglist * preferences;
{
 static int yes = -1;
 char * pref;
 
 if(!preferences)
  {
   yes = -1;
   return -1;
  }
  
  
 if(yes >= 0)
  return yes;
  
 pref = arg_get_value(preferences, "auto_enable_dependencies");
 if(pref && !strcmp(pref, "yes"))
  yes = 1;
 else
  yes = 0;
  
 return yes;
}



int
preferences_safe_checks_enabled(preferences)
 struct arglist * preferences;
{
 static int yes = -1;
 char * value;
 
 if(!preferences)
  {
   yes = -1;
   return -1;
  }
  
  
 if(yes >= 0)
   return yes;
 value = arg_get_value(preferences, "safe_checks");
 if(value && !strcmp(value, "yes"))
  	yes = 1;
 else
 	yes = 0;
 
 return yes;
}


int
preferences_use_mac_addr(preferences)
 struct arglist * preferences;
{
 static int yes = -1;
 char * value;

if(!preferences)
  {
   yes = -1;
   return -1;
  }
  
  
 if(yes >= 0)
  return yes;
 
 value = arg_get_value(preferences, "use_mac_addr");
 if(value && !strcmp(value, "yes"))
 	yes = 1;
 else
 	yes = 0;

 return yes;
}

int
preferences_upload_enabled(preferences)
 struct arglist * preferences;
{
 static int yes = -1;
 char * value;

 if(!preferences)
  {
   yes = -1;
   return -1;
  }
  
  
 if(yes >= 0)
  return yes;
 
 value = arg_get_value(preferences, "plugin_upload");
 if(value && !strcmp(value, "yes"))
 	yes = 1;
 else
 	yes = 0;
 
 return yes;
}

int
preferences_upload_suffixes(preferences, fname)
 struct arglist * preferences;
 char * fname;
{
 char * list = arg_get_value(preferences, "plugin_upload_suffixes");
 char * fsuffix; 
 char * delme;

 if(!list)
  return 0;
 else
  delme = list = estrdup(list);
  
 fsuffix = strrchr(fname, '.');
 if(!fsuffix)
  return 0;

 
 for(;;)
 {
  char * t = strchr(list, ',');
  int len;
  if(t)
   t[0]='\0';
  
  len = strlen(list);
  while(list[len - 1] == ' ')
  {
  	list[len - 1]='\0';
	len --;
  }
  
  while(list[0]==' ')list++;
  if(!strcmp(list, fsuffix))
  {
   efree(&delme);
   return 1;
  }
 
 if(t)list = &(t[1]);
 else break;
 }
 log_write("user attempted to upload %s\n", fname);
 efree(&delme);
 return 0;
}


int
preferences_nasl_no_signature_check(preferences)
 struct arglist * preferences;
{
 static int yes = -1;
 char * pref;
 
 if(!preferences)
  {
   yes = -1;
   return -1;
  }
  
  
 if(yes >= 0)
  return yes;
  
  
 pref = arg_get_value(preferences, "nasl_no_signature_check");
 if(pref && !strcmp(pref, "yes"))
   yes = 1;
 else
   yes = 0;

 return yes;
}

int
preferences_detached_scan(preferences)
 struct arglist * preferences;
{
 static int yes = -1;
 char * pref;
 
 if(!preferences)
  {
   yes = -1;
   return -1;
  }
  
  
 if(yes >= 0)
  return yes;
  
  
 pref = arg_get_value(preferences, "detached_scan");
 if(pref && !strcmp(pref, "yes"))
   yes = 1;
 else
   yes = 0;

 return yes;
}


int
preferences_continuous_scan(preferences)
 struct arglist * preferences;
{ 
 static int yes = -1;
 char * pref;
 
 if(!preferences)
  {
   yes = -1;
   return -1;
  }
  
  
 if(yes >= 0)
  return yes;
 
 pref = arg_get_value(preferences, "continuous_scan");
 if(pref && !strcmp(pref, "yes"))
   yes = 1;
 else
   yes = 0;
 
 return yes;
}


int
preferences_report_killed_plugins(preferences)
 struct arglist * preferences;
{ 
 static int yes = -1;
 char * pref;
 
 if(!preferences)
  {
   yes = -1;
   return -1;
  }
  
  
 if(yes >= 0)
  return yes;
 
 pref = arg_get_value(preferences, "report_killed_plugins");
 if((!pref) || strcmp(pref, "yes"))
   yes = 0;
 else
   yes = 1;
 
 return yes;
}

int
preferences_delay_between_scans(preferences)
 struct arglist * preferences;
{
 static int delay = -1;
 char * pref;
 
 if(!preferences)
  {
   delay = -1;
   return -1;
  }
  
  
 if(delay >= 0)
  return delay;
  
 pref = arg_get_value(preferences, "delay_between_scan_loops"); 
 if(pref)
 {
  if(atoi(pref)){
  	delay = atoi(pref);
	return delay;
	}
  else
   if(!strcmp(pref, "0")){
   	delay = 0;
   	return delay;
	}
 }
 delay = 3600;
 return delay;
}


int
preferences_user_is_admin(globals, preferences)
 struct arglist * globals;
 struct arglist * preferences;
{ 
 static int yes = -1;
 char * pref;
 static char * user;
 
 if(!user)
  user = (char*)arg_get_value(globals, "user");
 
 if(!preferences)
  {
   yes = -1;
   return -1;
  }
  
  
 if(yes >= 0)
  return yes;
 
 pref = arg_get_value(preferences, "admin_user");
 if((!pref) || strcmp(pref, user))
   yes = 0;
 else
   yes = 1;
 
 return yes;
}


char *
preferences_detached_scan_email(preferences)
 struct arglist * preferences;
{
 char * pref = arg_get_value(preferences, "detached_scan_email_address");

 if(pref && pref[0] != '\0' && strcmp(pref, "no"))
  return pref;
 else
  return NULL;
}


int
preferences_silent_dependencies(preferences)
 struct arglist * preferences;
{
 static int yes = -1;
 char * pref;
 
 if(!preferences)
  {
   yes = -1;
   return -1;
  }
  
  
 if(yes >= 0)
  return yes;
  
  
 pref = arg_get_value(preferences, "silent_dependencies");
 if(pref && !strcmp(pref, "yes"))
   yes = 1;
 else
   yes = 0;

 return yes;
}


#ifdef NESSUS_ON_SSL
char *
preferences_get_string(preferences, name)
 struct arglist * preferences;
 char		*name;
{
 char * pref = arg_get_value(preferences, name);

 if(pref && pref[0] != '\0' && strcmp(pref, "no"))
  return pref;
 else
  return NULL;
}

#endif


void
preferences_reset_cache()
{
 preferences_get_host_expansion(NULL);
 preferences_get_checks_read_timeout(NULL);
 preferences_log_whole_attack(NULL);
 preferences_report_killed_plugins(NULL);
 preferences_optimize_test(NULL);
 preferences_ntp_show_end(NULL);
 preferences_log_plugins_at_load(NULL);
 preferences_plugins_timeout(NULL);
 preferences_benice(NULL);
 preferences_autoload_dependencies(NULL);
 preferences_safe_checks_enabled(NULL);
 preferences_use_mac_addr(NULL);
 preferences_save_session(NULL);
 preferences_save_empty_sessions(NULL);
 preferences_upload_enabled(NULL);
 preferences_continuous_scan(NULL);
 preferences_delay_between_scans(NULL);
 preferences_detached_scan(NULL);
 preferences_detached_scan_email(NULL);
 preferences_silent_dependencies(NULL);
}
