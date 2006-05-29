/* OpenVAS
* $Id$
* Description: Launches the plugins, and manages multithreading.
*
* Authors: - Renaud Deraison <deraison@nessus.org> (initial version)
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
#include "attack.h"
#include "log.h"
#include "hosts_gatherer.h"
#include "sighand.h"
#include "rules.h"
#include "auth.h"
#include "processes.h"
#include "comm.h" 
#include "utils.h"
#include "preferences.h"
#include "ntp.h"
#include "ntp_11.h"
#include "pluginload.h"
#include "save_tests.h"
#include "save_kb.h"
#include "detached.h"

#include "pluginscheduler.h"
#include "pluginlaunch.h"
#include "plugs_req.h"
#include "hosts.h"

#define ERR_HOST_DEAD -1
#define ERR_CANT_FORK -2

#define MAX_FORK_RETRIES 10

extern u_short * getpts(char *, int *);

struct attack_start_args {
        struct arglist * globals;
        struct in_addr hostip;
        char * host_mac_addr;
        plugins_scheduler_t sched;
        int thread_socket;
        struct hg_globals * hg_globals;
        char hostname[1024];
};

/*******************************************************

		PRIVATE FUNCTIONS
		
********************************************************/


static void 
fork_sleep(int n)
{
 time_t then, now;
 
 now = then = time(NULL);
 while(now - then < n )
 {
   waitpid(-1, NULL, WNOHANG);
   usleep(10000);
   now = time(NULL);
 }
}
 

static void
attack_sigterm()
{
 hosts_stop_all();
 wait_for_children1();
}


static void 
arg_addset_value(arg, name, type, len, value)
 struct arglist *arg;
 char * name;
 int type, len;
 void * value;
{
 if(arg_get_type(arg, name) < 0)
  arg_add_value(arg, name, type, len, value);
 else
  arg_set_value(arg, name, len, value);
}



/*-------------------------------------------------------

	Init. an arglist which can be used by 
	the plugins from an hostname and its ip
	
--------------------------------------------------------*/	
static struct arglist * 
attack_init_hostinfos(mac, hostname, ip)
     char * mac;
     char * hostname;
    struct in_addr * ip;
{
  struct arglist * hostinfos;
  struct in_addr addr;
  
  hostinfos = emalloc(sizeof(struct arglist));
  if(inet_aton(hostname, &addr) != 0)
  {
   char f[1024];
   hg_get_name_from_ip(addr, f, sizeof(f));
   arg_add_value(hostinfos, "FQDN", ARG_STRING, strlen(f), estrdup(f));
  }
  else
   arg_add_value(hostinfos, "FQDN", ARG_STRING, strlen(hostname), estrdup(hostname));
   
   
  if(mac)
  {
  	arg_add_value(hostinfos, "NAME", ARG_STRING, strlen(mac), mac);
	arg_add_value(hostinfos, "MAC", ARG_STRING, strlen(mac), mac);
  }
  else
  	arg_add_value(hostinfos, "NAME", ARG_STRING, strlen(hostname), estrdup(hostname));
	
  arg_add_value(hostinfos, "IP", ARG_PTR, sizeof(struct in_addr), ip);
  return(hostinfos);
}

/*--------------------------------------------------------
	
		 Return our user name
 
 ---------------------------------------------------------*/
 
static char *
attack_user_name(globals)
 struct arglist * globals;
{
 static char * user;
 if(!user)
   user = (char*)arg_get_value(globals, "user");
  
 return user;
}


static int
launch_plugin(globals, sched, plugin, hostname, cur_plug, num_plugs, hostinfos, kb, new_kb)
 struct arglist * globals;
 plugins_scheduler_t * sched;
 struct scheduler_plugin * plugin;
 char * hostname;
 int *cur_plug, num_plugs;
 struct arglist * hostinfos;
 struct kb_item ** kb;
 int new_kb;
{
  struct arglist * preferences = arg_get_value(globals,"preferences");
  struct arglist * args = plugin->arglist->value;
  char name[1024];
  int optimize = preferences_optimize_test(preferences);
  int category = plugin->category;
  static int last_status = 0;
      
  strncpy(name, plug_get_path(args), sizeof(name) - 1);
  name[sizeof(name) - 1 ] = '\0';

  if(plug_get_launch(args) != LAUNCH_DISABLED || 
     category == ACT_INIT ||
    (category == ACT_SETTINGS)) /* can we launch it ? */
  {
   char * error;
   
   pl_class_t * cl_ptr = arg_get_value(args, "PLUGIN_CLASS");
   
  
  if(preferences_safe_checks_enabled(preferences) && 
  	(category == ACT_DESTRUCTIVE_ATTACK ||
	 category == ACT_KILL_HOST ||
	 category == ACT_FLOOD ||
	 category == ACT_DENIAL))
	 	{
		if(preferences_log_whole_attack(preferences))
		  log_write("user %s : Not launching %s against %s %s (this is not an error)\n",
	       			attack_user_name(globals),
				plugin->arglist->name, 
				hostname, 
				"because safe checks are enabled");
		plugin_set_running_state(sched, plugin, PLUGIN_STATUS_DONE);
		return 0;
		}

   (*cur_plug) ++;
   if ( ( *cur_plug * 100 ) / num_plugs  >= last_status )
   {
    last_status = (*cur_plug * 100 ) / num_plugs  + 2;
    if ( comm_send_status(globals, hostname, "attack", *cur_plug, num_plugs) < 0 )
    {
     /* Could not send our status back to our father -> exit */
     pluginlaunch_stop();
     return ERR_HOST_DEAD;
    }
   }


    if(save_kb(globals))
    {
     int id = plug_get_id(args);
     char asc_id[30];
	 
     snprintf(asc_id, sizeof(asc_id), "Launched/%d", id);
     if(kb_item_get_int(kb, asc_id) > 0 &&
	    !save_kb_replay_check(globals, category))
	  {
	   /* 
	    * XXX determine here if we should skip
	    * ACT_SCANNER, ACT_GATHER_INFO, ACT_ATTACK and ACT_DENIAL
	    */
	   if(preferences_log_whole_attack(preferences))
	    log_write("user %s : Not launching %s against %s %s (this is not an error)\n",
	       			attack_user_name(globals),
				plugin->arglist->name, 
				hostname, 
				"because it has already been launched in the past");
	   plugin_set_running_state(sched, plugin, PLUGIN_STATUS_DONE);			
	   return 0;
	  }
	  else {
                kb_item_add_int(kb, asc_id, 1);
		save_kb_write_int(globals, hostname, asc_id,  1);
		}
       }	     
	
	
	 
	 if(!optimize || !(error = requirements_plugin(kb, plugin, preferences)))
	 {
	  int pid;
	
	 /*
	  * Start the plugin
	  */
	 pid = plugin_launch(globals,sched, plugin, hostinfos, preferences, kb, name, cl_ptr);
	 if(pid  < 0)	
	 	{
		plugin_set_running_state(sched, plugin, PLUGIN_STATUS_UNRUN);
		return ERR_CANT_FORK;
		}
		 
	 if(preferences_log_whole_attack(preferences))
	 	log_write("user %s : launching %s against %s [%d]\n", 
	 				attack_user_name(globals),
					plugin->arglist->name, 
					hostname,
					pid);
					
	 	     
	 /*
	  * Stop the test if the host is 'dead'
	  */	 
        if(kb_item_get_int(kb, "Host/dead") > 0 ||
	   kb_item_get_int(kb, "Host/ping_failed") > 0)
	{
	  log_write("user %s : The remote host (%s) is dead\n",
	  				attack_user_name(globals),
	  				hostname);
	  pluginlaunch_stop();		
	  if(new_kb)save_kb_close(globals, hostname);	
	  if(kb_item_get_int(kb, "Host/ping_failed") > 0)
	  {
	   save_kb_restore_backup(globals, hostname);
	  }
	  
	  plugin_set_running_state(sched, plugin, PLUGIN_STATUS_DONE);				
	  return ERR_HOST_DEAD;
	}
       }
       
       else /* requirements_plugin() failed */
	  {
	   plugin_set_running_state(sched, plugin, PLUGIN_STATUS_DONE);
	   if(preferences_log_whole_attack(preferences))
	    log_write("user %s : Not launching %s against %s %s (this is not an error)\n",
	       			attack_user_name(globals),
				plugin->arglist->name, 
				hostname, 
				error);
	
	  }
      } /* if(plugins->launch) */
      else    
       plugin_set_running_state(sched, plugin, PLUGIN_STATUS_DONE);
       
      return 0;
}

/*--------------------------------------------------------
	
	          Attack _one_ host

----------------------------------------------------------*/	
static void 
attack_host      (globals, hostinfos, hostname,  sched) 
     
     struct arglist * globals;
     struct arglist * hostinfos;
     char * hostname;
     plugins_scheduler_t sched;
{ 

  /*
   * Used for the status
   */
  int num_plugs = 0;
  int cur_plug = 1;
  
  struct kb_item ** kb;
  int new_kb = 0;
  int kb_restored = 0;
 int forks_retry = 0;
 struct arglist * plugins = arg_get_value(globals, "plugins");
 struct arglist * tmp;
 
  setproctitle("testing %s", (char*)arg_get_value(hostinfos, "NAME"));
  
  if(save_kb(globals))
  {
   if( save_kb_exists(globals, hostname) != 0 && 
       save_kb_pref_restore(globals) != 0 )
     {
      save_kb_backup(globals, hostname);
      kb = save_kb_load_kb(globals, hostname);
      kb_restored = 1; 
     }
   else 
    {
     save_kb_new(globals, hostname);
     kb = kb_new();
     new_kb = 1;
    }

  arg_add_value(globals, "CURRENTLY_TESTED_HOST", ARG_STRING, strlen(hostname), hostname);
 }
 else kb = kb_new();
  

 num_plugs = get_active_plugins_number(plugins);
  
  tmp = emalloc(sizeof(struct arglist));
  arg_add_value(tmp, "HOSTNAME", ARG_ARGLIST, -1, hostinfos);
  
    
  /* launch the plugins */
  pluginlaunch_init(globals);
  
   
   for(;;)
   {
    struct scheduler_plugin * plugin;
    pid_t parent;
    
    /*
     * Check that our father is still alive 
     */
    parent = getppid();
    if(parent <= 1 || process_alive(parent) == 0 )
    {
     pluginlaunch_stop();
     return;
    }
     
    plugin = plugins_scheduler_next(sched);
    if(plugin != NULL && plugin != PLUG_RUNNING)
    { 
      int e;
 again:        
      if((e = launch_plugin( globals, sched, plugin, hostname, &cur_plug, num_plugs, hostinfos, kb, new_kb))  < 0)
		    {
		     /*
		      * Remote host died
		      */
		     if(e == ERR_HOST_DEAD)
		     	goto host_died;
		     else if(e == ERR_CANT_FORK )
		     {
		      if(forks_retry < MAX_FORK_RETRIES)
		      {
		       forks_retry++;
		       log_write("fork() failed - sleeping %d seconds (%s)", forks_retry, strerror(errno));
		       fork_sleep(forks_retry);
		       goto again;
		      }
		      else {
		      	log_write("fork() failed too many times - aborting");
			goto host_died;
			}
		     }
		    }
      }
     else if(plugin == NULL) break;
     else pluginlaunch_wait_for_free_process();
    }
  pluginlaunch_wait();
host_died: 
  arg_free(tmp); 
  pluginlaunch_stop();
  plugins_scheduler_free(sched);
  if(new_kb)save_kb_close(globals, hostname);
}

/*-----------------------------------------------------------------

  attack_start : set up some data and jump into
  attack_host()

 -----------------------------------------------------------------*/
static void
attack_start(args)
  struct attack_start_args * args;
{
 struct arglist * globals = args->globals;
 char * hostname = args->hostname;
 char * mac = args->host_mac_addr;
 struct arglist * plugs = arg_get_value(globals, "plugins");
 struct in_addr * hostip = &(args->hostip);
 struct arglist * hostinfos;
 
 struct arglist * preferences = arg_get_value(globals,"preferences");
 char * non_simult = arg_get_value(preferences, "non_simult_ports");
 int thread_socket = args->thread_socket;
 int soc;
 struct timeval then, now;
 plugins_scheduler_t sched = args->sched;
 int i;


 thread_socket = dup2(thread_socket, 4);
 for(i=5;i<getdtablesize();i++)
 {
  close(i);
 }


 gettimeofday(&then, NULL);


 if( non_simult == NULL )
 	{
        non_simult = estrdup("139, 445");
 	arg_add_value(preferences, "non_simult_ports", ARG_STRING, strlen(non_simult), non_simult);
	}
 arg_add_value(preferences, "non_simult_ports_list", ARG_ARGLIST, -1, (void*)list2arglist(non_simult));
 /*
  * Options regarding the communication with our father
  */
 nessus_deregister_connection((int)arg_get_value(globals, "global_socket"));
 arg_set_value(globals, "global_socket", -1, (void*)thread_socket);
 
 /*
  * Wait for the server to confirm it read our data
  * (prevents client desynch)
  */
 arg_add_value(globals, "confirm", ARG_INT, sizeof(int), (void*)1);
 
 soc = thread_socket;
 hostinfos = attack_init_hostinfos(mac, hostname,hostip);
 if(mac)
  hostname = mac;
  

  plugins_set_socket(plugs, soc);
  ntp_1x_timestamp_host_scan_starts(globals, hostname);
  attack_host(globals, hostinfos, hostname, sched);
  if(preferences_ntp_show_end(preferences))ntp_11_show_end(globals, hostname, 1);
  ntp_1x_timestamp_host_scan_ends(globals, hostname);
  gettimeofday(&now, NULL);
  if(now.tv_usec < then.tv_usec)
  {
   then.tv_sec ++;
   now.tv_usec += 1000000;
  }
  log_write("Finished testing %s. Time : %ld.%.2ld secs\n",
  		hostname,
  		(long)(now.tv_sec - then.tv_sec),
		(long)((now.tv_usec - then.tv_usec) / 10000));
  shutdown(soc, 2);		
  close(soc);
}

/*******************************************************

		PUBLIC FUNCTIONS
		
********************************************************/


/*------------------------------------------------

   This function attacks a whole network
 		
 -----------------------------------------------*/
int 
attack_network(globals)
    struct arglist * globals;
{
  int max_hosts			= 0;
  int num_tested		= 0;
  int host_pending		= 0;
  char hostname[1024];
  char * hostlist;
  struct in_addr host_ip;
  int hg_flags			= 0;
  int hg_res;
  struct hg_globals * hg_globals = NULL;
  int global_socket		= -1;
  struct arglist * preferences  = NULL;
  struct arglist * plugins      = NULL;
  ntp_caps* caps		= NULL;
  struct openvas_rules *rules	= NULL;
  struct arglist * rejected_hosts =  NULL;
  int restoring    = 0;
  harglst * tested = NULL;
  int  save_session= 0;  
  int continuous   = 0;
  int detached     = 0;
  int return_code = 0;
  char * port_range;
  plugins_scheduler_t sched;
  int fork_retries = 0;
  harglst * files;
  hargwalk * hw;
  char * key;
  struct timeval then, now;

  gettimeofday(&then, NULL);

  host_ip.s_addr = 0;
  preferences    = arg_get_value(globals, "preferences");
  detached = preferences_detached_scan(preferences);
  if(detached)
  {
   char *email;
   
   detached_new_session(globals, arg_get_value(preferences, "TARGET"));
   arg_addset_value(preferences, "ntp_keep_communication_alive", ARG_STRING, 0, NULL);
   
   /* 
    * Tell the client that the scan is finished (actually, we will
    * work hard to test the network, but this lazy client has the right
    * to get some rest...
    */
   log_write("user %s : running a detached scan\n", (char*)arg_get_value(globals, "user"));
   global_socket = (int)arg_get_value(globals, "global_socket");
   comm_terminate(globals);
   close_stream_connection(global_socket);
   global_socket = -1;
   arg_set_value(globals, "global_socket", sizeof(int), (void*)global_socket);
   
   nessus_signal(SIGTERM, attack_sigterm);
   
start_attack_network:
   if((email = preferences_detached_scan_email(preferences)))
   {
    /*
     * The user wants to receive the results by e-mail.
     */
    if(detached_setup_mail_file(globals, email))
    {
     /*
      * Could not create the file to store our data
      */
     close_stream_connection(global_socket);
     return -1;
    }
   }
   else arg_addset_value(globals, "detached_scan_email_address", ARG_STRING, 0, NULL);
  }  
  num_tested = 0;

  
  global_socket  = (int)arg_get_value(globals, "global_socket");
 
  plugins        = arg_get_value(globals, "plugins");
  caps           = arg_get_value(globals, "ntp_caps");
  rules          = arg_get_value(globals, "rules");
  rejected_hosts = emalloc(sizeof(struct arglist));
  
  if(detached)
    continuous = preferences_continuous_scan(preferences);
  
  save_session = preferences_save_session(preferences);
  if(continuous)
   restoring = 0;
  else
   restoring = ((int)arg_get_value(globals, "RESTORE-SESSION") == 1);
   
  if(restoring)tested = arg_get_value(globals, "TESTED_HOSTS");
  if(save_session)save_tests_init(globals);  


  hostlist = arg_get_value(preferences, "TARGET");
  if( hostlist == NULL ){
  	log_write("%s : TARGET not set ?!", 
			attack_user_name(globals));
	EXIT(1);
	}		
  
  
  port_range = arg_get_value(preferences, "port_range");
  if( port_range == NULL ||
      port_range[0] == '\0' )
      	port_range = "1-15000";
  
  if( strcmp(port_range, "-1") != 0 )
  {
   unsigned short * ports;
   ports = (unsigned short*)getpts(port_range, NULL);
   if( ports == NULL){
   	auth_printf(globals, "SERVER <|> ERROR <|> E001 - Invalid port range <|> SERVER\n");
	return -1; 
	}
  }
  /*
   * Initialization of the attack
   */
  sched  = plugins_scheduler_init(plugins,  preferences_autoload_dependencies(preferences), preferences_silent_dependencies(preferences) ); 
  
  
  hg_flags = preferences_get_host_expansion(preferences);
  max_hosts = get_max_hosts_number(globals, preferences);
  
  
  if( restoring == 0)
  {
  int max_checks  = get_max_checks_number(globals, preferences);
  log_write("user %s starts a new scan. Target(s) : %s, with max_hosts = %d and max_checks = %d\n",
			 attack_user_name(globals), 
			 hostlist,
			 max_hosts, 
			 max_checks);
  }
  else
  {
   int max_checks  = get_max_checks_number(globals, preferences);
   log_write("user %s restores session %s, with max_hosts = %d and max_checks = %d\n",
   			attack_user_name(globals),
			(char*)arg_get_value(globals, "RESTORE-SESSION-KEY"),
			max_hosts,
			max_checks);
			
   save_tests_playback(globals, arg_get_value(globals, "RESTORE-SESSION-KEY"),tested);
  }
  
  			 
  /* 
   * Initialize the hosts_gatherer library 
   */
  if ( preferences_get_slice_network_addresses ( preferences ) != 0 )
  	hg_flags |= HG_DISTRIBUTE;
				  
  hg_globals = hg_init(hostlist, hg_flags);
  hg_res = hg_next_host(hg_globals, &host_ip, hostname, sizeof(hostname));
  if( tested != NULL )
   while(hg_res >= 0 && 
         harg_get_int( tested, hostname ) != 0 )
	 		{
			hg_res = hg_next_host(hg_globals, &host_ip, hostname, sizeof(hostname));
			}
			
			
  if( hg_res < 0 )
   goto stop;
   
   hosts_init(global_socket, max_hosts);
  /*
   * Start the attack !
   */
   
   while( hg_res >= 0 )
    {
      nthread_t pid;
      
      
   /*
    * openvasd offers the ability to either test
    * only the hosts we tested in the past, or only
    * the hosts we never tested (or both, of course)
    */
   if(save_kb(globals))
    {
    if(save_kb_pref_tested_hosts_only(globals))
    {
    if(!save_kb_exists(globals, hostname))
     {
      log_write("user %s : not testing %s because it has never been tested before\n",
      		 attack_user_name(globals), 
		 hostname);
      hg_res = hg_next_host(hg_globals, &host_ip, hostname, sizeof(hostname));
      if( tested != NULL )
      {
        while(hg_res >= 0 &&  harg_get_int( tested, hostname ) != 0 )
	 		hg_res = hg_next_host(hg_globals, &host_ip, hostname, sizeof(hostname));
      }			
      continue;
     }
   }
   else if(save_kb_pref_untested_hosts_only(globals))
   {
    /* XXX */
    if(save_kb_exists(globals, hostname))
    {
     log_write("user %s : not testing %s because it has already been tested before\n", 
     			attack_user_name(globals), 
			hostname);
     hg_res = hg_next_host(hg_globals, &host_ip, hostname, sizeof(hostname));
     if( tested != NULL )
      {
        while(hg_res >= 0 &&  harg_get_int( tested, hostname ) != 0 )
	 		hg_res = hg_next_host(hg_globals, &host_ip, hostname, sizeof(hostname));
      }	
     continue;
    }
   }
  }

      host_pending = 0 ;
      if(CAN_TEST(get_host_rules(rules, host_ip,32)) == 0) /* do we have the right to test this host ? */ 
      {
       log_write("user %s : rejected attempt to scan %s", 
			attack_user_name(globals), hostname);
       arg_add_value(rejected_hosts, hostname, ARG_INT, sizeof(int), (void*)1);	
      }
      else
      {
        struct attack_start_args args;
	int s;
	char * MAC = NULL;
	int mac_err = -1;

	
	
	if(preferences_use_mac_addr(preferences) &&
	   is_local_ip(host_ip))
	{
	 mac_err = get_mac_addr(host_ip, &MAC);
	 if(mac_err > 0)
	 {
	  /* remote host is down */
	  hg_res = hg_next_host(hg_globals, &host_ip, hostname, sizeof(hostname));
	  if( tested != NULL )
	  {
   		while(hg_res >= 0 && harg_get_int( tested, hostname ) != 0 )
	 		hg_res = hg_next_host(hg_globals, &host_ip, hostname, sizeof(hostname));
	  }		
	  continue;
	 }
	}
	
	s = hosts_new(globals, hostname);
	if(s < 0)goto scan_stop;
	 
         

	args.globals = globals;
	strncpy(args.hostname, hostname, sizeof(args.hostname) - 1);
	args.hostname[sizeof(args.hostname) - 1] = '\0';
        args.hostip.s_addr = host_ip.s_addr;
        args.host_mac_addr = MAC;
        args.sched = sched;
        args.thread_socket = s;
   
forkagain:        
	pid = create_process((process_func_t)attack_start, &args); 
	if(pid < 0)
	 {
          fork_retries ++;
          if(fork_retries > MAX_FORK_RETRIES)
          {
	  log_write("fork() failed - %s. %s won't be tested\n", strerror(errno), hostname);
	  /*
	   * forking failed - we go to the wait queue
	   */
	  efree(&MAC);
          goto stop;
          }
          log_write("fork() failed - sleeping %d seconds and trying again...\n", fork_retries);
          fork_sleep(fork_retries);
          goto forkagain;
	 }

        hosts_set_pid(hostname, pid);
	log_write("user %s : testing %s (%s) [%d]\n", attack_user_name(globals), hostname, inet_ntoa(args.hostip), pid);
        if(MAC != NULL)efree(&MAC);
	} 
	
        
       num_tested++;
       hg_res = hg_next_host(hg_globals, &host_ip, hostname, sizeof(hostname));
       if(tested != NULL)
         {
	 while(hg_res >= 0 &&
	       harg_get_int(tested, hostname))
		{
		hg_res = hg_next_host(hg_globals, &host_ip, hostname, sizeof(hostname));
		}
	}
     }
 
   
    

  /*
   * Every host is being tested... We have to wait for the threads
   * to terminate
   */
  
  while(hosts_read(globals) == 0);
  log_write("user %s : test complete", attack_user_name(globals));
scan_stop:    
   /*
     * Delete the files uploaded by the user, if any
     */
    files = arg_get_value(globals, "files_translation");
    if(files)
    {
     hw  = harg_walk_init(files);
     while((key = (char*)harg_walk_next(hw)))
      {
      unlink(harg_get_string(files, key));
      }
    }
 
  if(rejected_hosts && rejected_hosts->next)
   {
     char * banner = emalloc(4001);
     int length = 0;

     sprintf(banner, "SERVER <|> ERROR <|> E002 - These hosts could not be tested because you are not allowed to do so :;");
     length = strlen(banner);

     while(rejected_hosts->next && (length < (4000-3)))
	{
	  int n;
	  n = strlen(rejected_hosts->name);
	  if(length + n + 1 >= 4000)
	  {
	    n = 4000 - length  - 2;
	  }
	  strncat(banner, rejected_hosts->name, n);
	  strncat(banner, ";", 1);
	  length+=n+1;
	  rejected_hosts = rejected_hosts->next;
	}
      if( rejected_hosts->next != NULL )
       strcat(banner, "...");
       
     auth_printf(globals, "%s\n", banner);
   }
	
stop:
  if(save_session){
  	save_tests_close(globals);
	if(!preferences_save_empty_sessions(preferences))
	{
	 if(save_tests_empty(globals))
          {
            log_write("user %s : Nothing interesting found - deleting the session\n",
    		(char*)arg_get_value(globals, "user"));
             save_tests_delete_current(globals);
	  }
        }
   }
  
  hg_cleanup(hg_globals);
  
  arg_free_all(rejected_hosts);
  plugins_scheduler_free(sched);
  if(detached)
  {
   if(preferences_detached_scan_email(preferences))
    detached_send_email(globals);
  }
  
  if(continuous){
  	sleep(preferences_delay_between_scans(preferences));
	plugins = plugins_reload(preferences, plugins, 1);
	arg_set_value(globals, "plugins", -1, plugins);
  	goto start_attack_network;
	}
  else if(detached)detached_end_session(globals);	


  gettimeofday(&now, NULL);
  log_write("Total time to scan all hosts : %ld seconds\n", now.tv_sec - then.tv_sec);
  
  return return_code;
}

   
 
