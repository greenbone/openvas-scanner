/* Nessus
 * Copyright (C) 2000 Renaud Deraison
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 */

#include <includes.h>

#ifdef ENABLE_SAVE_KB
#ifdef USE_GTK
#include <gtk/gtk.h>
#include "../xstuff.h"
#include "globals.h"
#include "prefs_help.h"

#define ENABLE_KB_SAVING "Enable KB saving"
#define TEST_ALL "Test all hosts"
#define TEST_TESTED "Only test hosts that have been tested in the past"
#define TEST_UNTESTED "Only test hosts that have never been tested in the past"

#define RESTORE_KB "Reuse the knowledge bases about the hosts for the test"

#define NO_SCANNER "Do not execute scanners that have already been executed"
#define NO_INFO "Do not execute info gathering plugins that have already been executed"
#define NO_ATTACK "Do not execute attack plugins that have already been executed"
#define NO_DENIAL "Do not execute DoS plugins that have already been executed"


static void set_state(c, name, value)
 struct arglist * c;
 char * name;
 int value;
{
  gtk_widget_set_sensitive(arg_get_value(c, name), value);
}

static void 
kb_enable_cb(a, ctrls)
 GtkWidget * a;
 struct arglist * ctrls;
{
 /*
  * De-sensitivise everything
  */
 GtkWidget * w;
 int value = GTK_TOGGLE_BUTTON(a) -> active;
 
 set_state(ctrls, "TEST_ALL", value);
 set_state(ctrls, "TEST_TESTED", value);
 set_state(ctrls, "TEST_UNTESTED", value);

 
 w = arg_get_value(ctrls, "RESTORE_KB");
 if(!(GTK_TOGGLE_BUTTON(w) -> active))
 {
  set_state(ctrls, "NO_SCANNER", FALSE);
  set_state(ctrls, "NO_INFO", FALSE);
  set_state(ctrls, "NO_ATTACK", FALSE);
  set_state(ctrls, "NO_DENIAL", FALSE);
 }
 else
 {
  set_state(ctrls, "NO_SCANNER", value);
  set_state(ctrls, "NO_INFO", value);
  set_state(ctrls, "NO_ATTACK", value);
  set_state(ctrls, "NO_DENIAL", value);
 }
 set_state(ctrls, "RESTORE_KB", value);
 set_state(ctrls, "MAX_AGE", value);
}

static void
kb_restore_cb(a, ctrls)
 GtkWidget * a;
 struct arglist * ctrls;
{
 int value = GTK_TOGGLE_BUTTON(a)->active;
 set_state(ctrls, "NO_SCANNER", value);
 set_state(ctrls, "NO_INFO", value);
 set_state(ctrls, "NO_ATTACK", value);
 set_state(ctrls, "NO_DENIAL", value);

}

static void 
arg_addset_value(arglist, name, value)
 struct arglist * arglist;
 char * name;
 char * value;
{
 if(arg_get_type(arglist, name) < 0)
  arg_add_value(arglist, name, ARG_STRING, strlen(value), strdup(value));
 else
  {
  arg_set_type(arglist, name, ARG_STRING);
  arg_set_value(arglist, name, strlen(value), strdup(value));
  }
}

static int
pref_set(arglist, name)
 struct arglist * arglist;
 char * name;
{
 int type = arg_get_type(arglist, name);
 if(type < 0)
   return 0; /* no set */
 if(type == ARG_INT)
  return (int)arg_get_value(arglist, name);
 else  {
 	char * value = arg_get_value(arglist, name);
	if(!value)
		return 0;
	return !strcmp(value, "yes");
	}
}


void 
prefs_dialog_kb_set_prefs(ctrls, gprefs)
 struct arglist * ctrls;
 struct arglist * gprefs;
{
 GtkWidget * w;
 struct arglist * prefs = arg_get_value(gprefs, "SERVER_PREFS");
 
 w = arg_get_value(ctrls, "ENABLE_SAVE_KB");
 gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(w), 
 			pref_set(prefs, "save_knowledge_base"));

 w = arg_get_value(ctrls, "TEST_ALL");
 gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(w),
 			!pref_set(prefs, "only_test_hosts_whose_kb_we_dont_have")
		    &&  !pref_set(prefs, "only_test_hosts_whose_kb_we_have"));
		    
		    
 w = arg_get_value(ctrls, "TEST_TESTED");
 gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(w),
 			!pref_set(prefs, "only_test_hosts_whose_kb_we_dont_have")
		    &&  pref_set(prefs, "only_test_hosts_whose_kb_we_have")); 

 w = arg_get_value(ctrls, "TEST_UNTESTED");
 gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(w),
 			pref_set(prefs, "only_test_hosts_whose_kb_we_dont_have")
		    &&  !pref_set(prefs, "only_test_hosts_whose_kb_we_have")); 
		    
 w = arg_get_value(ctrls, "RESTORE_KB");
 gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(w), 
 			pref_set(prefs, "kb_restore"));  

 w = arg_get_value(ctrls, "NO_SCANNER");
 gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(w), 
 			pref_set(prefs, "kb_dont_replay_scanners"));  
			
 w = arg_get_value(ctrls, "NO_INFO");
 gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(w), 
 			pref_set(prefs, "kb_dont_replay_info_gathering"));  
			
			
 w = arg_get_value(ctrls, "NO_ATTACK");
 gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(w), 
 			pref_set(prefs, "kb_dont_replay_attacks"));  						

 w = arg_get_value(ctrls, "NO_DENIAL");
 gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(w), 
 			pref_set(prefs, "kb_dont_replay_denials"));  	
			


			
						
 w = arg_get_value(ctrls, "MAX_AGE");
 if(arg_get_value(prefs, "kb_max_age"))
  gtk_entry_set_text(GTK_ENTRY(w), arg_get_value(prefs, "kb_max_age"));
 			

 kb_enable_cb(arg_get_value(ctrls, "ENABLE_SAVE_KB"), ctrls);
 kb_restore_cb(arg_get_value(ctrls, "RESTORE_KB"), ctrls);
}


void 
prefs_dialog_kb_get_prefs(ctrls)
 struct arglist * ctrls;
{
 GtkWidget * bt;
 struct arglist *prefs = arg_get_value(Prefs, "SERVER_PREFS");
 bt = arg_get_value(ctrls, "ENABLE_SAVE_KB");
 if(GTK_TOGGLE_BUTTON(bt) -> active)
  arg_addset_value(prefs, "save_knowledge_base", "yes");
 else
  arg_addset_value(prefs, "save_knowledge_base", "no");
  
 bt = arg_get_value(ctrls, "TEST_ALL");
 if(GTK_TOGGLE_BUTTON(bt) -> active)
  {
  arg_addset_value(prefs, "only_test_hosts_whose_kb_we_dont_have", "no");
  arg_addset_value(prefs, "only_test_hosts_whose_kb_we_have", "no");
  }
  
 bt = arg_get_value(ctrls, "TEST_TESTED");
 if(GTK_TOGGLE_BUTTON(bt) -> active)
  {
  arg_addset_value(prefs, "only_test_hosts_whose_kb_we_dont_have", "no");
  arg_addset_value(prefs, "only_test_hosts_whose_kb_we_have", "yes");
  }
 bt = arg_get_value(ctrls, "TEST_UNTESTED"); 
 if(GTK_TOGGLE_BUTTON(bt) -> active)
  {
  arg_addset_value(prefs, "only_test_hosts_whose_kb_we_dont_have", "yes");
  arg_addset_value(prefs, "only_test_hosts_whose_kb_we_have", "no");
  }
  
 bt = arg_get_value(ctrls, "RESTORE_KB");
 if(GTK_TOGGLE_BUTTON(bt) -> active)
  arg_addset_value(prefs, "kb_restore", "yes");
 else
  arg_addset_value(prefs, "kb_restore", "no");
  
  
 bt = arg_get_value(ctrls, "NO_SCANNER");
 if(GTK_TOGGLE_BUTTON(bt) -> active)
  arg_addset_value(prefs, "kb_dont_replay_scanners", "yes");
 else
  arg_addset_value(prefs, "kb_dont_replay_scanners", "no");
 
 bt = arg_get_value(ctrls, "NO_INFO");
 if(GTK_TOGGLE_BUTTON(bt) -> active)
  arg_addset_value(prefs, "kb_dont_replay_info_gathering", "yes");
 else
  arg_addset_value(prefs, "kb_dont_replay_info_gathering", "no");
  
  
 bt = arg_get_value(ctrls, "NO_ATTACK");
 if(GTK_TOGGLE_BUTTON(bt) -> active)
  arg_addset_value(prefs, "kb_dont_replay_attacks", "yes");
 else
  arg_addset_value(prefs, "kb_dont_replay_attacks", "no");
  
  
  bt = arg_get_value(ctrls, "NO_DENIAL");
 if(GTK_TOGGLE_BUTTON(bt) -> active)
  arg_addset_value(prefs, "kb_dont_replay_denials", "yes");
 else
  arg_addset_value(prefs, "kb_dont_replay_denials", "no"); 
  
 
   
 bt = arg_get_value(ctrls, "MAX_AGE");
 arg_addset_value(prefs, "kb_max_age", gtk_entry_get_text(GTK_ENTRY(bt)));
 
}
struct arglist * prefs_dialog_kb()
{
 GtkWidget * frame;
 struct arglist * ctrls = emalloc(sizeof(struct arglist));
 GtkWidget * button, *label;
 GtkWidget * box, * sbox, * entry;
 GtkTooltips * tooltips;
 
 tooltips = gtk_tooltips_new();
 
 frame = gtk_frame_new("Nessus Knowledge Base");
 gtk_container_border_width(GTK_CONTAINER(frame), 10);
 arg_add_value(ctrls, "FRAME", ARG_PTR, -1, frame);
 
  
 
 box = gtk_vbox_new(FALSE, FALSE);
 
 gtk_container_add(GTK_CONTAINER(frame), box);
 button = gtk_check_button_new_with_label(ENABLE_KB_SAVING);
 gtk_tooltips_set_tip(tooltips, button, HLP_ENABLE_KB_SAVING, "");
 gtk_signal_connect(GTK_OBJECT(button),
		     "clicked",
		     GTK_SIGNAL_FUNC(kb_enable_cb),
		     ctrls);
 gtk_box_pack_start(GTK_BOX(box), button, FALSE, FALSE, 5);
 /* XXX must disable all the panel if deactivated */
 
 arg_add_value(ctrls, "ENABLE_SAVE_KB", ARG_PTR, -1, button);
 
 gtk_widget_show(button);
 
 button = gtk_radio_button_new_with_label(NULL, TEST_ALL);
 gtk_tooltips_set_tip(tooltips, button, HLP_KB_TEST_ALL, "");
 gtk_box_pack_start(GTK_BOX(box), button, FALSE, FALSE, 5);
 arg_add_value(ctrls, "TEST_ALL", ARG_PTR, -1, button);
 gtk_widget_show(button);
 
 /*list = gtk_radio_button_group(GTK_RADIO_BUTTON(button));*/
 button = gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON(button), TEST_TESTED);
 gtk_tooltips_set_tip(tooltips, button, HLP_KB_TEST_TESTED, "");
 gtk_box_pack_start(GTK_BOX(box), button, FALSE, FALSE, 5);
 arg_add_value(ctrls, "TEST_TESTED", ARG_PTR, -1, button);
 gtk_widget_show(button);
 
 button = gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON(button), TEST_UNTESTED);
 gtk_tooltips_set_tip(tooltips, button, HLP_KB_TEST_UNTESTED, "");
 gtk_box_pack_start(GTK_BOX(box), button, FALSE, FALSE, 5);
 arg_add_value(ctrls, "TEST_UNTESTED", ARG_PTR, -1, button);
 gtk_widget_show(button);
 
 
 button = gtk_check_button_new_with_label(RESTORE_KB);
 gtk_tooltips_set_tip(tooltips, button, HLP_RESTORE_KB, "");
 gtk_box_pack_start(GTK_BOX(box), button, FALSE, FALSE, 5);
 arg_add_value(ctrls, "RESTORE_KB", ARG_PTR, -1, button);
 gtk_signal_connect(GTK_OBJECT(button),
		     "clicked",
		     GTK_SIGNAL_FUNC(kb_restore_cb),
		     ctrls);
 gtk_widget_show(button);
 
 sbox = gtk_vbox_new(FALSE, FALSE);
 gtk_box_pack_start(GTK_BOX(box), sbox, FALSE, FALSE, 5);
 gtk_widget_show(sbox);
 
 button = gtk_check_button_new_with_label(NO_SCANNER);
 gtk_tooltips_set_tip(tooltips, button, HLP_KB_NO_SCANNER, "");
 gtk_container_border_width(GTK_CONTAINER(sbox), 10);
 gtk_box_pack_start(GTK_BOX(sbox), button, TRUE, TRUE, 0);
 arg_add_value(ctrls, "NO_SCANNER", ARG_PTR, -1, button);
 gtk_widget_show(button);
 
 button = gtk_check_button_new_with_label(NO_INFO);
 gtk_tooltips_set_tip(tooltips, button, HLP_KB_NO_INFO, "");
 gtk_box_pack_start(GTK_BOX(sbox), button, TRUE, TRUE, 5);
 gtk_widget_show(button);
 arg_add_value(ctrls, "NO_INFO", ARG_PTR, -1, button);
 
  
  
 button = gtk_check_button_new_with_label(NO_ATTACK);
 gtk_tooltips_set_tip(tooltips, button, HLP_KB_NO_ATTACK, "");
 gtk_box_pack_start(GTK_BOX(sbox), button, TRUE, TRUE, 5);
 gtk_widget_show(button);
 arg_add_value(ctrls, "NO_ATTACK", ARG_PTR, -1, button);
 
 
 button = gtk_check_button_new_with_label(NO_DENIAL);
 gtk_tooltips_set_tip(tooltips, button, HLP_KB_NO_DENIAL, "");
 gtk_box_pack_start(GTK_BOX(sbox), button, TRUE, TRUE, 5);
 gtk_widget_show(button);
 arg_add_value(ctrls, "NO_DENIAL", ARG_PTR, -1, button);
  
 
 sbox = gtk_hbox_new(TRUE, TRUE);
 gtk_box_pack_start(GTK_BOX(box), sbox, TRUE, TRUE, 5);
 gtk_widget_show(sbox);
 
 label = gtk_label_new("Max age of a saved KB (in secs) : ");
 gtk_box_pack_start(GTK_BOX(sbox), label, TRUE, TRUE, 5);
 gtk_widget_show(label);
 
 entry = gtk_entry_new();
 gtk_tooltips_set_tip(tooltips, entry, HLP_KB_MAX_AGE, "");
 gtk_box_pack_start(GTK_BOX(sbox), entry, TRUE, TRUE, 5);
 gtk_entry_set_text(GTK_ENTRY(entry), "864000");
 gtk_widget_show(entry);
 arg_add_value(ctrls, "MAX_AGE", ARG_PTR, -1, entry);
 
 
 gtk_widget_show(box);
 kb_enable_cb(arg_get_value(ctrls, "ENABLE_SAVE_KB"), ctrls);
 kb_restore_cb(arg_get_value(ctrls, "RESTORE_KB"), ctrls);
 gtk_tooltips_enable(tooltips);
 
 return ctrls;
}


#endif
#endif
