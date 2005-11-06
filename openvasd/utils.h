/* Nessuslib -- the Nessus Library
 * Copyright (C) 1998 Renaud Deraison
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */   

#ifndef _NESSUSD_UTILS_H
#define _NESSUSD_UTILS_H


struct attack_atom
{
 char * name;
 int soc;  /* public socket  */
 int psoc; /* private socket */
 struct attack_atom * next;
};
struct arglist * sort_plugins_by_type(struct arglist *);
int get_max_hosts_number(struct arglist *, struct arglist *);
int get_max_checks_number(struct arglist *, struct arglist *);
int get_active_plugins_number(struct arglist *);
void plugins_set_ntp_caps(struct arglist *, ntp_caps*);
void send_plugin_order(struct arglist *, struct arglist *);
int check_threads_input(struct attack_atom **, int, struct arglist *);
int is_symlink(char *);
void check_symlink(char *);
char * hosts_arglist_to_string(struct arglist *);

struct attack_atom ** attack_atom_new();
void attack_atom_free(struct attack_atom **);
void attack_atom_free_others(struct attack_atom **, char *);
void attack_atom_insert(struct attack_atom **, char *, int, int);
void attack_atom_remove(struct attack_atom **, char *);


void create_pid_file();
void delete_pid_file();
char*temp_file_name();
int version_check(char *, char*);

struct arglist * list2arglist(char*);
int common(struct arglist*, struct arglist*);

int process_alive(pid_t);
int is_client_present(int);
int is_socket_connected(int);
int data_left(int);
int set_linger(int, int);

void wait_for_children1();
#endif
