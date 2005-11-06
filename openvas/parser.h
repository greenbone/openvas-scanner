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
 
#ifndef _NESSUSC_PARSER_H
#define _NESSUSC_PARSER_H

#define MSG_ERROR 1
#define MSG_PORT 2
#define MSG_HOLE 3
#define MSG_BYE 4
#define MSG_INFO 5
#define MSG_STAT 6
#define MSG_PING 7
#define MSG_PLUGINS_ORDER 8
#define MSG_FINISHED 9
#define MSG_STAT2 10
#define MSG_NOTE 11
#define MSG_TIME 12

#define MSG_ERROR_STR "ERROR"
#define MSG_PORT_STR "PORT"
#define MSG_HOLE_STR "HOLE"
#define MSG_INFO_STR "INFO"
#define MSG_NOTE_STR "NOTE"
#define MSG_STAT_STR "STATUS"
#define MSG_BYE_STR "BYE"
#define MSG_PING_STR "PING"
#define MSG_PLUGINS_ORDER_STR "PLUGINS_ORDER"
#define MSG_FINISHED_STR "FINISHED"
#define MSG_TIME_STR "TIME"

int parse_message_type(char *);
int parse_server_message(char *,  int,  char *);
void parse_host_add_port(int, char *, char *);
void parse_host_add_data(int, char *, int);
char * parse_plugin_symbol(char *);
char * parse_separator(char *);
char * parse_symbol(char *);
void parse_nessusd_status(char *, char **, char **, char  **, int *);
void parse_nessusd_short_status(char *, char **, char **, char  **, int *);

#endif
