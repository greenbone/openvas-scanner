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
 
#ifndef _NESSUSC_ERROR_DIALOG_H
#define _NESSUSC_ERROR_DIALOG_H

#define DIALOG_TYPE_INFO 0
#define DIALOG_TYPE_WARNING 1
#define DIALOG_TYPE_ERROR 2


#define show_error(x) show_dialog(x, DIALOG_TYPE_ERROR)
#define show_warning(x) show_dialog(x, DIALOG_TYPE_WARNING)
#define show_info(x) show_dialog(x, DIALOG_TYPE_INFO)

#define show_error_and_wait(x) show_dialog_and_wait(x, DIALOG_TYPE_ERROR)
#define show_warning_and_wait(x) show_dialog_and_wait(x, DIALOG_TYPE_WARNING)
#define show_info_and_wait(x) show_dialog_and_wait(x, DIALOG_TYPE_INFO)


extern void show_dialog(char * error_text, int type);
extern void show_dialog_and_wait_build(int * ok, char * error_text, int type);
extern void show_dialog_and_wait(char * error, int type);

#endif
