/* Nessus
 * Copyright (C) 1998, 1999, 2000 Renaud Deraison
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
 */  

/* Pluto 26.6.00:
 *
 * changed infos_and_holes_to into findings_to 
 */

#include <includes.h>
#include "globals.h"

#include "report.h"
#include "families.h"
#include "nsr_output.h"
#include "html_output.h"
#include "html_graph_output.h"
#include "report_utils.h"
#include "error_dialog.h"
#include "latex_output.h"
#include "text_output.h"
#include "xml_output.h"
#include "globals.h"
#include "comm.h"
#include "backend.h"

#define SAVE_NSR 0
#define SAVE_HTML 1
#define SAVE_TEXT 2
#define SAVE_LATEX 3
#define SAVE_HTML_GRAPH 4
#define SAVE_XML 5
#define SAVE_MAX SAVE_XML


/* reports back the highest number */
int is_there_any_hole(arglist)
 struct arglist * arglist;
{
 int ret = 0;
 /* Pluto 25.6.00: with three level of return, real sort */
 while(arglist && arglist->next && (ret!=HOLE_PRESENT))
 {
  int tmp = 0;
  int tmp2 = 0;
  if(!arglist->name)
   {
    arglist = arglist->next;
    continue;
   }
  if(!strcmp(arglist->name, "REPORT"))tmp2 = HOLE_PRESENT;
  else if(!strcmp(arglist->name, "INFO"))tmp2 = WARNING_PRESENT;
  else if(!strcmp(arglist->name, "NOTE"))tmp2 = NOTE_PRESENT;
  /*
   * Check in the sublist
   */
  if(arglist->type == ARG_ARGLIST)tmp = is_there_any_hole(arglist->value);
  if(tmp >= tmp2)tmp2 = tmp;
  if(tmp2 >= ret)ret = tmp2;
  arglist = arglist->next;
 }
 return(ret);
}
