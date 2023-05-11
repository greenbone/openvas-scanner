/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 1998-2003 Renaud Deraison
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file kb_cache.c
 * @brief kb_cache.h implementation.
 */

#include "kb_cache.h"

// shared database between openvas and ospd.
kb_t main_kb = NULL;

/**
 * @brief sets the shared database between ospd and openvas as a main_kb for
 * further usage.
 * @description this sets the given kb as a main_kb global variable. It is NOT
 * threadsafe and must be called after each reconnect or fork.
 *
 * @param main_kb Current main kb.
 *
 */
void
set_main_kb (kb_t kb)
{
  main_kb = kb;
}

/**
 * @brief gets the main_kb.
 * @description returns the previously set main_kb; when asserts are enabled it
 * will abort when main_kb is not set. However each usage must check if the
 * return is NULL or not.
 *
 * @return the set main_kb
 */
kb_t
get_main_kb (void)
{
  assert (main_kb);
  return main_kb;
}
