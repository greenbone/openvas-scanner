/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file heartbeat.c
 * @brief Function for heartbeat
 */

#include "../misc/heartbeat.h"

#include "../misc/plugutils.h" /* for kb_item_set_int_with_main_kb_check */

#include <gvm/base/prefs.h> /* for prefs_get() */
#include <gvm/boreas/cli.h> /* for is_host_alive() */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "sd   main"

/**
 * @brief Check if the hosts is still alive and set it as dead if not.
 *
 * @param kb Host kb where the host is set as dead.
 *
 * @return 1 if considered alive, 0 if it is dead. -1 on error
 * or option disabled.
 */
int
check_host_still_alive (kb_t kb, const char *hostname)
{
  int is_alive = 0;
  boreas_error_t alive_err;

  /* Heartbeat will work only with boreas enabled. We check if we
     have all what we need before running a heartbeat check. */
  if (prefs_get_bool ("test_alive_hosts_only"))
    {
      const gchar *alive_test_str = prefs_get ("ALIVE_TEST");

      /* Don't perform a hearbeat check if the host is always considered
         alive or the alive test is not valid. */
      if (!(alive_test_str
            && atoi (alive_test_str) >= ALIVE_TEST_TCP_ACK_SERVICE
            && atoi (alive_test_str) < 32 // max value for alive test combi.
            && !((atoi (alive_test_str)) & ALIVE_TEST_CONSIDER_ALIVE)))
        return -1;
    }
  else
    {
      g_warning ("%s: Trying to perform an alive test, but Boreas is not "
                 "enabled. Heartbeat check for %s will not be performed",
                 __func__, hostname);
      return -1;
    }

  alive_err = is_host_alive (hostname, &is_alive);
  if (alive_err)
    {
      g_warning ("%s: Heartbeat check failed for %s with error %d.", __func__,
                 hostname, alive_err);
      return -1;
    }

  if (is_alive == 0)
    {
      g_message ("%s: Heartbeat check was not successful. The host %s has"
                 " been set as dead.",
                 __func__, hostname);
      kb_item_set_int_with_main_kb_check (kb, "Host/dead", 1);
      return 0;
    }

  return 1;
}
