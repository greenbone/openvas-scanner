/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file user_agent.c
 * @brief Functions to set and get the User-Agent.
 */

#include "user_agent.h"

#include "ipc_openvas.h"
#include "plugutils.h" /* plug_get_host_fqdn */
#include "vendorversion.h"

#include <glib.h>
#include <gvm/base/prefs.h> /* for prefs_get */

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  misc"

/**
 * @brief user-agent, or NULL.
 */
static gchar *user_agent = NULL;

static int
send_user_agent_via_ipc (struct ipc_context *ipc_context)
{
  struct ipc_data *ua = NULL;
  const char *json = NULL;
  int ret = 0;
  ua = ipc_data_type_from_user_agent (user_agent, strlen (user_agent));
  json = ipc_data_to_json (ua);
  ipc_data_destroy (&ua);
  ret = ipc_send (ipc_context, IPC_MAIN, json, strlen (json));
  if (-1 == ret)
    {
      g_warning ("Unable to send %s to host process", user_agent);
    }
  return ret;
}

/**
 * @brief Create and set the global User-Agent variable.
 *
 * @description Gets the User-Agent from the globals_settings.nasl
 * script preferences. If it is not set, it uses the Vendor version.
 * In case that there is no Vendor version, it creates one with a fix string
 * and the nasl library version.
 */
static void
user_agent_create (void)
{
  gchar *ua = NULL;

  ua = get_plugin_preference ("1.3.6.1.4.1.25623.1.0.12288", "HTTP User-Agent",
                              -1);
  if (!ua || strlen (g_strstrip (ua)) == 0)
    {
      g_free (ua);
      if (!vendor_version_get () || *vendor_version_get () == '\0')
        ua = g_strdup_printf ("Mozilla/5.0 [en] (X11, U; OpenVAS-VT %s)",
                              OPENVAS_MISC_VERSION);
      else
        ua = g_strdup_printf ("Mozilla/5.0 [en] (X11, U; %s)",
                              vendor_version_get ());
    }

  user_agent = ua;
}

/**
 * @brief Set user-agent
 *
 * Set the global user agent.
 * This function overwrite the existing UA.
 * Null or empty string are not allowed.
 *
 * @param[in]  ua  user-agent to be set.
 *
 * Return the old User-Agent. It must be free by the caller
 */
gchar *
user_agent_set (const gchar *ua)
{
  gchar *ua_aux = NULL;

  ua_aux = g_strdup (user_agent);

  if (ua != NULL && ua[0] != '\0')
    {
      g_free (user_agent);
      user_agent = g_strdup (ua);
    }

  return ua_aux;
}

/**
 * @brief Get user-agent.
 *
 * param[in] ipc_context IPC context for sending data to the parent process
 * param[out] useragent  the user agent if any set or an empty string.
 *
 * @return 0 on success, -1 on error when sending the message, -2 if the context
 * does not exists
 */
int
user_agent_get (struct ipc_context *ipc_context, char **useragent)
{
  int ret = 0;
  if (!user_agent || user_agent[0] == '\0')
    {
      user_agent_create ();
      ret = send_user_agent_via_ipc (ipc_context);
    }

  *useragent = user_agent ? g_strdup (user_agent) : "";
  return ret;
}
