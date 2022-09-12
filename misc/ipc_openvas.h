#ifndef MISC_IPC_OPENVAS_H
#define MISC_IPC_OPENVAS_H
#include "ipc.h"

// ipc_hostname is used to send / retrieve new hostnames.
struct ipc_hostname
{
  char *source;        // source value
  char *hostname;      // hostname value
  size_t source_len;   // length of source
  size_t hostname_len; // length of hostname
};

// ipc_user_agent is used to send / retrieve the User-Agent.
struct ipc_user_agent
{
  char *user_agent;      // user_agent value
  size_t user_agent_len; // length of user_agent
};


// ipc_data_type defines
enum ipc_data_type
{
  IPC_DT_HOSTNAME,
  IPC_DT_USER_AGENT,
};

struct ipc_data
{
  enum ipc_data_type type;
  void *data;
};

struct ipc_data *
ipc_data_type_from_hostname (const char *source, size_t source_len,
                             const char *hostname, size_t hostname_len);

struct ipc_data *
ipc_data_type_from_user_agent (const char *user_agent, size_t user_agent_len);

void
ipc_data_destroy (struct ipc_data *data);

const char *
ipc_data_to_json (struct ipc_data *data);

struct ipc_data *
ipc_data_from_json (const char *json, size_t len);

#endif
