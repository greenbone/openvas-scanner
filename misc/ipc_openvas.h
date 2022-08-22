#ifndef IPC_OPENVAS_H
#define IPC_OPENVAS_H
#include "ipc.h"

// ipc_hostname is used to send / retrieve new hostnames.
struct ipc_hostname
{
  char *source;        // source value
  char *hostname;      // hostname value
  size_t source_len;   // length of source
  size_t hostname_len; // length of hostname
};

// ipc_data_type defines
enum ipc_data_type
{
  IPC_DT_HOSTNAME,
};

struct ipc_data
{
  enum ipc_data_type type;
  void *data;
};

struct ipc_data *
ipc_data_type_from_hostname (const char *source, size_t source_len,
                             const char *hostname, size_t hostname_len);

void
ipc_hostname_destroy (struct ipc_hostname *data);

void
ipc_data_destroy (struct ipc_data *data);

const char *
ipc_data_to_json (struct ipc_data *data);

struct ipc_data *
ipc_data_from_json (const char *json, size_t len);

#endif
