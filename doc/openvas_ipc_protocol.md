# OpenVAS IPC Protocol

This protocol allows the communication between parent and child process in the openvas-scanner. The information is sent in json format.

## Data Handling
The data to be sent/retrive is stored inside a structure whit two fields: `data_type` and an `union` of different data members

``` c
struct ipc_data
{
  enum ipc_data_type type;
  union
  {
    ipc_user_agent_t *ipc_user_agent;
    ipc_hostname_t *ipc_hostname;
    ipc_lsc_t *ipc_lsc;
  };
};
```

### Data types

Currently, the following data types are supported

- **User-Agent:** First time that the User-Agent is used during a scan, it will be sent to the parent process and stored for further usage.
- **Hostname:** Hostnames which are found for a plugin are communicated the parent process and added to the vhost list. Later launched plugins know the updated list.
- **LSC:** The gather-package-list.nasl nasl script gathered the necessary data for running a LSC scan. The parent process is told to run the scan.

The `enum ipc_data_type` has also the IPC_DT_ERROR definition for unknown types.

``` c
enum ipc_data_type
{
  IPC_DT_ERROR = -1,
  IPC_DT_HOSTNAME = 0,
  IPC_DT_USER_AGENT,
  IPC_DT_LSC,
};
```

### Data

Currently, there are three data holders, which correspond to the supported data types. This data is not directly accessible, and functions must be used to set/get the data.

- **ipc_hostname:** used to send / retrieve new hostnames.

``` c
struct ipc_hostname
{
  char *source;        // source value
  char *hostname;      // hostname value
  size_t source_len;   // length of source
  size_t hostname_len; // length of hostname
};
```

- **ipc_user_agent:** used to send/retrieve new hostnames.

``` c
struct ipc_user_agent
{
  char *user_agent;      // user_agent value
  size_t user_agent_len; // length of user_agent
};
```

- **ipc_lsc:** used to send/retrieve the LSC data_ready flag.

``` c
struct ipc_lsc
{
  gboolean data_ready; // flag indicating that lsc data is in the kb
};
```


## Messages

Before sending a message to another process, the message must be created in the right json format.

The following examples show how the Json message looks like for the different data types.


- *ipc_hostname:*
```
{
  "type":0,
  "source":"TLS certificate",
  "hostname":"localhost"
}
  ```
- *ipc_user_agent:*
```
{
  "type":1,
  "user-agent":"Orange Agent"
}
  
```

- *ipc_lsc:*
```
{
  "type":2,
  "data_ready":"True"
}
  
```

The following code shows how to use the different functions for ipc communication:

``` c
#include <stdio.h>
#include <openvas/misc/ipc_openvas.h>

int
main(int argc, char **argv)
{

  ipc_data_t *data_s = NULL;
  ipc_data_t *data_r = NULL;
  gchar *hn = "localhost";
  gchar *hns = "TLS certificate";

  // Preapre data to be sent
  data_s = g_malloc0 (sizeof (ipc_data_t *));
  data_s = ipc_data_type_from_hostname (hns, strlen (hns), hn, strlen(hn));

  char *json = ipc_data_to_json(data_s);
  printf ("\nPrint json message:\n%s\n\n\n", json);


  // Read received data
  data_r = g_malloc0 (sizeof (ipc_data_t *));
  data_r = ipc_data_from_json (json, strlen (json));

  printf ("Print data received in the json string:\n"
          "hostname: %s\n"
          "source: %s\n",
          ipc_get_hostname_from_data (data_r),
          ipc_get_hostname_source_from_data (data_r));
}
```

# Sending and retrieving IPC messages.

Inter-process communication is done using pipes. Therefore, an IPC context is initialized when a new process is created. This opens the pipe and the child inherits the file descriptors, stablishing the communication between parent and child process.

Each process has an IPC context, which is de following data structure. The variable context
contains the two files decriptors (read/write) created and used for pipe communication.

``` c
struct ipc_context
{
  enum ipc_protocol type;
  enum ipc_relation relation;
  unsigned int closed;
  pid_t pid;
  void *context;
};
```

<small>*see src/processes.c:create_ipc_process()*</small>

#### Sending a message

Since the processes have an IPC context, calling the function *ipc_send()* is enough to send an IPC message to another process. 

The following example can be find in the file *src/misc/user_agent.c*, where the IPC message in jso format is encapsulated in the ipc data structure (includes the type of message) and sent to the parent process.

```c
static void
send_user_agent_via_ipc (struct ipc_context *ipc_context)
{
  struct ipc_data *ua = NULL;
  const char *json = NULL;

  ua = ipc_data_type_from_user_agent (user_agent, strlen (user_agent));
  json = ipc_data_to_json (ua);
  ipc_data_destroy (ua);
  if (ipc_send (ipc_context, IPC_MAIN, json, strlen (json)) < 0)
    g_warning ("Unable to send %s to host process", user_agent);
}
```

#### Retrieving a message

For retrieving a message, it is quite similar to sending one. Having a context, it is just necessary to call *ipc_retrieve()* function. This will return the ipc data structure containing the message type and the information in json format to be processed.

An example of usage can be seen in *src/attack.c:read_ipc()*

``` c
static void
read_ipc (struct ipc_context *ctx)
{
  char *result;
  ipc_data_t *idata;

  while ((result = ipc_retrieve (ctx, IPC_MAIN)) != NULL)
    {
      if ((idata = ipc_data_from_json (result, strlen (result))) != NULL)
        {
          switch (ipc_get_data_type_from_data (idata))
            {
            case IPC_DT_ERROR:
              g_warning ("%s: Unknown data type.", __func__);
              break;
            case IPC_DT_HOSTNAME:
              if (ipc_get_hostname_from_data (idata) == NULL)
                g_warning ("%s: ihost data is NULL ignoring new vhost",
                           __func__);
              else
                append_vhost (ipc_get_hostname_from_data (idata),
                              ipc_get_hostname_source_from_data (idata));
              break;
...
```

