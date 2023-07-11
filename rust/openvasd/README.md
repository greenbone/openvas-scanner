# OpenVAS Daemon

Is the implementation for [scanner-api](https://greenbone.github.io/scanner-api/).

Currently it is utilizing ospd-openvas.

# Requirements

It requires a running ospd-openvas instance.

# Configuration

Create a configuration file under either:

- `/etc/openvasd/openvasd.toml`
- `$HOME/.config/openvasd/openvasd.toml`

or provide the `-c` flag when starting openvasd.

Configure it like:


```
[feed]
# path to the openvas feed. This is required for the /vts endpoint.
path = "/var/lib/openvas/plugins"

[feed.check_interval]
# how often the feed should be checked for updates
secs = 3600
nanos = 0

[endpoints]
# enables GET /scans endpoint
enable_get_scans = true
# if set it requires `x-api-key` header to use the endpoint
key = "mtls_is_preferred"

[tls]
# the server certificate
certs = "/etc/openvasd/tls/server.pem"
# server key
key = "/var/lib/openvasd/tls/server.rsa"
# dir that contains client certificates. if there are none than every client is
# allowed to connect otherwise just the clients that have the configured
# client certificates
client_certs = "/etc/openvasd/tls/client"

[ospd]
# path to the unix socket of ospd-openvas
socket = "/var/run/ospd/ospd.sock"

[ospd.result_check_interval]
# interval of checking for results for started scans
secs = 1
nanos = 0

[listener]
# ip address and port to listen to
address = "127.0.0.1:3000"

[log]
# level of the log messages: TRACE > DEBUG > INFO > WARN > ERROR
level = "INFO"
```

If you want to enable TLS for secure communication, ensure that the TLS
certificate files are in place and accessible.

Server Certificates: The server certificate and private key files should be
located at the paths specified in the tls.certs and tls.key configuration
options, respectively. Adjust the file paths in the configuration if necessary.

Client Certificates: If you want to restrict access to clients with specific
client certificates, ensure that the directory specified in the
tls.client_certs configuration option contains the required client certificate
files.


If you want to enforce the requirement for clients to provide an x-api-key
header, make sure to set the key configuration option under [endpoints] to the
desired value. Clients connecting to the service will need to include this
header with the configured value for successful authentication.


# Usage

```
Usage: openvasd [OPTIONS]

Options:
  -c, --config <config>
          path to toml config file [env: OPENVASD_CONFIG=]
      --feed-path <feed-path>
          path to openvas feed [env: FEEED_PATH=]
      --feed-check-interval <SECONDS>
          interval to check for feed updates in seconds [env: FEED_CHECK_INTERVAL=]
      --tls-certs <tls-certs>
          path to server tls certs [env: TLS_CERTS=]
      --tls-key <tls-key>
          path to server tls key [env: TLS_KEY=]
      --tls-client-certs <tls-client-certs>
          path to client tls certs. Enables mtls. [env: TLS_CLIENT_CERTS=]
      --enable-get-scans
          enable get scans endpoint [env: ENABLE_GET_SCANS=]
      --api-key <api-key>
          API key that must be set as X-API-KEY header to gain access [env: API_KEY=]
      --ospd-socket <ospd-socket>
          socket to ospd [env: OSPD_SOCKET=]
      --result-check-interval <SECONDS>
          interval to check for new results in seconds [env: RESULT_CHECK_INTERVAL=]
  -l, --listening <IP:PORT>
          the address to listen to (e.g. 127.0.0.1:3000 or 0.0.0.0:3000). [env: LISTENING=]
  -L, --log-level <log-level>
          Level of log messages to be shown. TRACE > DEBUG > INFO > WARN > ERROR [env: OPENVASD_LOG=]
  -h, --help
          Print help
```

# Options

| Option                  | Long Command            | Short Command | Config Section             | Config Name      | Environment Variable  | Description                                                                                                      | Default Value            |
| ----------------------- | ----------------------- | ------------- | -------------------------- | ---------------- | --------------------- | ---------------------------------------------------------------------------------------------------------------- | ------------------------ |
| Config Path             | --config                | -c            |                            |                  | OPENVASD_CONFIG       | Path to toml config file                                                                                         |                          |
| Feed Path               | --feed-path             |               | feed                       | path             | FEEED_PATH            | Path to openvas feed                                                                                             | /var/lib/openvas/plugins |
| Feed Check Interval     | --feed-check-interval   |               | feed.check_interval        | secs</br>nanos   | FEED_CHECK_INTERVAL   | Interval to check for feed updates in seconds. Using the config file, it can be set in seconds and nanoseconds   | 3600 (seconds)           |
| TLS Certificates        | --tls-certs             |               | tls                        | certs            | TLS_CERTS             | Path to server TLS certs file. If none is given, TLS is disabled                                                 |                          |
| TLS Key                 | --tls-key               |               | tls                        | key              | TLS_KEY               | Path to server TLS key                                                                                           |                          |
| TLS Client Certificates | --tls-client-certs      |               | tls                        | client_certs     | TLS_CLIENT_CERTS      | Path to client TLS certs enables mTLS                                                                            |                          |
| Enable get scans        | --enable-get-scans      |               | endpoints                  | enable_get_scans | ENABLE_GET_SCANS      | Enables GET /scans endpoint                                                                                      | false                    |
| API key                 | --api-key               |               | endpoints                  | key              | API_KEY               | API key that must be set as X-API-KEY header to gain access. If none is given, api-key authorization is disabled |                          |
| OSPD Socket             | --opsd-socket           |               | ospd                       | socket           | OSPD_SOCKET           | Path to the unix socket of ospd-openvas                                                                          | /var/run/ospd/ospd.sock  |
| Result Check Interval   | --result-check-interval |               | ospd.result_check_interval | secs</br>nanos   | RESULT_CHECK_INTERVAL | Interval to check for new results in seconds. Using the config file, it can be set in seconds and nanoseconds    | 1 (second)               |
| Listening               | --listening             | -l            | listener                   | address          | LISTENING             | IP address and port to listen to                                                                                 | 127.0.0.1:3000           |
| Log Level               | --log-level             | -L            | log                        | level            | OPENVASD_LOG          | Level of log messages to be shown. TRACE > DEBUG > INFO > WARN > ERROR                                           | INFO                     |
| Help                    | --help                  | -h            |                            |                  |                       | Print help                                                                                                       |                          |