# OpenVAS Daemon

Is the implementation for [scanner-api](https://greenbone.github.io/scanner-api/).

Currently it is utilizing ospd-openvas.

The log level can be adjusted with the env variable `OPENVASD_LOG` and can have the following values:

- TRACE
- DEBUG
- INFO
- WARN
- ERROR

the default is `INFO`.

# Requirements

It requires a running ospd-openvas instance.

## Configuration

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
          path to openvas feed [env: FEEED_PATH=] [default: /var/lib/openvas/plugins]
      --feed-check-interval <SECONDS>
          interval to check for feed updates in seconds [env: FEED_CHECK_INTERVAL=] [default: 3600]
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
          socket to ospd [env: OSPD_SOCKET=] [default: /var/run/ospd/ospd.sock]
      --result-check-interval <SECONDS>
          interval to check for new results in seconds [env: RESULT_CHECK_INTERVAL=] [default: 1]
  -l, --listening <IP:PORT>
          the address to listen to (e.g. 127.0.0.1:3000 or 0.0.0.0:3000). [env: LISTENING=] [default: 127.0.0.1:3000]
  -L, --log-level <log-level>
          Level of log messages to be shown. TRACE > DEBUG > INFO > WARN > ERROR [env: OPENVASD_LOG=] [default: INFO]
  -h, --help
          Print help
```
