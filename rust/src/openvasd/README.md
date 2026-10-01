# OpenVAS Daemon

Is the implementation for [scanner-api](https://greenbone.github.io/scanner-api/).

Currently it is utilizing ospd-openvas.

- [OpenVAS Daemon](#openvas-daemon)
- [Requirements](#requirements)
- [Configuration](#configuration)
  - [Authentication](#authentication)
    - [API Key](#api-key)
    - [Certificates](#certificates)
      - [How does mTLS works?](#how-does-mtls-works)
      - [Certificate Authority for pki](#certificate-authority-for-pki)
      - [mTLS with self-signed client certificates.](#mtls-with-self-signed-client-certificates)
  - [Mode](#mode)
- [Usage](#usage)
  - [Feed signature check.](#feed-signature-check)
- [Options](#options)
- [Migration from previous OSP commands](#migration-from-previous-osp-commands)

# Requirements

```
> readelf -d ./openvasd-x86_64-unknown-linux-gnu | grep NEEDED
 0x0000000000000001 (NEEDED)             Shared library: [libgcc_s.so.1]
 0x0000000000000001 (NEEDED)             Shared library: [libm.so.6]
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 0x0000000000000001 (NEEDED)             Shared library: [ld-linux-x86-64.so.2]
```


# Configuration

Create a configuration file under either:

- `/etc/openvasd/openvasd.toml`
- `$HOME/.config/openvasd/openvasd.toml`

or provide the `-c` flag when starting openvasd.

An example can be found [here](../../examples/openvasd/config.example.toml)

For customer-facing tuning guidance for `[container_image_scanner.image]`, see [Container Image Scanner Configuration](../../doc/container-image-scanner-configuration.md).

## Authentication

The API supports two kinds of authentication methods:
    
- API Key
- Certificates

The authentication modes are set within a configuration file or via the argument list, when starting the server.

The authentication is required for each request except for a HEAD request.

### API Key

An API key is a token that the client provides when doing API requests and are used to authorize access.

If you want to enforce the requirement for clients to provide an x-api-key
header, make sure to set the key configuration option under [endpoints] to the
desired value. Clients connecting to the service will need to include this
header with the configured value for successful authentication.

The `X-API-KEY` must be in the header

`curl --insecure --request GET https://localhost:3000/scans -H "X-API-KEY: mtls_is_preferred"`

### Certificates
    
Both methods TLS and Mutual TLS (mTLS) are supported for authentication, while the second is strongly recommended, since it guaranties that both network connection ends are who they say to be.

If you want to enable TLS for secure communication, ensure that the TLS
certificate files are in place and accessible.

Server Certificates: The server certificate and private key files should be
located at the paths specified in the tls.certs and tls.key configuration
options, respectively. Adjust the file paths in the configuration if necessary.

Client Certificates: If you want to restrict access to clients with specific
client certificates, ensure that the directory specified in the
tls.client_certs configuration option contains the required client certificate
files.

#### How does mTLS works?

It is similar to the known TLS, but there are some extra steps. In the following list of steps for stablishing a mTLS connection, the steps written in bold are the extra steps for mTLS:
1. The client connects to the server
2. The server presents its TLS certificate
3. The client verifies the server certificate
4. **The client presents its TLS certificate**
5. **The server verifies the client certificate**
6. **The server gives access to the client**
7. Client and server exchange information through a encrypted TLS connection.

#### Certificate Authority for pki

Who implements mTLS is its own Certification Authority. This is a difference from standard TLS, where an external organization verifies and validates the TLS certificates.
For mTLS is necessary a TLS root certificate which allows an organization to be its owns certificate authority. The root CA signs intermediate certificates forming a chain of trust. The intermediate CA is created for security reasons. then, the root certificate is used as less as possible and in case the intermediate key is compromised, the root CA can revoke the intermediate key and create a new one.
Finally, the intermediate CA is used to sign client and server certificates.

In the examples folder for a [PKI Mutual TLS](../../examples/tls/pki) you can find three scripts for creation of root and intermediate CA, client and server pairs (keys and certs).

Once you created the all key-certs pairs, you can use them for stablishing a mTLS secure connection between `openvasd` and the clients.

In the openvasd.toml configuration file, under the section `[tls]`:
- set the variable `certs` with the path to the server certificate,
- set the variable `key` with the path to the server key,
- set the variable `client_certs` with the path to the intermediate CA certificate.

You should store in a secure place the root and intermediate key, which are not necessary anymore, but only for revoke/create intermediate CA pairs.

On the client side, you use the client key, the client cert and the same intermediate CA certificate you use in the server side. An example of usage is the following curl command:

`curl --insecure --verbose  --cert client.cert --key client.key --cacert CA/ca.cert --request GET https://localhost:3000/scans -H "X-API-KEY: mtls_is_preferred"`

Now, since both server and client are signed by the same CA, certificates can be verified and the encrypted connection is authenticated.

#### mTLS with self-signed client certificates.

This method is similar to the explained above, but differs in that the clients and server certificates are self-signed, or signed by different CAs.
Then, the clients have to register a single certificate with the authorization server, and there is no shared CA certificate.
During authentication, the server checks if the client uses the same certificate for the TLS session as was configured or registered for that individual client. The server trusts the pinned certificate. The client's organization does not have to maintain any public key infrastructure and can simply use a self-signed certificate for authentication.

The scripts for generating the self-signed certificate can be found in [self-signed](../../examples/tls/self-signed) folder.

Once you created the all key-certs pairs, you can use them for stablishing a mTLS secure connection between `openvasd` and the clients.

In the openvasd.toml configuration file, under the section `[tls]`:
- set the variable `certs` with the path to the server certificate,
- set the variable `key` with the path to the server key,
- set the variable `client_certs` with the path to the folder with all registered client's self-signed certificates, previously shared via a secure method.

On the client side, you use the client key and the client certificate. An example of usage is the following curl command:

`curl --insecure --verbose  --cert client.cert --key client.key --request GET https://localhost:3000/scans -H "X-API-KEY: mtls_is_preferred"`

As can be seen, no CA certificate is used, since instead the client certificate is used on the server side.

## Mode

Openvasd currently supports two operation modes. The `service` mode supports all available endpoints, where the `service_notus` mode only supports the notus related endpoints.

# Usage

```
Usage: openvasd [OPTIONS]

Options:
  -c, --config <config>
          path to toml config file [env: OPENVASD_CONFIG=]
      --feed-path <feed-path>
          path to openvas feed. its parent directory must be writable unless --lock-file-dir is set [env: FEED_PATH=]
      --lock-file-dir <lock-file-dir>
          directory in which openvasd creates feed-update.lock. must be writable [env: LOCK_FILE_DIR=]
  -x, --feed-signature-check
          Deprecated. To enable or disable feed signature use the configuration.
      --feed-check-interval <SECONDS>
          interval to check for feed updates in seconds [env: FEED_CHECK_INTERVAL=]
      --advisories <notus-advisories>
          Path containing the Notus advisories directory [env: NOTUS_ADVISORIES=]
      --products <notus-products>
          Path containing the Notus products directory [env: NOTUS_PRODUCTS=]
      --notus-address <IP:PORT>
          the address to reach notus on [env: NOTUS_ADDRESS=]
      --redis-url <redis-url>
          Redis url. Either unix:// or redis:// [env: REDIS_URL=]
      --tls-certs <tls-certs>
          path to server tls certs [env: TLS_CERTS=]
      --tls-key <tls-key>
          path to server tls key [env: TLS_KEY=]
      --tls-client-certs <tls-client-certs>
          path to client tls certs. Enables mtls. [env: TLS_CLIENT_CERTS=]
      --enable-get-scans [<enable-get-scans>]
          enable get scans endpoint. Default 'false'. [env: ENABLE_GET_SCANS=] [possible values: true, false]
      --enable-get-performance [<enable-get-performance>]
          enable get performance endpoint. Default 'false'. [env: ENABLE_GET_PERFORMANCE=] [possible values: true, false]
      --api-key <api-key>
          API key that must be set as X-API-KEY header to gain access [env: API_KEY=]
      --scanner-type <ospd,openvas>
          Type of scanner used to manage scans [env: SCANNER_TYPE=]
      --max-queued-scans <max-queued-scans>
          Maximum number of queued scans [env: MAX_QUEUED_SCANS=]
      --max-running-scans <max-running-scans>
          Maximum number of active running scans, omit for no limits [env: MAX_RUNNING_SCANS=]
      --min-free-mem <min-free-mem>
          Minimum memory available to start a new scan [env: MIN_FREE_MEMORY=]
      --check_interval <SECONDS>
          Check interval of the Scheduler if a new scan can be started [env: SCHEDULER_CHECK_INTERVAL=]
      --ospd-socket <ospd-socket>
          socket to ospd [env: OSPD_SOCKET=]
      --read-timeout <SECONDS>
          read timeout in seconds on the ospd-openvas socket [env: READ_TIMEOUT=]
      --result-check-interval <SECONDS>
          interval to check for new results in seconds [env: RESULT_CHECK_INTERVAL=]
  -l, --listening <IP:PORT>
          the address to listen to (e.g. 127.0.0.1:3000 or 0.0.0.0:3000). [env: LISTENING=]
      --storage-type <redis,inmemory,fs>
          either be stored in memory or on the filesystem. [env: STORAGE_TYPE=]
      --storage-path <PATH>
          directory for the openvasd and container image scanner database files. must be writable [env: STORAGE_PATH=]
      --storage-key <KEY>
          the password to use for encryption when type is set to fs. If not set the files are not encrypted. [env: STORAGE_KEY=]
  -L, --log-level <log-level>
          Level of log messages to be shown. TRACE > DEBUG > INFO > WARN > ERROR [env: OPENVASD_LOG=]
      --version
          Show openvasd version and exit.
      --mode <service,service_notus>
          Sets the openvasd mode [env: OPENVASD_MODE=]
      --auto_enable_dependencies <auto_enable_dependencies>
          OpenVAS plugins use the result of each other to execute their job. For instance, a plugin which logs into the remote SMB registry will need the results of the plugin which finds the SMB name of the remote host and the results of the plugin which attempts to log into the remote host. If you want to only select a subset of the plugins available, tracking the dependencies can quickly become tiresome. If you set this option to 'yes', openvas will automatically enable the plugins that are depended on. [possible values: true, false]
      --cgi_path <cgi_path>
          By default, openvas looks for default CGIs in /cgi-bin and /scripts. You may change these to something else to reflect the policy of your site. The syntax of this option is the same as the shell $PATH variable: path1:path2:...
      --checks_read_timeout <checks_read_timeout>
          Number of seconds that the security checks will wait for when doing a recv(). You should increase this value if you are running openvas across a slow network slink (testing a host via a dialup connection for instance)
      --non_simult_ports <non_simult_ports>
          Some services (in particular SMB) do not appreciate multiple connections at the same time coming from the same host. This option allows you to prevent openvas to make two connections on the same given ports at the same time. The syntax of this option is 'port1[, port2...]'. Note that you can use the KB notation of openvas to designate a service formally. Ex: '139, Services/www', will prevent openvas from making two connections at the same time on port 139 and on every port which hosts a web server.
      --open_sock_max_attempts <open_sock_max_attempts>
          When a port is found as opened at the beginning of the scan, and for some reason the status changes to filtered/closed, it will not be possible to open a socket. This is the number of unsuccessful retries to open the socket before to set the port as closed. This avoids to launch plugins which need the opened port as a mandatory key, therefore it avoids an overlong scan duration. If the set value is 0 or a negative value, this option is disabled. It should be take in account that one unsuccessful attempt needs the number of retries set in 'Socket timeout retry'.
      --timeout_retry <timeout_retry>
          Number of retries when a socket connection attempt times out. This option is different from 'Maximum Attempts to open Sockets', as after the number of retries here is reached it counts as a single attempt for open the socket.
      --optimize_test <optimize_test>
          By default, optimize_test is enabled which means openvas does trust the remote host banners and is only launching plugins against the services they have been designed to check. For example it will check a web server claiming to be IIS only for IIS related flaws but will skip plugins testing for Apache flaws, and so on. This default behavior is used to optimize the scanning performance and to avoid false positives. If you are not sure that the banners of the remote host have been tampered with, you can disable this option. [possible values: true, false]
      --plugins_timeout <plugins_timeout>
          This is the maximum lifetime, in seconds of a plugin. It may happen that some plugins are slow because of the way they are written or the way the remote server behaves. This option allows you to make sure your scan is never caught in an endless loop because of a non-finishing plugin. Doesn't affect ACT_SCANNER plugins, use 'ACT_SCANNER plugins timeout' for them instead.
      --report_host_details <report_host_details>
          Host Details are general Information about a Host collected during a scan. These are used internally for plugins, but it is also possible to report these as results. In order for this option to work the Plugin 'Host Details' with the OID 1.3.6.1.4.1.25623.1.0.103997 must also be in the VTs list, as this plugin is responsible for doing the actual reporting. [possible values: true, false]
      --safe_checks <safe_checks>
          Most of the time, openvas attempts to reproduce an exceptional condition to determine if the remote services are vulnerable to certain flaws. This includes the reproduction of buffer overflows or format strings, which may make the remote server crash. If you set this option to 'true', openvas will disable the plugins which have the potential to crash the remote services, and will at the same time make several checks rely on the banner of the service tested instead of its behavior towards a certain input. This reduces false positives and makes openvas nicer towards your network, however this may make you miss important vulnerabilities (as a vulnerability affecting a given service may also affect another one). [possible values: true, false]
      --scanner_plugins_timeout <scanner_plugins_timeout>
          Like 'Plugins Timeout', but for ACT_SCANNER plugins.
      --time_between_request <time_between_request>
          Some devices do not appreciate quick connection establishment and termination neither quick request. This option allows you to set a wait time between two actions like to open a tcp socket, to send a request through the open tcp socket, and to close the tcp socket. This value should be given in milliseconds. If the set value is 0 (default value), this option is disabled and there is no wait time between requests.
      --unscanned_closed <unscanned_closed>
          This defines whether TCP ports that were not scanned should be treated like closed ports. [possible values: true, false]
      --unscanned_closed_udp <unscanned_closed_udp>
          This defines whether UDP ports that were not scanned should be treated as closed ports. [possible values: true, false]
      --expand_vhosts <expand_vhosts>
          Whether to expand the target host's list of vhosts with values gathered from sources such as reverse-lookup queries and VT checks for SSL/TLS certificates. [possible values: true, false]
      --test_empty_vhost <test_empty_vhost>
          If set to yes, the scanner will also test the target by using empty vhost value in addition to the target's associated vhost values. [possible values: true, false]
      --alive_test_ports <alive_test_ports>
          Preference to set the port list for the TCP SYN and TCP ACK alive test methods.
      --test_alive_hosts_only <test_alive_hosts_only>
          If this option is set to 'true', openvas will scan the target list for alive hosts in a separate process while only testing those hosts which are identified as alive. This boosts the scan speed of target ranges with a high amount of dead hosts significantly. [possible values: true, false]
      --test_alive_wait_timeout <test_alive_wait_timeout>
          This option is to set how long (in sec) Boreas (alive test) waits for replies after last packet was sent.
      --table_driven_lsc <table_driven_lsc>
          This option will enable table driven local security Checks (LSC). This means gathered packages are sent to a specialized scanner. This is far more efficient than doing checks via NASL. [possible values: true, false]
      --dry_run <dry_run>
          A dry run is a simulated scan, with no actual host scanned. This mode is useful for automated testing and also to check up, if the setup is actually working. [possible values: true, false]
      --results_per_host <results_per_host>
          Amount of fake results generated per each host in the target list for a dry run scan.
      --max_mem_kb <max_mem_kb>
          Maximum amount of memory (in MB) allowed to use for a single script. If this value is set, the amount of memory put into redis is tracked for every Script. If the amount of memory exceeds this limit, the script is not able to set more kb items. The tracked the value written into redis is only estimated, as it does not check, if a value was replaced or appended. The size of the key is also not tracked. If this value is not set or <= 0, the maximum amount is unlimited (Default).
  -h, --help
          Print help
```

## Feed signature check.

If the signature check is enabled, it is also required to set the the `GNUPGHOME` environment variable with the path to the keyring.

# Options

| Option                   | Long Command            | Short Command | Config Section                     | Config Name       | Environment Variable     | Description                                                                                                                                                               | Default Value                 |
| ------------------------ | ----------------------- | ------------- | ---------------------------------- | ----------------- | ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------- |
| Config Path              | --config                | -c            |                                    |                   | OPENVASD_CONFIG          | Path to toml config file                                                                                                                                                  |                               |
| Feed Path                | --feed-path             |               | feed                               | path              | FEED_PATH                | Path to the OpenVAS feed. If no lock file directory is configured, its parent directory must be writable.                                                                 | /var/lib/openvas/plugins      |
| Feed lock file directory | --lock-file-dir         |               | feed                               | lock_file_dir     | LOCK_FILE_DIR            | Directory in which `openvasd` creates `feed-update.lock`; must be writable. Defaults to the parent directory of the feed path.                                            | /var/lib/openvas              |
| Feed Signature Check     | --feed-signature-check  | -x            | feed                               | signature_check   |                          | Enable feed signature check.                                                                                                                                              | false                         |
| Feed Check Interval      | --feed-check-interval   |               | feed.check_interval                | secs</br>nanos    | FEED_CHECK_INTERVAL      | Interval to check for feed updates in seconds. Using the config file, it can be set in seconds and nanoseconds                                                            | 3600 (seconds)                |
| Notus advisories path    | --advisories            |               | notus                              | advisories_path   | NOTUS_ADVISORIES         | Path containing the Notus advisories directory                                                                                                                            | /var/lib/notus/advisories/    |
| Notus products path      | --products              |               | notus                              | products_path     | NOTUS_PRODUCTS           | Path containing the Notus products                                                                                                                                        | /var/lib/notus/products/      |
| Redis URL                | --redis-url             |               | storage.redis                      | url               | REDIS_URL                | Redis url. Either unix:// or redis://                                                                                                                                     | redis://localhost:6379        |
| TLS Certificates         | --tls-certs             |               | tls                                | certs             | TLS_CERTS                | Path to server TLS certs file. If none is given, TLS is disabled                                                                                                          |                               |
| TLS Key                  | --tls-key               |               | tls                                | key               | TLS_KEY                  | Path to server TLS key                                                                                                                                                    |                               |
| TLS Client Certificates  | --tls-client-certs      |               | tls                                | client_certs      | TLS_CLIENT_CERTS         | Path to client TLS certs enables mTLS                                                                                                                                     |                               |
| Enable get scans         | --enable-get-scans      |               | endpoints                          | enable_get_scans  | ENABLE_GET_SCANS         | Enables GET /scans endpoint                                                                                                                                               | false                         |
| API key                  | --api-key               |               | endpoints                          | key               | API_KEY                  | API key that must be set as X-API-KEY header to gain access. If none is given, api-key authorization is disabled                                                          |                               |
| Scanner Type             | --scanner-type          |               | scanner                            | type              | SCANNER_TYPE             | Type of wrapper used to manage scans, currently only `OSPD` is available                                                                                                  | OSPD                          |
| Max queued scans         | --max-queued-scans      |               | scheduler                          | max_queued_scans  | MAX_QUEUED_SCANS         | Maximum number of queued scans, omit for no limits                                                                                                                        |                               |
| Max running scans        | --max-running-scans     |               | scheduler                          | max_running_scans | MAX_RUNNING_SCANS        | Maximum number of active running scans, omit for no limits                                                                                                                |                               |
| Min free memory          | --min-free-mem          |               | scheduler                          | min_free_mem      | MIN_FREE_MEMORY          | Minimum memory that must be available in order to start a scan. If not set, there is no limit.                                                                            |                               |
| Scheduler check interval | --check-interval        |               | scheduler.check_interval           | secs</br>nanos    | SCHEDULER_CHECK_INTERVAL | Iteration interval for the scheduler                                                                                                                                      | secs = 0<br>nanos = 500000000 |
| OSPD Socket              | --opsd-socket           |               | scanner.ospd                       | socket            | OSPD_SOCKET              | Path to the unix socket of ospd-openvas                                                                                                                                   | /var/run/ospd/ospd.sock       |
| Socket read timeout      | --read-timeout          |               | scanner.ospd.read_timeout          | secs</br>nanos    | READ_TIMEOUT             | Max time openvasd waits for an ospd-openvas response before returning a 500 code (Internal server error). Using the config file, it can be set in seconds and nanoseconds | Waits forever                 |
| Result Check Interval    | --result-check-interval |               | scanner.ospd.result_check_interval | secs</br>nanos    | RESULT_CHECK_INTERVAL    | Interval to check for new results in seconds. Using the config file, it can be set in seconds and nanoseconds                                                             | 1 (second)                    |
| Listening                | --listening             | -l            | listener                           | address           | LISTENING                | IP address and port to listen to                                                                                                                                          | 127.0.0.1:3000                |
| Storage type             | --storage-type          |               | storage                            | type              | STORAGE_TYPE             | Information can either be stored in memory or on the filesystem                                                                                                           | inmemory                      |
| Storage path             | --storage-path          |               | storage                            | location          | STORAGE_PATH             | Directory for the main and container image scanner SQLite databases; must be writable. `in-memory` does not use a directory.                                              | in-memory                     |
| Log Level                | --log-level             | -L            | log                                | level             | OPENVASD_LOG             | Level of log messages to be shown. TRACE > DEBUG > INFO > WARN > ERROR                                                                                                    | INFO                          |
| Service mode             | --mode                  |               |                                    | mode              | OPENVASD_MODE            | Sets the openvasd mode, can be either `service` or `service_notus`                                                                                                        | service                       |
| Help                     | --help                  | -h            |                                    |                   |                          | Print help                                                                                                                                                                |                               |

# Migration from previous OSP commands

In this [page](../../doc/openvasd-osp-cmd-equivalence.md) you can find a guide for API usage of previous OSP commands
