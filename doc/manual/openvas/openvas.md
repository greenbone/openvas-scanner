# openvas

## NAME

openvas - The Scanner of the Greenbone Vulnerability Management

## SYNOPSIS

**openvas \[ -V \] \[ -h \] \[ -c ***config-file ***\] \[ \--scan-start
***scan-uuid ***\"\]** ** \[ -u \] \[ -s \] \[ -y \]**

## DESCRIPTION

**Greenbone Vulnerability Management (GVM)** is a vulnerability auditing
and management framework made up of several modules. The OpenVAS
Scanner, **openvas** is in charge of executing many security tests
against many target hosts in a highly optimized way.

**openvas** inspects the remote hosts to list all the vulnerabilities
and common misconfigurations that affects them.

It is a command line tool with parameters to update the feed of
vulnerability tests and to start a scan. The second part of the
interface is the redis store where the parameters about a scan task need
to be placed and from where the results can be retrieved.

## OPTIONS

**-c ***\<config-file\>***, \--config-file=***\<config-file\>*

:   Use the alternate configuration file instead of *\@OPENVAS_CONF@*

**-V, \--version**

:   Prints the version number and exits

**-h, \--help**

:   Show a summary of the commands

**\--scan-start=***\<scan-uuid\>*

:   ID for a single scan task. The scanner will start the scan with the
    data already loaded in a redis KB, which will be found using the
    given scan-id.

**\--scan-stop=***\<scan-uuid\>*

:   ID for a single scan task. The scanner will search the redis kb
    associated to the given scan_id. It takes the pid from the kb and
    sends the SIGUSR1 kill signal to stop the scan.

**-u, \--update-vt-info**

:   Updates VT info into redis store from VT files.

## THE CONFIGURATION FILE

The default **openvas** configuration file, *\@OPENVAS_CONF@* contains
these options:

plugins_folder

:   Contains the location of the plugins folder. This is usually
    \@OPENVAS_NVT_DIR@, but you may change this.

max_hosts

:   is maximum number of hosts to test at the same time which should be
    given to the client (which can override it). This value must be
    computed given your bandwidth, the number of hosts you want to test,
    your amount of memory and the horsepower of your processor(s).

max_checks

:   is the number of plugins that will run against each host being
    tested. Note that the total number of process will be *max_checks* x
    *max_hosts* so you need to find a balance between these two options.
    Note that launching too many plugins at the same time may disable
    the remote host, either temporarily (ie: inetd closes its ports) or
    definitely (the remote host crash because it is asked to do too many
    things at the same time), so be careful.

log_whole_attack

:   If this option is set to \'yes\', openvas will store the name, pid,
    date and target of each plugin launched. This is helpful for
    monitoring and debugging purpose, however this option might make
    openvas fill your disk rather quickly.

debug_tls

:   This is an scanner-only option which allows you to set the TLS log
    level. The level is an integer between 0 and 9. Higher values mean
    more verbosity and might make openvas fill your disk rather quickly.
    The default value is 0 (disabled).

Larger values should only be used with care, since they may reveal
sensitive information in the scanner logs.

Use a debug level over 10 to enable all debugging options.

log_plugins_name_at_load

:   If this option is set to \'yes\', openvas will log the name of each
    plugin being loaded at startup, or each time it receives the HUP
    signal.

cgi_path

:   By default, openvas looks for default CGIs in /cgi-bin and /scripts.
    You may change these to something else to reflect the policy of your
    site. The syntax of this option is the same as the shell \$PATH
    variable: path1:path2:\...

port_range

:   This is the default range of ports that the scanner plugins will
    probe. The syntax of this option is flexible, it can be a single
    range (\"1-1500\"), several ports (\"21,23,80\"), several ranges of
    ports (\"1-1500,32000-33000\"). Note that you can specify UDP and
    TCP ports by prefixing each range by T or U. For instance, the
    following range will make openvas scan UDP ports 1 to 1024 and TCP
    ports 1 to 65535 : \"T:1-65535,U:1-1024\".

test_alive_hosts_only

:   If this option is set to \'yes\', openvas will scan the target list
    for alive hosts in a separate process while only testing those hosts
    which are identified as alive. This boosts the scan speed of target
    ranges with a high amount of dead hosts significantly.

alive_test_ports

:   Preference to set the port list for the TCP SYN and TCP ACK alive test
    methods. This setting overwrites the default port list:
    "21-23,25,53,80,110-111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080".

test_alive_wait_timeout

:   This option is to set how long (in sec) Boreas (alive test) waits for
    replies after last packet was sent. Default: 3 seconds

optimize_test

:   By default, optimize_test is enabled which means openvas does trust
    the remote host banners and is only launching plugins against the
    services they have been designed to check. For example it will check
    a web server claiming to be IIS only for IIS related flaws but will
    skip plugins testing for Apache flaws, and so on. This default
    behavior is used to optimize the scanning performance and to avoid
    false positives. If you are not sure that the banners of the remote
    host have been tampered with, you can disable this option.

test_empty_vhost

:   If set to yes, the scanner will also test the target by using empty
    vhost value in addition to the target\'s associated vhost values.

checks_read_timeout

:   Number of seconds that the security checks will wait for when doing
    a recv(). You should increase this value if you are running openvas
    across a slow network slink (testing a host via a dialup connection
    for instance)

timeout_retry

:   Number of retries when a socket connection attempt times out.

open_sock_max_attempts

:   When a port is found as opened at the beginning of the scan, and for
    some reason the status changes to filtered/closed, it will not be
    possible to open a socket. This is the number of unsuccessful
    retries to open the socket before to set the port as closed. This
    avoids to launch plugins which need the opened port as a mandatory
    key, therefore it avoids an overlong scan duration. If the set value
    is 0 or a negative value, this option is disabled. It should be take
    in account that one unsuccessful attempt needs the number of retries
    set in \"timeout_retry\".

time_between_request

:   Some devices do not appreciate quick connection establishment and
    termination neither quick request. This option allows you to set a
    wait time between two actions like to open a tcp socket, to send a
    request through the open tcp socket, and to close the tcp socket.
    This value should be given in milliseconds. If the set value is 0
    (default value), this option is disabled and there is no wait time
    between requests.

expand_vhosts

:   Whether to expand the target host\'s list of vhosts with values
    gathered from sources such as reverse-lookup queries and VT checks
    for SSL/TLS certificates.

non_simult_ports

:   Some services (in particular SMB) do not appreciate multiple
    connections at the same time coming from the same host. This option
    allows you to prevent openvas to make two connections on the same
    given ports at the same time. The syntax of this option is
    \"port1\[, port2\...\]\". Note that you can use the KB notation of
    openvas to designate a service formally. Ex: \"139, Services/www\",
    will prevent openvas from making two connections at the same time on
    port 139 and on every port which hosts a web server.

allow_simultaneous_ips

:   If set to no, this option prevent openvas to scan more than one
    different IPs (e.g. the IPv4 and IPv6 addresses) which belong to the
    same host at the same time. Default, yes.

plugins_timeout

:   This is the maximum lifetime, in seconds of a plugin. It may happen
    that some plugins are slow because of the way they are written or
    the way the remote server behaves. This option allows you to make
    sure your scan is never caught in an endless loop because of a
    non-finishing plugin. Doesn\'t affect ACT_SCANNER plugins.

scanner_plugins_timeout

:   Like plugins_timeout, but for ACT_SCANNER plugins.

max_vts_timeouts

:   During a scan it might happen that a host unexpectedly shuts down, a
    firewall blocks the traffic, a network device issue break the
    connection, etc. This leads to many NVT timeouts and long scan
    durations. This option checks the alive status of the host again
    after the provided amount of max NVT timeouts are reached. If the
    host is considered dead the scan will be stopped for this host.
    Otherwise the scan will continue. This option requires Boreas alive
    test to be enabled. Default: option not set, disabled.

safe_checks

:   Most of the time, openvas attempts to reproduce an exceptional
    condition to determine if the remote services are vulnerable to
    certain flaws. This includes the reproduction of buffer overflows or
    format strings, which may make the remote server crash. If you set
    this option to \'yes\', openvas will disable the plugins which have
    the potential to crash the remote services, and will at the same
    time make several checks rely on the banner of the service tested
    instead of its behavior towards a certain input. This reduces false
    positives and makes openvas nicer towards your network, however this
    may make you miss important vulnerabilities (as a vulnerability
    affecting a given service may also affect another one).

auto_enable_dependencies

:   OpenVAS plugins use the result of each other to execute their job.
    For instance, a plugin which logs into the remote SMB registry will
    need the results of the plugin which finds the SMB name of the
    remote host and the results of the plugin which attempts to log into
    the remote host. If you want to only select a subset of the plugins
    available, tracking the dependencies can quickly become tiresome. If
    you set this option to \'yes\', openvas will automatically enable
    the plugins that are depended on.

hosts_allow

:   Comma-separated list of the only targets that are authorized to be
    scanned. Supports the same syntax as the list targets. Both target
    hostnames and the address to which they resolve are checked.
    Hostnames in hosts_allow list are not resolved however.

hosts_deny

:   Comma-separated list of targets that are not authorized to be
    scanned. Supports the same syntax as the list targets. Both target
    hostnames and the address to which they resolve are checked.
    Hostnames in hosts_deny list are not resolved however.

sys_hosts_allow

:   Like hosts_allow. Can\'t be overridden by the client.

sys_hosts_deny

:   Like hosts_deny. Can\'t be overridden by the client.

max_sysload

:   Maximum load on the system. Once this load is reached, no further
    VTs are started until the load drops below this value again.

min_free_mem

:   Minimum available memory (in MB) which should be kept free on the
    system. Once this limit is reached, no further VTs are started until
    sufficient memory is available again.

The other options in this file can usually be redefined by the client.

## NETWORK USAGE

Bear in mind that OpenVAS can be quite network intensive. Even if the
OpenVAS developers have taken every effort to avoid packet loss
(including transparently resending UDP packets, waiting for data to be
received in TCP connections, etc.) so bandwidth use should always be
closely monitored, with current server hardware, bandwidth is usually
the bottleneck in a OpenVAS scan. It might not became too apparent in
the final reports, scanners will still run, holes might be detected, but
you will risk to run into *false negatives* (i.e. OpenVAS will not
report a security hole that is present in a remote host)

Users might need to tune OpenVAS configuration if running the scanner in
low bandwidth conditions (*low* being \'less bandwidth that the one your
hardware system can produce) or otherwise will get erratic results.
There are several parameters that can be modified to reduce network
load:

checks_read_timeout

:   The default value is set to 5 seconds, that can (should) be
    increased if network bandwidth is low in the openvas.conf or
    openvasrc configuration files. Notice that it is recommended to
    increase this this value, if you are running a test outside your LAN
    (i.e. to Internet hosts through an Internet connection), to over 10
    seconds.

max_hosts

:   Number of hosts to test at the same time. It can be as low as you
    want it to be (obviously 1 is the minimum)

max_checks

:   Number of checks to test at the same time it can be as low as you
    want it to be and it will also reduce network load and improve
    performance (obviously 1 is the minimum) Notice that OpenVAS will
    spawn max_hosts \* max_checks processes.

drop_privileges

:   If this preference is set to \'yes\', OpenVAS will attempt to drop
    its root privilege before launching any VT and the new process owner
    is \'nobody\'; the default value of this preference is \'no\',
    meaning no change in behaviour.

nasl_drop_privileges_user

:   If a user is set, NASL functions can use this user to drop its root
    privilege. The new process owner is set only for those process
    calling a nasl function which supports a drop privileges action.
    This preference must not be mixed with \'drop_privileges\'. If
    \'drop_privileges\' is enabled, this option should not be used, as
    \'drop_privileges\' sets the owner to \'nobody\'

vendor_version

:   Use the alternate vendor instead of the default one during scans.

Other options might be using the QoS features offered by your server
operating system or your network to improve the bandwidth use.

It is not easy to give a bandwidth estimate for a OpenVAS run, you will
probably need to make your own counts. However, assuming you test 65536
TCP ports. This will require at least a single packet per port that is
at least 40 bytes large. Add 14 bytes for the ethernet header and you
will send 65536 \* (40 + 14) = 3670016 bytes. So for just probing all
TCP ports we may need a multitude of this as nmap will try to resend the
packets twice if no response is received.

A very rough estimate is that a full scan for UDP, TCP and RPC as well
as all NASL scripts may result in 8 to 32 MB worth of traffic per
scanned host. Reducing the amount of tested part and such will reduce
the amount of data to be transferred significantly.

## SEE ALSO

**gvmd(8)**, **gsad(8)**, **ospd-openvas(8)**, **[openvas-nasl(1)](../nasl/openvas-nasl.md)**,
**[openvas-nasl-lint(1)](../nasl/openvas-nasl-lint.md)**

## MORE INFORMATION

The canonical places where you will find more information about OpenVAS
are:

> [Community Portal](https://community.greenbone.net)\
> [Development Platform](https://github.com/greenbone)\
> [Traditional home site](https://www.openvas.org)

## AUTHORS

openvas was forked from nessusd in 2005. Nessusd was written by Renaud
Deraison \<deraison@cvs.nessus.org\>. Most new code since 2005 developed
by Greenbone Networks GmbH.
