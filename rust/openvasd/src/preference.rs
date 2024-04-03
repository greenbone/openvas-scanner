// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use lazy_static::lazy_static;
use models::{PreferenceValue, ScanPreferenceInformation};

pub const PREFERENCES: [ScanPreferenceInformation; 22] = [
    ScanPreferenceInformation {
        id: "auto_enable_dependencies",
        name: "Automatic Enable Dependencies",
        default: PreferenceValue::Bool(true),
        description: "OpenVAS plugins use the result of each other to execute their job. For \
        instance, a plugin which logs into the remote SMB registry will need the results of the \
        plugin which finds the SMB name of the remote host and the results of the plugin which \
        attempts to log into the remote host. If you want to only select a subset of the plugins \
        available, tracking the dependencies can quickly become tiresome. If you set this option \
        to 'yes', openvas will automatically enable the plugins that are depended on.",
    },
    ScanPreferenceInformation {
        id: "cgi_path",
        name: "CGI Path",
        default: PreferenceValue::String("/cgi-bin:/scripts"),
        description: "By default, openvas looks for default CGIs in /cgi-bin and /scripts. \
        You may change these to something else to reflect the policy of your \
        site. The syntax of this option is the same as the shell $PATH \
        variable: path1:path2:...",
    },
    ScanPreferenceInformation {
        id: "checks_read_timeout",
        name: "Checks Read Timeout",
        default: PreferenceValue::Int(5),
        description: "Number of seconds that the security checks will wait for when doing \
        a recv(). You should increase this value if you are running openvas \
        across a slow network slink (testing a host via a dialup connection \
        for instance)",
    },
    ScanPreferenceInformation {
        id: "non_simult_ports",
        name: "Non simultaneous ports",
        default: PreferenceValue::String("139, 445, 3389, Services/irc"),
        description: "Some services (in particular SMB) do not appreciate multiple \
        connections at the same time coming from the same host. This option \
        allows you to prevent openvas to make two connections on the same \
        given ports at the same time. The syntax of this option is \
        'port1[, port2...]'. Note that you can use the KB notation of \
        openvas to designate a service formally. Ex: '139, Services/www', \
        will prevent openvas from making two connections at the same time on \
        port 139 and on every port which hosts a web server.",
    },
    ScanPreferenceInformation {
        id: "open_sock_max_attempts",
        name: "Maximum Attempts to open Sockets",
        default: PreferenceValue::Int(5),
        description: "When a port is found as opened at the beginning of the scan, and for \
        some reason the status changes to filtered/closed, it will not be \
        possible to open a socket. This is the number of unsuccessful \
        retries to open the socket before to set the port as closed. This \
        avoids to launch plugins which need the opened port as a mandatory \
        key, therefore it avoids an overlong scan duration. If the set value \
        is 0 or a negative value, this option is disabled. It should be take \
        in account that one unsuccessful attempt needs the number of retries \
        set in 'Socket timeout retry'.",
    },
    ScanPreferenceInformation {
        id: "timeout_retry",
        name: "Socket timeout retry",
        default: PreferenceValue::Int(5),
        description: "Number of retries when a socket connection attempt times out. This option \
        is different from 'Maximum Attempts to open Sockets', as after the number of retries \
        here is reached it counts as a single attempt for open the socket.",
    },
    ScanPreferenceInformation {
        id: "optimize_test",
        name: "Optimize Test",
        default: PreferenceValue::Bool(true),
        description: "By default, optimize_test is enabled which means openvas does trust \
        the remote host banners and is only launching plugins against the \
        services they have been designed to check. For example it will check \
        a web server claiming to be IIS only for IIS related flaws but will \
        skip plugins testing for Apache flaws, and so on. This default \
        behavior is used to optimize the scanning performance and to avoid \
        false positives. If you are not sure that the banners of the remote \
        host have been tampered with, you can disable this option.",
    },
    ScanPreferenceInformation {
        id: "plugins_timeout",
        name: "Plugins Timeout",
        default: PreferenceValue::Int(5),
        description: "This is the maximum lifetime, in seconds of a plugin. It may happen \
        that some plugins are slow because of the way they are written or \
        the way the remote server behaves. This option allows you to make \
        sure your scan is never caught in an endless loop because of a \
        non-finishing plugin. Doesn't affect ACT_SCANNER plugins, use \
        'ACT_SCANNER plugins timeout' for them instead.",
    },
    ScanPreferenceInformation {
        id: "report_host_details",
        name: "Report Host Details",
        default: PreferenceValue::Bool(true),
        description: "Host Details are general Information about a Host collected during a scan. \
        These are used internally for plugins, but it is also possible to report these \
        as results. In order for this option to work the Plugin 'Host Details' with the OID \
        1.3.6.1.4.1.25623.1.0.103997 must also be in the VTs list, as this plugin is responsible \
        for doing the actual reporting.",
    },
    ScanPreferenceInformation {
        id: "safe_checks",
        name: "Safe Checks",
        default: PreferenceValue::Bool(true),
        description: "Most of the time, openvas attempts to reproduce an exceptional \
        condition to determine if the remote services are vulnerable to \
        certain flaws. This includes the reproduction of buffer overflows or \
        format strings, which may make the remote server crash. If you set \
        this option to 'true', openvas will disable the plugins which have \
        the potential to crash the remote services, and will at the same \
        time make several checks rely on the banner of the service tested \
        instead of its behavior towards a certain input. This reduces false \
        positives and makes openvas nicer towards your network, however this \
        may make you miss important vulnerabilities (as a vulnerability \
        affecting a given service may also affect another one).",
    },
    ScanPreferenceInformation {
        id: "scanner_plugins_timeout",
        name: "ACT_SCANNER plugins timeout",
        default: PreferenceValue::Int(36000),
        description: "Like 'Plugins Timeout', but for ACT_SCANNER plugins.",
    },
    ScanPreferenceInformation {
        id: "time_between_request",
        name: "Time between Requests",
        default: PreferenceValue::Int(0),
        description: "Some devices do not appreciate quick connection establishment and \
        termination neither quick request. This option allows you to set a \
        wait time between two actions like to open a tcp socket, to send a \
        request through the open tcp socket, and to close the tcp socket. \
        This value should be given in milliseconds. If the set value is 0 \
        (default value), this option is disabled and there is no wait time \
        between requests.",
    },
    ScanPreferenceInformation {
        id: "unscanned_closed",
        name: "Close unscanned Port TCP",
        default: PreferenceValue::Bool(true),
        description: "This defines whether TCP ports that were not scanned should be treated like closed ports.",
    },
    ScanPreferenceInformation {
        id: "unscanned_closed_udp",
        name: "Close unscanned Port UDP",
        default: PreferenceValue::Bool(true),
        description: "This defines whether UDP ports that were not scanned should be treated as closed ports.",
    },
    ScanPreferenceInformation {
        id: "expand_vhosts",
        name: "Expand VHosts",
        default: PreferenceValue::Bool(true),
        description: "Whether to expand the target host's list of vhosts with values \
        gathered from sources such as reverse-lookup queries and VT checks \
        for SSL/TLS certificates.",
    },
    ScanPreferenceInformation {
        id: "test_empty_vhost",
        name: "Test Empty VHost",
        default: PreferenceValue::Bool(false),
        description: "If set to yes, the scanner will also test the target by using empty \
        vhost value in addition to the target's associated vhost values.",
    },
    ScanPreferenceInformation {
        id: "alive_test_ports",
        name: "Alive Test Ports",
        default: PreferenceValue::String(
            "21-23,25,53,80,110-111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080",
        ),
        description: "Preference to set the port list for the TCP SYN and TCP ACK alive test \
        methods.",
    },
    ScanPreferenceInformation {
        id: "test_alive_hosts_only",
        name: "Test Alive Hosts Only",
        default: PreferenceValue::Bool(false),
        description: "If this option is set to 'true', openvas will scan the target list \
        for alive hosts in a separate process while only testing those hosts \
        which are identified as alive. This boosts the scan speed of target \
        ranges with a high amount of dead hosts significantly.",
    },
    ScanPreferenceInformation {
        id: "test_alive_wait_timeout",
        name: "Alive Test Timeout",
        default: PreferenceValue::Int(1),
        description: "This option is to set how long (in sec) Boreas (alive test) waits for \
        replies after last packet was sent.",
    },
    ScanPreferenceInformation {
        id: "table_driven_lsc",
        name: "Table Driven LSC",
        default: PreferenceValue::Bool(true),
        description: "This option will enable table driven local security Checks (LSC). This means \
        gathered packages are sent to an specialized scanner. This is far more efficient than doing \
        checks via NASL.",
    },
    ScanPreferenceInformation {
        id: "dry_run",
        name: "Dry Run",
        default: PreferenceValue::Bool(false),
        description: "A dry run is a simulated scan, with no actual host scanned. This mode \
        is useful for automated testing and also to check up, if the setup is actually working.",
    },
    ScanPreferenceInformation {
        id: "results_per_host",
        name: "Results per Host",
        default: PreferenceValue::Int(10),
        description: "Amount of fake results generated per each host in the target \
        list for a dry run scan.",
    },
];

lazy_static! {
    pub static ref PREFERENCES_JSON: String = serde_json::to_string(&PREFERENCES).unwrap();
}
