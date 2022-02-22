# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [22.4] (unreleased)

### Added
- Add support for volatile keys. [#682](https://github.com/greenbone/openvas/pull/682)
- Extend nasl lint to check Syntax for Arguments for script_xref() function. [#714](https://github.com/greenbone/openvas/pull/714)
- Recheck alive status of host with specified amount of NVT timeouts. [#729](https://github.com/greenbone/openvas/pull/729)
- Integrate sentry for debugging purposes [#742](https://github.com/greenbone/openvas/pull/742)
- Add support for non-interactive shell to nasl_ssh_shell_open().
  [#744](https://github.com/greenbone/openvas/pull/744)
  [#757](https://github.com/greenbone/openvas/pull/757)
- Add message type validation for proto_post_wrapped. [#805](https://github.com/greenbone/openvas/pull/805)
- Add nasl function sftp_enabled_check() to check if sftp subsystem is enabled in the target.
  - [#853](https://github.com/greenbone/openvas/pull/853)
  - [#862](https://github.com/greenbone/openvas/pull/862)
- Add `find_all` to eregmatch() nasl function. Backport PR #875. [#876](https://github.com/greenbone/openvas/pull/876)
- Add nasl functions for checking ssl/tls secure renegotiation and performing re-handshake. [#889](https://github.com/greenbone/openvas/pull/889)
- Fix Segmentation fault when freeing hosts and alive hosts [#888](https://github.com/greenbone/openvas/pull/888)

### Changed
- function script_bugtraq_id getting skipped, linter warns. [#724](https://github.com/greenbone/openvas/pull/724)
- Refactor dead host status sending. [#807](https://github.com/greenbone/openvas/pull/807)
- Refactor openvas.c.
  [#810](https://github.com/greenbone/openvas/pull/810)
  [#811](https://github.com/greenbone/openvas/pull/811)
- Handle script timeout as script preference with ID 0 [#844](https://github.com/greenbone/gvm-libs/pull/844)

### Fixed
- Use fchmod to change file permission instead of on open to prevent race conditions [854](https://github.com/greenbone/openvas-scanner/pull/854)
- Several minor potential security risks in different files, spotted by Code QL [854](https://github.com/greenbone/openvas-scanner/pull/854)
- Fix plugins upload. Backport #878 [#880](https://github.com/greenbone/openvas/pull/880)
- Fix Error Message when NVTI chache init failed. Backport #885 [#887](https://github.com/greenbone/openvas/pull/887)
- Fix Segmentation fault when freeing hosts and alive hosts [#888](https://github.com/greenbone/openvas/pull/888)

### Removed
- Remove handling of source_iface related preferences. [#730](https://github.com/greenbone/openvas/pull/730)

[22.4]: https://github.com/greenbone/openvas-scanner/compare/stable...main

## [21.4.3] (unreleased)
### Added
- Add nasl function sftp_enabled_check() to check if sftp subsystem is enabled in the target.
  - [#853](https://github.com/greenbone/openvas/pull/853)
  - [#862](https://github.com/greenbone/openvas/pull/862)

### Changed
- Changed defaults for installation locations [#826](https://github.com/greenbone/openvas-scanner/pull/826)
  - SYSCONFDIR is /etc by default now
  - LOCALSTATEDIR is /var by default now
  - OPENVAS_RUN_DIR is /run/ospd by default now
  - OPENVAS_FEED_LOCK_PATH is /var/lib/openvas/feed-update.lock by default now

### Deprecated
### Removed
### Fixed
- Fix interrupted scan, when the process table is full. [#832](https://github.com/greenbone/openvas-scanner/pull/832)
- Use fchmod to change file permission instead of on open to prevent race conditions [854](https://github.com/greenbone/openvas-scanner/pull/854)
- Fix plugins upload [#878](https://github.com/greenbone/openvas/pull/878)
- Fix Error Message when NVTI chache init failed [#885](https://github.com/greenbone/openvas/pull/885)
- Fix potential segfault.[#884](https://github.com/greenbone/openvas/pull/884)

[21.4.3]: https://github.com/greenbone/openvas-scanner/compare/v21.4.2...stable

## [21.4.2] - 2021-08-03
### Fixed
- Fix clang-analyzer warnings.
  [#791](https://github.com/greenbone/openvas/pull/791)
  [#795](https://github.com/greenbone/openvas/pull/795)

[21.4.2]: https://github.com/greenbone/openvas-scanner/compare/v21.4.1...v21.4.2

## [21.4.1] - 2021-06-23

### Added
- Improve nasl linter to catch more cases of undeclared variables. [#728](https://github.com/greenbone/openvas-scanner/pull/728)
- Add deprecation warning for source_iface related settings which will be removed with the 22.4 release. [#732](https://github.com/greenbone/openvas-scanner/pull/732)
- New Credentials for SSH to get su privileges. Backport of [#744](https://github.com/greenbone/openvas-scanner/pull/744). [#753](https://github.com/greenbone/openvas-scanner/pull/753)

### Changed
- Update default log config [#711](https://github.com/greenbone/openvas-scanner/pull/711)

### Fixed
- Use host from the original hosts list when boreas is enabled. [#725](https://github.com/greenbone/openvas/pull/725)
- Initialize the the kb to store results for openvas-nasl [#735](https://github.com/greenbone/openvas/pull/735)
- Fix unittest. Mock kb_lnk_reset. [#748](https://github.com/greenbone/openvas/pull/748)

### Removed

[21.4.1]: https://github.com/greenbone/openvas/compare/v21.4.1...stable

## [21.4.0] - 2021-04-15

### Added
- Add scanner-only option to enable tls debugging. [#558](https://github.com/greenbone/openvas/pull/558)
- Extend nasl lint to detect if function parameter is used twice. [#585](https://github.com/greenbone/openvas/pull/585)
- Add option to specify if a host can be scanned through its IPv4 and IPv6 in parallel.
  [#604](https://github.com/greenbone/openvas/pull/604)
  [#645](https://github.com/greenbone/openvas/pull/645)
- Add insert_tcp_options and insert_tcp_v6_options nasl functions. [#618](https://github.com/greenbone/openvas/pull/618)
- Add get_tcp_option and extend dump_tcp_packet nasl functions. [#621](https://github.com/greenbone/openvas/pull/621)
- Add new scanner only option for spawning NASL functions with a different owner. [#634](https://github.com/greenbone/openvas/pull/634)
- Add debug logs for allow_simultaneous_ips=no. [#685](https://github.com/greenbone/openvas/pull/685)
- Add min_free_mem and max_sysload scanner only options. [#690](https://github.com/greenbone/openvas/pull/690)

### Changed
- Store results in main_kb instead of host_kb. [#550](https://github.com/greenbone/openvas/pull/550)
- Also use internal function name in some nasl log messages. [#611](https://github.com/greenbone/openvas/pull/611)
- Move more scanner preferences to gvm-libs to make them available for openvas-nasl. [#614](https://github.com/greenbone/openvas/pull/614)

### Removed
- Use the nvticache name from gvm-libs, defined in nvticache.h. [#578](https://github.com/greenbone/openvas/pull/578)

[21.4.0]: https://github.com/greenbone/openvas/compare/oldstable...v21.4.0

## [20.8.4] (unreleased)
### Added
### Changed
- Changed defaults for installation locations [#826](https://github.com/greenbone/openvas-scanner/pull/826)
  - SYSCONFDIR is /etc by default now
  - LOCALSTATEDIR is /var by default now
  - OPENVAS_RUN_DIR is /run/ospd by default now
  - OPENVAS_FEED_LOCK_PATH is /var/lib/openvas/feed-update.lock by default now

### Deprecated
### Removed
### Fixed

[20.8.4]: https://github.com/greenbone/openvas-scanner/compare/v20.8.3...oldstable

## [20.8.3] - 2021-08-03
### Fixed

- Fix clang-analyzer warnings.
  [#791](https://github.com/greenbone/openvas/pull/791)
  [#795](https://github.com/greenbone/openvas/pull/795)

[20.8.3]: https://github.com/greenbone/openvas/compare/v20.8.2...v20.8.3

## [20.8.2] - 2021-06-23

### Added
- Check for wrong names or values in the script_xrefs params.
  [#650](https://github.com/greenbone/openvas/pull/650)
  [#653](https://github.com/greenbone/openvas/pull/653)
- Log a message if the scanner did not launch all plugins against a host.
  [#700](https://github.com/greenbone/openvas/pull/700)
  [#734](https://github.com/greenbone/openvas/pull/734)

### Changed
- Replace bogus data with a better message and the vendor. [#665](https://github.com/greenbone/openvas/pull/665)
- Improve log message for WMI connect failed or missing WMI support. [#670](https://github.com/greenbone/openvas/pull/670)
- Don't use g_error. Use g_warning instead and let the scanner to continue. [#710](https://github.com/greenbone/openvas/pull/710)
- Update COPYING file. [#750](https://github.com/greenbone/openvas/pull/750)
- Set file permissions when syncing community feed [#769](https://github.com/greenbone/openvas-scanner/pull/769)

### Fixed
- Fix issues discovered with clang compiler. [#654](https://github.com/greenbone/openvas/pull/654)
- Fix gcc-9 and gcc-10 warnings. [#655](https://github.com/greenbone/openvas/pull/655)
- Fix double free in nasl_cert_query. [#658](https://github.com/greenbone/openvas/pull/658)
- Fix message to the client if there is a iface problem. [#695](https://github.com/greenbone/openvas/pull/695)
- Fix SIGSEGV when no best route is found. [#702](https://github.com/greenbone/openvas/pull/702)
- Fix host count when reverse_lookup_only is enabled. [#715](https://github.com/greenbone/openvas/pull/715)
- Use host from the original hosts list when boreas is enabled. Backport of [PR #727](https://github.com/greenbone/openvas/pull/727). [#725](https://github.com/greenbone/openvas/pull/725)
- The function description of nasl_ssh_shell_read() has been fixed. [#755](https://github.com/greenbone/openvas/pull/755)

### Removed
- Remove code from the openvas daemon era. Do not flushall redis. [#689](https://github.com/greenbone/openvas/pull/689)
- Remove deprecated option logfile. [#713](https://github.com/greenbone/openvas/pull/713)

[20.8.2]: https://github.com/greenbone/openvas/compare/v20.8.1...v20.8.2

## [20.8.1] - 2021-02-01

### Added
- Extend nasl lint to detect if function parameter is used twice. [#590](https://github.com/greenbone/openvas/pull/590)
- Add support for TLSv1.3. [#588](https://github.com/greenbone/openvas/pull/588)[#598](https://github.com/greenbone/openvas/pull/598)
- Add alternative for supporting snmp during scans. [#594](https://github.com/greenbone/openvas/pull/594)
- Add resolve_hostname_to_multiple_ips() NASL function. [#596](https://github.com/greenbone/openvas/pull/596)
- Add dump_icmp_packet() and dump_icmp_v6_packet() nasl functions. [#609](https://github.com/greenbone/openvas/pull/609)
- Send message to the client with hosts count. [#606](https://github.com/greenbone/openvas/pull/606)
- Use nasl_perror on invalid input and add more documentation. [#608](https://github.com/greenbone/openvas/pull/608)
- Add timeout argument to ssh_connect() nasl function to set the connection timeout. [631](https://github.com/greenbone/openvas/pull/631)

### Changed
- Downgrade wmi queries log level for common errors.
  [#602](https://github.com/greenbone/openvas/pull/602)
  [#607](https://github.com/greenbone/openvas/pull/607)
- Rename some nasl functions and func parameters for consistency and fix byte order issue in get_ipv6_element. [#613](https://github.com/greenbone/openvas/pull/613)
- Change log level from debug to message to show max_host and max_scan during scan start. [#626](https://github.com/greenbone/openvas/pull/626)
- Changed the redis-openvas.conf, so that it is compliant with the 5.0+ version(s) of redis. [#668](https://github.com/greenbone/openvas/pull/668)

### Fixed
- Fork vhosts before creating the socket.[#576](https://github.com/greenbone/openvas/pull/576)
- Check if another forked child has already added the same vhost. [#581](https://github.com/greenbone/openvas/pull/581)
- Send duplicated hosts as dead hosts to ospd, to adjust scan progress calculation. [#586](https://github.com/greenbone/openvas/pull/586)
- Only send the signal if the pid is a positive value. [#593](https://github.com/greenbone/openvas/pull/593)
- When routes with same mask are found the route with the better metric is chosen.
  [#593](https://github.com/greenbone/openvas/pull/593)
  [#639](https://github.com/greenbone/openvas/pull/639)
- Fix malformed target. [#625](https://github.com/greenbone/openvas/pull/625)
- Fix snmp result. Only return the value and do not stop at the first \n. [#627](https://github.com/greenbone/openvas/pull/627)
- Fix masking of IPv6 addresses. [#635](https://github.com/greenbone/openvas/pull/635)
- Fix technique switch for getting the appropriate interface to use for IPv6 dst addr. [#636](https://github.com/greenbone/openvas/pull/636)
- Fix host count. Set to -1 when the target string is invalid. [#646](https://github.com/greenbone/openvas/pull/646)

[20.08.1]: https://github.com/greenbone/openvas/compare/v20.8.0...v20.8.1

## [20.8.0] - 2020-08-11

### Added
- Create greenbone-nvt-sync create lock file during feed sync.
  [#458](https://github.com/greenbone/openvas/pull/458)
  [#459](https://github.com/greenbone/openvas/pull/459)
- Extend script_get_preference() to get the value by id. [#470](https://github.com/greenbone/openvas/pull/470)
- Add extended environmental variables info to greenbone-nvt-sync help text. [#488](https://github.com/greenbone/openvas/pull/488)
- Extend nasl functions which generate results with optional "uri" parameter [#526](https://github.com/greenbone/openvas/pull/526)
- Add nasl function to get the host kb index. [#530](https://github.com/greenbone/openvas/pull/530)
- Print the filter used by pcap in the error message.
  [#537](https://github.com/greenbone/openvas/pull/537)
  [#540](https://github.com/greenbone/openvas/pull/540)

### Changed
- The logging of the NASL internal regexp functions was extended to include the pattern in case of a failed regcomp(). [#397](https://github.com/greenbone/openvas/pull/397)
- Add config for gpg keyring path (OPENVAS_GPG_BASE_DIR) [#407](https://github.com/greenbone/openvas/pull/407)
- Use __func__ instead of __FUNCTION__ [#419](https://github.com/greenbone/openvas/pull/419)
- Use pcap_findalldevs() instead of deprecated function pcap_lookupdev() [#422](https://github.com/greenbone/openvas/pull/422) [#430](https://github.com/greenbone/openvas/pull/430)
- Add port-range option for openvas-nasl [#431](https://github.com/greenbone/openvas/pull/431)
- Add test_alive_hosts_only feature. [#456](https://github.com/greenbone/openvas/pull/456)
- Don't reload the plugins when start a new scan. [#458](https://github.com/greenbone/openvas/pull/458)
- Drop http feed sync. [#478](https://github.com/greenbone/openvas/pull/478)
- Add aligned summary to log at scan end. [#496](https://github.com/greenbone/openvas/pull/496)
- Unify log messages about start/end of scan and of hosts. [#500](https://github.com/greenbone/openvas/pull/500)
- Use flock to lock the feed lock file. [#507](https://github.com/greenbone/openvas/pull/507)
- Move alive detection module (Boreas) into gvm-libs [#519](https://github.com/greenbone/openvas/pull/519)
- Allow to set all legal types of icmp v6 in icmp header in openvas-nasl. [#542](https://github.com/greenbone/openvas/pull/542)
- The output of the NASL dump_* packet forgery functions was made consistent. [#555](https://github.com/greenbone/openvas/pull/555)
- Make drop_privileges setting a scanner-only preference. [#557](https://github.com/greenbone/openvas/pull/557)
- Feed lock path is now configurable. [#574](https://github.com/greenbone/openvas/pull/574)

### Fixed
- Improve signal handling when update vhosts list. [#425](https://github.com/greenbone/openvas/pull/425)
- Wait for all children instead of waiting just for one a time. [#428](https://github.com/greenbone/openvas/pull/428)
- Don't detect MongoDB as a HTTP service. [#447](https://github.com/greenbone/openvas/pull/447)
- Set status finished and send a message if the port list is invalid. [#453](https://github.com/greenbone/openvas/pull/453)
- Fix format-truncation warning in GCC 8.2 and later. [#461](https://github.com/greenbone/openvas/pull/461)
- Clean the new kb when the scan was stopped and the host has not been started. [#494](https://github.com/greenbone/openvas/pull/494)
- Prevent child deadlock. [#491](https://github.com/greenbone/openvas/pull/491)
- Memleak fixes for kb_item_get_str(). [#502](https://github.com/greenbone/openvas/pull/502)
- Fix denied hosts.  [#510](https://github.com/greenbone/openvas/pull/510)
- Fix openvas-nasl. Add kb key/value for all vhosts. [#533](https://github.com/greenbone/openvas/pull/533)
- Wait for last plugin to finish before change to other category. [#534](https://github.com/greenbone/openvas/pull/534)
- Corrected function parameter names in nasl_perror calls. [#539](https://github.com/greenbone/openvas/pull/539)
- Various updates to the nasl_perror() error texts. [#539](https://github.com/greenbone/openvas/pull/542)
- Fix icmp checksum calculation in openvas-nasl. [#543](https://github.com/greenbone/openvas/pull/543)
- Fix ipv6 flow label in nasl_packet_forgery_v6() for openvas-nasl. [#545](https://github.com/greenbone/openvas/pull/545)
- Fix name of NASL internal IPPROTO_IP variable. [#552](https://github.com/greenbone/openvas/pull/552)
- Fix byte ordering and wrong PROTO identifier in dump_ipv6_packet() for openvas-nasl. [#549](https://github.com/greenbone/openvas/pull/549)
- Fix size calculation which lead to alloc error in get_tcp_element() of openvas-nasl. [#546](https://github.com/greenbone/openvas/pull/546)
- Fix filter out of default 'radio' type preferences [#560](https://github.com/greenbone/openvas/pull/560)
- Allow group access to lockfile and fix empty timestamp [#562](https://github.com/greenbone/openvas/pull/562)
- Do not simply abort when log file is not writable but print err msg and shutdown gracefully instead. [#661](https://github.com/greenbone/openvas/pull/661)

### Removed
- Removed "network scan" mode. This includes removal of NASL API methods "scan_phase()" and "network_targets()". Sending a "network_mode=yes" in a scanner configuration will have no effect anymore. [#493](https://github.com/greenbone/openvas/pull/493)

[20.8.1]: https://github.com/greenbone/openvas/compare/openvas-7.0...v20.8.1

## [7.0.1]

### Added
- Display gvm-libs version in `openvas --version` output [#436](https://github.com/greenbone/openvas/pull/436)

### Changed
- Improve handling of invalid or existent ids of nvt's preference id. [#416](https://github.com/greenbone/openvas/pull/416)
- Perform a scan even if there are missing plugins. [#439](https://github.com/greenbone/openvas/pull/439)

### Fixed
- Do not store in memory an empty file received as nvt preference. [#409](https://github.com/greenbone/openvas/pull/409)
- Fix stop scan. [#414](https://github.com/greenbone/openvas/pull/414)
- Fix hanging scans. [#423](https://github.com/greenbone/openvas/pull/423)
- Improve signal handling when update vhosts list. [#426](https://github.com/greenbone/openvas/pull/426)
- Wait for all children instead of waiting just for one a time. [#429](https://github.com/greenbone/openvas/pull/429)
- Release redis connection. [[#452](https://github.com/greenbone/openvas/pull/452)

[7.0.1]: https://github.com/greenbone/openvas/compare/v7.0.0...openvas-7.0

## [7.0.0] (2019-10-11)

### Added
- An ID has been added to NVT preferences. [#282](https://github.com/greenbone/openvas/pull/282)
- A new NVT cross references data handling has been added. [#317](https://github.com/greenbone/openvas/pull/317)
- Add option --scan-stop. [#352](https://github.com/greenbone/openvas/pull/352)
- Add support to open an rc4 stream cipher, the function to encrypt stream data using the cipher handle,
  and the function to close a handler. [#354](https://github.com/greenbone/openvas/pull/354)
- Add one single config for redis to config/redis-openvas.conf. [#370](https://github.com/greenbone/openvas/pull/370)

### Changed
- Vendor version is now an option in the config file. [#363](https://github.com/greenbone/openvas/pull/363)
- The NVT preference format has been changed. [#275](https://github.com/greenbone/openvas/pull/275)
- Redis supported versions must be 3.2 or higher. [#287](https://github.com/greenbone/openvas/pull/287)
- Log directory is now configurable. [#316](https://github.com/greenbone/openvas/pull/316)
- The greenbone-nvt-sync script is not allowed to run as root. [#323](https://github.com/greenbone/openvas/pull/323)
- OpenVAS Scanner has been renamed to OpenVAS (Open Vulnerability Assessment Scanner). [#337](https://github.com/greenbone/openvas/pull/337) [#343](https://github.com/greenbone/openvas/pull/343)
- Retry until a host finishes and frees a db before running a new host scan, in case there is no free redis db. Therefore a infinite loop has been added when it call kb_new(). [#340](https://github.com/greenbone/openvas/pull/340)
- Use new nvti_add_tag() instead of plug_set_tag() and remove plug_set_tag(). [#385](https://github.com/greenbone/openvas/pull/385)
- Remove dead code about tags regarding former openvas settings "result_prepend_tags" and "result_append_tags". [#386](https://github.com/greenbone/openvas/pull/386)
- Check cache/feed errors during plugin scheduling. [#358](https://github.com/greenbone/openvas/pull/358)
- Vendor version is now an option in the config file. [#363](https://github.com/greenbone/openvas/pull/363)
- Use API for accessing NVTI elements. [#365](https://github.com/greenbone/openvas/pull/365)
- Allow send_packet() and send_v6packet() to send packets to broadcast/multicast.[#388](https://github.com/greenbone/openvas/pull/388)


### Fixed
- An issue with stuck scans where only a single plugin is running and is beyond its timeout has been addressed. [#289](https://github.com/greenbone/openvas/pull/289)
- Fix a type mismatch. Use correct format specifier for size_t. [#299](https://github.com/greenbone/openvas/pull/299)
- An issue which caused falling back into a default port in get_ssh_port() has been fixed. [#342](https://github.com/greenbone/openvas/pull/342)
- An issue which could have caused a truncated string in register_service() has been fixed. [#373](https://github.com/greenbone/openvas/pull/373)
- Reset redis connection after the host scan finished. This avoids to leave open fd, which cause ulimit problems. [#384](https://github.com/greenbone/openvas/pull/384)
- Fix mis-identification of Sphinx Search service. [#387](https://github.com/greenbone/openvas/pull/387)
- Set a key in redis when the scan finishes and fix stop scan using the right pid. [#390](https://github.com/greenbone/openvas/pull/390)
- Fix detection of finger service. [#391](https://github.com/greenbone/openvas/pull/391)
- Wait for zombie process in case of timed out nvts. [#379](https://github.com/greenbone/openvas/pull/379)
- Fix handling of file type nvt preferences. [#399](https://github.com/greenbone/openvas/pull/399)

### Removed
- Unused be_nice scan preferences has been removed. [#313](https://github.com/greenbone/openvas/pull/313)
- OTP has been entirely removed in favor of using the ospd-openvas interface. [#333](https://github.com/greenbone/openvas/pull/333) [#351](https://github.com/greenbone/openvas/pull/351)
  [#337](https://github.com/greenbone/openvas/pull/337) [#389](https://github.com/greenbone/openvas/pull/389)
- Daemon mode has been entirely removed. [#337](https://github.com/greenbone/openvas/pull/337) [#341](https://github.com/greenbone/openvas/pull/341)

[7.0.0]: https://github.com/greenbone/openvas/compare/v6.0.1...v7.0.0

## [6.0.2] (unreleased)

### Changed
- The call to wmiexec.py has been replaced with impacket-wmiexec, because the symlink has been added in Debian Stretch with python-impacket 0.9.15-1.

[6.0.2]: https://github.com/greenbone/openvas/compare/v6.0.1...openvas-scanner-6.0

## [6.0.1] (2019-07-17)

### Added

### Changed
- Use lowercase for values added from add_host_name(). [#306](https://github.com/greenbone/openvas/pull/306)
- Do not launch the scan if the nvticache is corrupted. [#309](https://github.com/greenbone/openvas/pull/310)
- Separate each scan plugin process into its own process group. [#325](https://github.com/greenbone/openvas/pull/325)

### Fixed
- An issue which caused the scanner to crash when a plugin is missing during a scan has been addressed. [#296](https://github.com/greenbone/openvas/pull/296)
- An issue which causes a scan to hang has been addressed. [#301](https://github.com/greenbone/openvas/pull/301)
- Issues in building process have been addressed. [#308](https://github.com/greenbone/openvas/pull/308)
- An issue which caused resuming task not to work was addressed. [#312](https://github.com/greenbone/openvas/pull/312)
- An issue which caused a possible null IP values in OTP results / HOST_END has been addressed. [#321](https://github.com/greenbone/openvas/pull/321)
- An issue which caused the scanner to finish instantly without any result has been addressed. [#330](https://github.com/greenbone/openvas/pull/330)

### Removed
- Currently unused advanced_log related code has been removed. [#327](https://github.com/greenbone/openvas/pull/327)

[6.0.1]: https://github.com/greenbone/openvas/compare/v6.0.0...openvas-scanner-6.0

## [6.0.0] (2019-04-05)

### Added
- Function to get the currently running script filename has been added.

### Changed
- Debugging nasl mechanism has been improved, replacing preprocessor directives
  with g_debug facility.
- Code related to redis queries was improved.
- OpenVAS reload has been improved.
- Documentation has been improved.

### Fixed
- An issue related to the log facility and greenbone-nvt-sync has been fixed.
- An issue which caused nasl-lint to fail in case of unneeded nested functions has been addressed.
- An issue which caused returning erroneous values by get_plugin_preference() has been addressed.
- An issue which cause stuck scans where only a single plugin is running and is beyond its timeout has been addressed.
- Issues reported by static code analysis have been addressed.
- Issues in building process have been addressed.
- Several code improvements and clean-ups have been done.

### Removed
- Unused internal_send/recv() functions have been removed.

[6.0.0]: https://github.com/greenbone/openvas/compare/v6.0+beta2...v6.0.0
