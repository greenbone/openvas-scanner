# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- An ID has been added to NVT preferences. [#282](https://github.com/greenbone/openvas/pull/282)
- A new NVT cross references data handling has been added.[#317](https://github.com/greenbone/openvas/pull/317)

### Changes
- Vendor version is now an option in the config file. [#363](https://github.com/greenbone/openvas/pull/363)
- The NVT preference format has been changed. [#275](https://github.com/greenbone/openvas/pull/275)
- Redis supported versions must be 3.2 or higher. [#287](https://github.com/greenbone/openvas/pull/287)
- Log directory is now configurable. [#316](https://github.com/greenbone/openvas/pull/316)
- The greenbone-nvt-sync script is not allowed to run as root. [#323](https://github.com/greenbone/openvas/pull/323)
- OpenVAS Scanner has been renamed to OpenVAS (Open Vulnerability Assessment Scanner). [#337](https://github.com/greenbone/openvas/pull/337) [#343](https://github.com/greenbone/openvas/pull/343)
- Retry until a host finishes and frees a db before running a new host scan, in case there is no free redis db. Therefore a infinite loop has been added when it call kb_new(). [#340](https://github.com/greenbone/openvas/pull/340)

### Fixed
- An issue with stuck scans where only a single plugin is running and is beyond its timeout has been addressed. [#289](https://github.com/greenbone/openvas/pull/289)
- Fix a type mismatch. Use correct format specifier for size_t. [#299](https://github.com/greenbone/openvas/pull/299)
- An issue which caused falling back into a default port in get_ssh_port() has been fixed. [#342](https://github.com/greenbone/openvas/pull/342)

### Removed
- Unused be_nice scan preferences has been removed. [#313](https://github.com/greenbone/openvas/pull/313)
- OTP has been entirely removed in favor of using the ospd-openvas interface. [#337](https://github.com/greenbone/openvas/pull/337)
- Daemon mode has been entirely removed. [#337](https://github.com/greenbone/openvas/pull/337)  [#341](https://github.com/greenbone/openvas/pull/341)

[Unreleased]: https://github.com/greenbone/openvas/compare/openvas-scanner-6.0...master

## [6.0.2] (unreleased)

### Changes
- The call to wmiexec.py has been replaced with impacket-wmiexec, because the symlink has been added in Debian Stretch with python-impacket 0.9.15-1.

[6.0.2]: https://github.com/greenbone/openvas/compare/v6.0.1...openvas-scanner-6.0

## [6.0.1] (2019-07-17)

### Added

### Changes
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
