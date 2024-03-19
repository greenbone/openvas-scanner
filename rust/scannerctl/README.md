# scannerctl

Is CLI frontend to use rust scanner utilities.

Usage: `scannerctl [OPTIONS] <COMMAND>`

Options:

- `-v`, `--verbose`: Prints more details while running
- `-h`, `--help`:    Print help
- `-V`, `--version`: Print version

## Commands

### execute

Executes a nasl script using a in memory data base.

It executes either a script via a path or an OID. When an OID is provided it requires the `-p` option to be valid feed to find the script belonging to that OID, otherwise the `-p` is optional and when set does not need to have a sha256sums.

The optional `--target, -t` option allows to set a host target to run the script against to:

When `-v` is set it is printing the statements to be executed as well as the returned NaslValue.

As examples executing: `scannerctl execute examples/hello.nasl` returns:
```text
Hello, world!
```
while executing `scannerctl -v execute examples/hello.nasl` returns:

```text
> if (description == 1) {{ ... }}
=> Null
> display(Hello, world!)
Hello, world!
=> Null
```

Usage: `scannerctl execute [OPTIONS] [-t HOST] <script>`

### feed

Handles feed related tasks.

Usage: `scannerctl feed <COMMAND>`

#### update

Runs nasl scripts in description mode and updates data into redis so that ospd-openvas can read the data.
Also, load the Notus advisories up into the redis cache. The path to the notus advisories must be provided.

When either path or redis is not set it will get the defaults by calling `openvas -s`.

Usage `scannerctl feed update [OPTIONS]`

Usage example, load both:
`GPGHOME=/path/to/.gnupg scannerctl feed update --notus-path <path-to-the-advisories> --signature-check`

Options:
- `-v`, `--vts-only`: Load only nvts into redis cache
- `-n`, `--notus-only`: Load only Notus advisories into redis cache
- `--vts-path <FILE>`: Path to the feed.
- `--notus-path <FILE>`: Path to the notus advisories.
- `-x`, `--signature-check`: Enable NASL signature check.
- `-r`, `--redis <VALUE>`: Redis url. Must either start `unix://` or `redis://`.

On `feed update` it will first read the `sha256sums` file within the feed directory and verify each file with the corresponding sha256sums. When the hash is correct it will execute each mentioned `*.nasl` script within that dir with `description = 1`.
Optionally, it is possible to perform a signature verification of the sha256sums file before uploading. To perform the signature check, also the environment variable `GNUPGHOME` must be set with the gnupg home directory, where the `pubring.kbx` file is stored.

Notus advisories and VTs can be uploaded independtently using the options `--vts-only` and `--notus-only` respectively. They can not be used together. 

#### transform

Runs nasl scripts in description mode and returns it as a json array into stdout.


When path is not set it will get the defaults by calling `openvas -s`.

Usage `scannerctl feed transform [OPTIONS]`

Options:
- `-p`, `--path <FILE>`:   Path to the feed.


On `feed transform` it will first read the `sha256sums` file within the feed directory and verify each file with the corresponding sha256sums. When the hash is correct it will execute each mentioned `*.nasl` script within that dir with `description = 1`.
Optionally, it is possible to perform a signature verification of the sha256sums file before the transformation. To enable the signature check, the environment variable `GNUPGHOME` must be set with the gnupg home directory, where the `pubring.kbx` file is stored.

It will produce a json array in stdout in the format described within [json-storage](../json-storage/README.md).

#### transpile

Tool for feed manipulation. Transforms each nasl script and inc file based on the given rules.
Currently it is able to rename, remove, add, push parameter or functions within a feed.

Usage `scannerctl feed transpile [OPTIONS] --rules <FILE>`

Options:
- `-p`, `--path <FILE>`: Path to the feed.
- `-r`, `--rules <FILE>`: Path to transpiler rules.
- `-h`, `--help`: Print help

An example can be found in [examples](../examples/scannerctl/transpile.toml) folder. This example demonstrates how to
- rename service `www` to `word-wide-web` in register_product
- `register_host_detail` to `add_host_detail`

to execute it call:

`scannerctl -v feed transpile -p /tmp/feed -r examples/scannerctl/transpile.toml`

##### NVT

Describes meta information for a nasl script. Each nasl script must have a description block that may looks something like:

```text
if (description)
{
  script_oid("0.0.0.0.0.0.0.0.0.1");
  script_version("2023-02-23T13:33:44+0000");
  script_tag(name:"last_modification", value:"2020-12-07 13:33:44 +0000 (Mon, 07 Dec 2020)");
  script_tag(name:"creation_date", value:"2009-05-12 22:04:51 +0200 (Tue, 12 May 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Application Server Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 6262);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"summary", value:"HTTP AS detection");
  script_xref(name:"URL", value:"https://greenbone.net");
  exit(0);
}
...
exit(42);
```

Based on the requirement that each description block must have an `exit(0);` call in it the script can be safely run with `description = 1`. to update / create so called meta-data.

###### oid

The script id, following roughly the oid pattern. Each oid must be unique within a feed.

###### name

The name of the script. A freely choosable text.
###### filename

The relative filename of the script. It does not include the feed path and is relative to the feed directory.

###### tag

A struct that contain multiple information set via `script_tag`.

- `solution` - a string.
- `solution_method` - a string,
- `last_modification` - unix timestamp as a number,
- `solution_type` - either: `Mitigation`, `NoneAvailable`, `VendorFix`, `WillNotFix`, `Workaround`
- `creation_date` - unix timestamp as a number,
- `severity_origin` - a string,
- `qod_type` - either: `executable_version`, `executable_version_unreliable`, `exploit`, `general_note`, `package`, `registry`, `remote_active`, `remote_analysis`, `remote_app`, `remote_banner`, `remote_banner_unreliable`, `remote_probe`, `remote_vul`
- `impact` - a string,
- `insight` - a string,
- `qod` - a number,
- `severity_date` - unix timestamp as a number,
- `summary` - a string,
- `vuldetect` - a string,
- `affected` - a string,
- `deprecated` - bool either true or false,
- `severity_vector` - a string,
- `cvss_base_vector` - a string

###### dependencies
A list of dependencies as a string representing a relative path a nasl file.
###### required_keys
A list of keys in the `kb` that a required for that nasl script to run.
###### mandatory_keys
A list of keys in the `kb` that a mandatory for that nasl script to run.
###### excluded_keys
A list of keys in the `kb` that prevent that nasl script to run.
###### required_ports
A list of required ports as string.
###### required_udp_ports
A list of required udp ports as string.
###### references

A list of references:

- `class` - string, the class of a reference
- `id` - the type of reference 

###### preferences

A list of preferences.

- `id` - string, the id of a preference,
- `class` - either: `check_box`, `entry`, `file`, `password`, `radio`, `ssh_login`
- `name` - string, the name of the preference,
- `default` - string, default value of the preference

###### category

The script category; can either be:

- `attack` - will be run within the attack stage
- `denial` - will be run within the denial stage
- `destructive_attack` - will be run within the destructive_attack stage
- `end` - will be run within the end stage
- `flood` - will be run within the flood stage
- `gather_info` - will be run within the gather_info stage
- `init` - will be run within the init stage
- `kill_host` - will be run within the kill_host stage
- `mixed_attack` - will be run within the mixed_attack stage
- `scanner` - will be run within the scanner stage
- `settings` - will be run within the settings stage

###### family

The family a script belongs to. Is a freely choosable string.

### syntax

```text
Verifies syntax of NASL files in given dir or file.

Usage: scannerctl syntax [OPTIONS] <path>

Arguments:
  <path>

Options:
  -q, --quiet  Prints only error output and no progress.
  -h, --help   Print help
```

### scan-config

Transforms a scan-config from gvmds data-objects to scan json of [openvasd](https://greenbone.github.io/scanner-api/#/scan/create_scanl).

To set the target and credentials you can pipe a partial scan json into `scannerctl scan-config` by providing `-i` flag.

As an example we assume that the data-objects feed is in `~/src/greenbone/data-objects/content/22.04` while the vulnerability feed is in `~/src/greenbone/vulnerability-tests/nasl/common` and we want to create a scan to verify localhost with a discovery and full and fast policy on the openvas default portlist.

For that we need to execute:

```text
echo '{ "target": { "hosts": ["localhost"], "ports": [] }, "vts": [] }'| \
scannerctl scan-config -i -p ~/src/greenbone/vulnerability-tests/nasl/common \
  -l ~/src/greenbone/data-objects/content/22.04/port-lists/openvas-default-c7e03b6c-3bbe-11e1-a057-406186ea4fc5.xml \
  ~/src/greenbone/data-objects/content/22.04/scan-configs/discovery-8715c877-47a0-438d-98a3-27c7a6ab2196.xml \
  ~/src/greenbone/data-objects/content/22.04/scan-configs/full-and-fast-daba56c8-73ec-11df-a475-002264764cea.xml
```

Be aware that each call does a description run of the defined feed to gather the meta data, depending on your system and the size of the feed it requires may some time.

#### Usage

```text
Transforms a scan-config xml to a scan json for openvasd.
When piping a scan json it is enriched with the scan-config xml and may the portlist otherwise it will print a scan json without target or credentials.

Usage: scannerctl scan-config [OPTIONS] <scan-config>

Arguments:
  <scan-config>  

Options:
  -p, --path <FILE>      Path to the feed.
  -i, --input            Parses scan json from stdin.
  -l, --portlist <FILE>  Path to the port list xml
  -h, --help             Print help
```

### notus

Does use notus products to compare packages against known vulnerabilities. It can be used to do a single notus scan by providing a list of packages and an operating system. A notus scan will then lookup the provided packages and compares it version to known vulnerabilities. The results will be printed on the command line.

#### Usage

```text
does use notus products to compare packages against known vulnerabilities.

Usage: scannerctl notus [OPTIONS] --path <FILE> <os>...

Arguments:
  <os>...  

Options:
  -p, --path <FILE>   Path to the product feed.
  -i, --input         comma separated pkg list from stdin.
  -l, --pkg <STRING>  Comma separated list of packages.
  -v, --verbose...    Prints more details while running
  -h, --help          Print help
```

## Build

Run `cargo test` to test and `cargo build --release` to build it.

## Install

`cargo install --path .`
