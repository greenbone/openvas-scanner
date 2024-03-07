# Full Openvas Installation Guide

This guide covers the complete installation in order to be able to start a scan with the API provided by openvasd

Everything is available as regularly updated source code snapshots/release archives confirmed to work and as source code checkouts directly from the git source code repositories at GitHub.

# Building from Source

Building the Greenbone Community Edition from source requires knowledge about:

- Using a terminal
- Shell programming basics
- Installing software via apt
- Using a C compiler
- Using CMake and make
- The [Linux File System Hierarchy](https://en.wikipedia.org/wiki/Filesystem_Hierarchy_Standard)
- Running services via systemd

Additionally, a basic knowledge about the [architecture](https://greenbone.github.io/docs/latest/architecture.html) of the Greenbone Community Edition is required to follow this guide.



<i>Note

This guide is intended for developers who want to try out the newest features and/or want to get familiar with the source code. It is not intended for production setups.

Currently the docs support the following distributions:

- Debian stable [bookworm](https://www.debian.org/releases/stable)
  
Most likely, other Debian derivatives like Mint and Kali will also work with only minor adjustments required.</i>

## Hardware Requirements

Minimal:

- CPU Cores: 2

- Random-Access Memory: 4GB

- Hard Disk: 20GB free

Recommended:

- CPU Cores: 4

- Random-Access Memory: 8GB

- Hard Disk: 60GB free

## Prerequisites

<i>Note

Please follow the guide step by step. Later steps might require settings or output of a previous command.</i>


The command `sudo` is used for executing commands that require privileged access on the system.

### Creating a User and a Group

The services provided by necessary for a scan should run as a dedicated user and group. Therefore a `gvm` user and a group with the same name will be created.

```shell
sudo useradd -r -M -U -G sudo -s /usr/sbin/nologin gvm
```

### Adjusting the Current User

To allow the current user to run openvasd he must be added to the gvm group. To make the group change effective either logout and login again or use *su*.

```shell
sudo usermod -aG gvm $USER

su $USER
```

### Choosing an Install Prefix

Before building the software stack, a (root) directory must be chosen where the built software will finally be installed. For example, when building packages, the distribution developers set this path to `/usr`.

By default, it is `/usr/local` which is also used in this guide. This directory will be stored in an environment variable `INSTALL_PREFIX` to be able to reference it later.

```shell
export INSTALL_PREFIX=/usr/local
```

### Setting the PATH

On Debian systems the locations `/sbin`, `/usr/sbin` and `/usr/local/sbin` are not in the `PATH` of normal users. To run *openvasd* which is located in `/usr/local/sbin` the `PATH` environment variable should be adjusted.

```shell
export PATH=$PATH:$INSTALL_PREFIX/sbin
```

### Creating a Source, Build and Install Directory

To separate the sources and the build artifacts, a source and a build directory must be created.

This source directory will be used later in this guide via an environment variable `SOURCE_DIR`. Accordingly, a variable `BUILD_DIR` will be set for the build directory. Both can be set to any directory to which the current user has write permissions. Therefore directories in the current user’s home directory are chosen in this guide.

```shell
export SOURCE_DIR=$HOME/source
mkdir -p $SOURCE_DIR
```

```shell
export BUILD_DIR=$HOME/build
mkdir -p $BUILD_DIR
```

Additionally, an install directory will be set as an environment variable `INSTALL_DIR`. It is used as a temporary installation directory before moving all built artifacts to the final destination.

```shell
export INSTALL_DIR=$HOME/install
mkdir -p $INSTALL_DIR
```

### Choosing the Installation Source

For building the GVM software stack, three different sources can be chosen depending on the desired stability:

- Building from release [tarballs](https://en.wikipedia.org/wiki/Tar_(computing))
- Building from git tags
- Building from release branches
- Building any branch from git

Linux distributions use the release [tarballs](https://en.wikipedia.org/wiki/Tar_(computing)) because it is the most common and well known method to share source code.

Newer build systems may stick with the git tags.

If you are a developer and very familiar with building from source already, you may also try out using the git release branches. These have the advantage that they contain the newest fixes which may not yet be included in the release tarballs or git tags. As a downside, the release branches may contain only partially fixed issues and need to be updated more often.

This guide will explain the installation from any git branch.

### Installing Common Build Dependencies

For downloading, configuring, building and installing the Greenbone Community Edition components, several tools and applications are required. To install this requirements the following commands can be used:

```shell
sudo apt update
sudo apt install --no-install-recommends --assume-yes \
  build-essential \
  curl \
  cmake \
  pkg-config \
  python3 \
  python3-pip \
  gnupg
```

### Importing the Greenbone Signing Key

To validate the integrity of the downloaded source files, [GnuPG](https://www.gnu.org/) is used. It requires downloading the Greenbone Community Signing public key and importing it into the current user’s keychain.

```shell
curl -f -L https://www.greenbone.net/GBCommunitySigningKey.asc -o /tmp/GBCommunitySigningKey.asc
gpg --import /tmp/GBCommunitySigningKey.asc
```

For understanding the validation output of the gpg tool, it is best to mark the Greenbone Community Signing key as fully trusted.

```shell
echo "8AE4BE429B60A59B311C2E739823FAA60ED1E580:6:" | gpg --import-ownertrust
```

## Building and Installing the Components

<i>Note

The components should be build and installed in the listed order.</i>

### gvm-libs

*gvm-libs* is a C library providing basic functionality like XML parsing and network communication. It is a dependency of *openvas-scanner*.

Install dependencies for gmv-libs:

```shell
sudo apt install -y \
  libglib2.0-dev \
  libgpgme-dev \
  libgnutls28-dev \
  uuid-dev \
  libssh-gcrypt-dev \
  libhiredis-dev \
  libxml2-dev \
  libpcap-dev \
  libnet1-dev \
  libpaho-mqtt-dev
```

Optional dependencies:

```shell
sudo apt install -y \
  libldap2-dev \
  libradcli-dev
```

Download gvm-libs sources from git:

```shell
cd $SOURCE_DIR
git clone git@github.com:greenbone/gvm-libs.git
```

Afterwards, gvm-libs can be build and installed:

```shell
mkdir -p $BUILD_DIR/gvm-libs && cd $BUILD_DIR/gvm-libs

cmake $SOURCE_DIR/gvm-libs \
  -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX \
  -DCMAKE_BUILD_TYPE=Release \
  -DSYSCONFDIR=/etc \
  -DLOCALSTATEDIR=/var

make -j$(nproc)
```
```shell
mkdir -p $INSTALL_DIR/gvm-libs

make DESTDIR=$INSTALL_DIR/gvm-libs install

sudo cp -rv $INSTALL_DIR/gvm-libs/* /
```

If you want to debug, change `DCMAKE_BUILD_TYPE=Debug`.

### openvas-smb

openvas-smb is a helper module for *openvas-scanner*. It includes libraries (openvas-wmiclient/openvas-wincmd) to interface with Microsoft Windows Systems through the Windows Management Instrumentation API and a winexe binary to execute processes remotely on that system.

It is an optional dependency of *openvas-scanner* but is required for scanning Windows-based systems.


Install dependencies for openvas-smb:

```shell
sudo apt install -y \
  gcc-mingw-w64 \
  libgnutls28-dev \
  libglib2.0-dev \
  libpopt-dev \
  libunistring-dev \
  heimdal-dev \
  perl-base
```

Download openvas-smb sources from git:

```shell
cd $SOURCE_DIR
git clone git@github.com:greenbone/openvas-smb.git
```

Building openvas-smb:

```shell
mkdir -p $BUILD_DIR/openvas-smb && cd $BUILD_DIR/openvas-smb

cmake $SOURCE_DIR/openvas-smb \
  -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX \
  -DCMAKE_BUILD_TYPE=Release

make -j$(nproc)
```

Installing openvas-smb:

```shell
mkdir -p $INSTALL_DIR/openvas-smb

make DESTDIR=$INSTALL_DIR/openvas-smb install

sudo cp -rv $INSTALL_DIR/openvas-smb/* /
```

### openvas-scanner

openvas-scanner is a full-featured scan engine that executes a continuously updated and extended feed of [Vulnerability Tests (VTs)](https://greenbone.github.io/docs/latest/glossary.html#term-VT). The feed consist of thousands of NASL (Network Attack Scripting Language) scripts which implement all kind of vulnerability checks.

Install dependencies for openvas-scanner:

```shell
sudo apt install -y \
  bison \
  libglib2.0-dev \
  libgnutls28-dev \
  libgcrypt20-dev \
  libpcap-dev \
  libgpgme-dev \
  libksba-dev \
  rsync \
  nmap \
  libjson-glib-dev \
  libcurl4-gnutls-dev \
  libbsd-dev
```

Optional dependencies:

```shell
sudo apt install -y \
  python3-impacket \
  libsnmp-dev
```

Download openvas-scanner sources from git:

```shell
cd $SOURCE_DIR
git clone git@github.com:greenbone/openvas-scanner.git
```

Building openvas-scanner:

```shell
mkdir -p $BUILD_DIR/openvas-scanner && cd $BUILD_DIR/openvas-scanner

cmake $SOURCE_DIR/openvas-scanner \
  -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX \
  -DCMAKE_BUILD_TYPE=Release \
  -DINSTALL_OLD_SYNC_SCRIPT=OFF \
  -DSYSCONFDIR=/etc \
  -DLOCALSTATEDIR=/var \
  -DOPENVAS_FEED_LOCK_PATH=/var/lib/openvas/feed-update.lock \
  -DOPENVAS_RUN_DIR=/run/ospd

make -j$(nproc)
```

Installing openvas-scanner:

```shell
mkdir -p $INSTALL_DIR/openvas-scanner

make DESTDIR=$INSTALL_DIR/openvas-scanner install

sudo cp -rv $INSTALL_DIR/openvas-scanner/* /
```

### openvasd

openvasd is the [HTTP based API](https://greenbone.github.io/scanner-api/) for the scanner. It replaces ospd-openvas with the Open Scanner Protocol (OSP) and is providing the same functionality.

<i><b>WARNING</b>

Currently openvasd still depends on ospd-openvas</i>

Before proceeding, please be sure you have already downloaded [openvas-scanner](#openvas-scanner)

As openvasd is written in rust, we need the rust toolchain for installation:

```shell
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

From here on it is easy, as all dependencies are handled by cargo, the rust package manager automatically. So we can directly proceed to the installation.

Building openvasd:

```shell
mkdir -p $BUILD_DIR/openvasd
cd $SOURCE_DIR/openvas-scanner/rust
cargo build -r --target-dir $BUILD_DIR/openvasd
```

Install openvasd:

```shell
sudo cp -rv $BUILD_DIR/openvasd/release/openvasd $INSTALL_PREFIX/bin/
sudo cp -rv $BUILD_DIR/openvasd/release/scannerctl $INSTALL_PREFIX/bin/
```

### ospd-openvas

*ospd-openvas* is an [OSP server](https://greenbone.github.io/docs/latest/glossary.html#term-OSP) implementation.

Install dependencies for ospd-openvas:

```shell
sudo apt install -y \
  python3 \
  python3-pip \
  python3-setuptools \
  python3-packaging \
  python3-wrapt \
  python3-cffi \
  python3-psutil \
  python3-lxml \
  python3-defusedxml \
  python3-paramiko \
  python3-redis \
  python3-gnupg \
  python3-paho-mqtt \
  python3-poetry
```

Download ospd-openvas sources from git:

```shell
cd $SOURCE_DIR
git clone git@github.com:greenbone/ospd-openvas.git
```

Install ospd-openvas:

```shell
cd $SOURCE_DIR/ospd-openvas

mkdir -p $INSTALL_DIR/ospd-openvas

python3 -m pip install --root=$INSTALL_DIR/ospd-openvas --no-warn-script-location .

sudo cp -rv $INSTALL_DIR/ospd-openvas/* /
```

### notus-scanner

*notus-scanner* is used for detecting vulnerable products by evaluating internal system information gathered by openvas-scanner. It communicates with openvas-scanner and ospd-openvas via MQTT. It is running as a daemon.

Install dependencies for notus-scanner

```shell
sudo apt install -y \
  python3 \
  python3-pip \
  python3-setuptools \
  python3-paho-mqtt \
  python3-psutil \
  python3-gnupg
```

Download notus-scanner sources from git:

```shell
cd $SOURCE_DIR
git clone git@github.com:greenbone/notus-scanner.git
```

Install notus-scanner:

```shell
cd $SOURCE_DIR/notus-scanner

mkdir -p $INSTALL_DIR/notus-scanner

python3 -m pip install --root=$INSTALL_DIR/notus-scanner --no-warn-script-location .

sudo cp -rv $INSTALL_DIR/notus-scanner/* /
```


### greenbone-feed-sync

The `greenbone-feed-sync` tool is a Python based script to download all [feed data](https://greenbone.github.io/docs/latest/glossary.html#term-Feed) from the [Greenbone Community Feed](https://greenbone.github.io/docs/latest/glossary.html#term-Greenbone-Community-Feed) to your local machine. It is an improved version of two former shell scripts.

Install dependencies:

```shell
sudo apt install -y \
  python3 \
  python3-pip
```

The latest version of greeenbone-feed-sync can be installed by using standard Python installation tool pip.

To install it system-wide for all users without running pip as root user, the following commands can be used:

```shell
mkdir -p $INSTALL_DIR/greenbone-feed-sync

python3 -m pip install --root=$INSTALL_DIR/greenbone-feed-sync --no-warn-script-location greenbone-feed-sync

sudo cp -rv $INSTALL_DIR/greenbone-feed-sync/* /
```

## Performing a Feed Synchronization

For the actual vulnerability scanning, [Vulnerability Test scripts](https://greenbone.github.io/docs/latest/glossary.html#term-VT), security information like [CVEs](https://greenbone.github.io/docs/latest/glossary.html#term-CVE), port lists and scan configurations are required. All this data is provided by the [Greenbone Community Feed](https://greenbone.github.io/docs/latest/glossary.html#term-Greenbone-Community-Feed) and should be downloaded initially before starting the services.

A synchronization always consists of two parts:

1. Downloading the changes via [rsync](https://en.wikipedia.org/wiki/Rsync)
2. Loading the changes into memory and a database by a daemon

Both steps may take a while, from several minutes up to hours, especially for the initial synchronization. Only if both steps are finished, the synchronized data is up-to-date and can be used.

The first step is done via the greenbone-feed-sync script. The second step is done automatically when the daemons are started.

### Downloading the Data

Some additional data, which is part of the feed data, is necessary to run scans:
1. We need the nvt-data, which contains VT-scripts. Those are executed by the openvas-scanner.
2. We need the notus-data, which contains lookup tables for the notus-scanner.

Get the data:

```shell
sudo /usr/local/bin/greenbone-feed-sync --type nvt
```

### Feed Validation

For validating the feed content, a GnuPG keychain with the Greenbone Community Feed integrity key needs to be created.

Creating a GPG keyring for feed content validation:

```shell
curl -f -L https://www.greenbone.net/GBCommunitySigningKey.asc -o /tmp/GBCommunitySigningKey.asc

export GNUPGHOME=/tmp/openvas-gnupg
mkdir -p $GNUPGHOME

gpg --import /tmp/GBCommunitySigningKey.asc
echo "8AE4BE429B60A59B311C2E739823FAA60ED1E580:6:" | gpg --import-ownertrust

export OPENVAS_GNUPG_HOME=/etc/openvas/gnupg
sudo mkdir -p $OPENVAS_GNUPG_HOME
sudo cp -r /tmp/openvas-gnupg/* $OPENVAS_GNUPG_HOME/
sudo chown -R gvm:gvm $OPENVAS_GNUPG_HOME
```


## Performing a System Setup

### Setting up the Redis Data Store

Looking at the [Architecture](https://greenbone.github.io/docs/latest/architecture.html), the [Redis](https://redis.io/) key/value storage is used by the scanner (openvas-scanner and ospd-openvas) for handling the [VT](https://greenbone.github.io/docs/latest/glossary.html#term-VT) information and scan results.

Installing the Redis server:

```shell
sudo apt install -y redis-server
```

After installing the Redis server package, a specific configuration for the openvas-scanner must be added.

Adding configuration for running the Redis server for the scanner:

```shell
sudo cp $SOURCE_DIR/openvas-scanner/config/redis-openvas.conf /etc/redis/
sudo chown redis:redis /etc/redis/redis-openvas.conf
echo "db_address = /run/redis-openvas/redis.sock" | sudo tee -a /etc/openvas/openvas.conf
```

Start redis with openvas config:

```shell
sudo systemctl start redis-server@openvas.service
```

Ensure redis with openvas config is started on every system startup:

```shell
sudo systemctl enable redis-server@openvas.service
```

Additionally the gvm user must be able to access the redis unix socket at `/run/redis-openvas/redis.sock`.

Adding the gvm user to the redis group:

```shell
sudo usermod -aG redis gvm
```

### Setting up the Mosquitto MQTT Broker

The Mosquitto MQTT broker is used for communication between ospd-openvas, openvas-scanner and notus-scanner.

Installing the Mosquitto broker:

```shell
sudo apt install -y mosquitto
```

After installing the Mosquitto broker package, the broker must be started and the server uri must be added to the openvas-scanner configuration.

Starting the broker and adding the server uri to the openvas-scanner configuration:

```shell
sudo systemctl start mosquitto.service
sudo systemctl enable mosquitto.service
echo -e "mqtt_server_uri = localhost:1883\ntable_driven_lsc = yes" | sudo tee -a /etc/openvas/openvas.conf
```

### Adjusting Permissions

For a system-wide multi-user installation, it must be ensured that the directory permissions are set correctly and are matching the group setup. All users of the group gvm should be able to read and write logs, lock files and data like VTs.

Adjusting directory permissions:

```shell
sudo mkdir -p /var/lib/notus
sudo mkdir -p /run/gvmd

sudo chown -R gvm:gvm /var/lib/openvas
sudo chown -R gvm:gvm /var/lib/notus
sudo chown -R gvm:gvm /var/log/gvm
sudo chown -R gvm:gvm /run/gvmd

sudo chmod -R g+srw /var/lib/openvas
sudo chmod -R g+srw /var/log/gvm
```

### Setting up sudo for Scanning

For vulnerability scanning, it is required to have several capabilities for which only root users are authorized, e.g., creating raw sockets. Therefore, a configuration will be added to allow the users of the gvm group to run the openvas-scanner application as root user via sudo.

<i><b>Warning</b>

Make sure that only necessary users have access to the gvm group. Each user of the gvm group can manipulate the Vulnerability Test (VT) scripts (.nasl files). These scripts are run with root privileges and therefore can be used for exploits. See https://csal.medium.com/pentesters-tricks-local-privilege-escalation-in-openvas-fe933d7f161f.</i>

```shell
sudo visudo
```

Add the following at the bottom of the file:

```
# allow users of the gvm group run openvas
%gvm ALL = NOPASSWD: /usr/local/sbin/openvas
```

### Setting up Certificates for openvasd



### Setting up Services for Systemd

[Systemd](https://systemd.io/) is used to start the daemons ospd-openvas and notus-scanner. Therefore, service files are required.

Systemd service file for ospd-openvas:

```shell
cat << EOF > $BUILD_DIR/ospd-openvas.service
[Unit]
Description=OSPd Wrapper for the OpenVAS Scanner (ospd-openvas)
Documentation=man:ospd-openvas(8) man:openvas(8)
After=network.target networking.service redis-server@openvas.service mosquitto.service
Wants=redis-server@openvas.service mosquitto.service notus-scanner.service
ConditionKernelCommandLine=!recovery

[Service]
Type=exec
User=gvm
Group=gvm
Environment="PATH=$PATH"
RuntimeDirectory=ospd
RuntimeDirectoryMode=2775
PIDFile=/run/ospd/ospd-openvas.pid
ExecStart=/usr/local/bin/ospd-openvas --foreground --unix-socket /run/ospd/ospd-openvas.sock --pid-file /run/ospd/ospd-openvas.pid --log-file /var/log/gvm/ospd-openvas.log --lock-file-dir /var/lib/openvas --socket-mode 0o770 --mqtt-broker-address localhost --mqtt-broker-port 1883 --notus-feed-dir /var/lib/notus/advisories
SuccessExitStatus=SIGKILL
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF
```

Systemd service file for notus-scanner:

```shell
cat << EOF > $BUILD_DIR/notus-scanner.service
[Unit]
Description=Notus Scanner
Documentation=https://github.com/greenbone/notus-scanner
After=mosquitto.service
Wants=mosquitto.service
ConditionKernelCommandLine=!recovery

[Service]
Type=exec
User=gvm
RuntimeDirectory=notus-scanner
RuntimeDirectoryMode=2775
PIDFile=/run/notus-scanner/notus-scanner.pid
ExecStart=/usr/local/bin/notus-scanner --foreground --products-directory /var/lib/notus/products --log-file /var/log/gvm/notus-scanner.log
SuccessExitStatus=SIGKILL
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF
```

<i>WARNING

The systemd setup only includes the API-key setup. Please follow the instructions at https://github.com/greenbone/openvas-scanner/tree/main/rust/openvasd for more information about authentication methods.
</i>

Systemd service file for openvasd:
```shell
cat << EOF > $BUILD_DIR/openvasd.service
[Unit]
Description=OpenVAS Daemon
Documentation=https://github.com/greenbone/openvas-scanner
After=ospd-openvas.service
Wants=ospd-openvas.service
ConditionKernelCommandLine=!recovery

[Service]
Type=exec
User=gvm
RuntimeDirectory=openvasd
RuntimeDirectoryMode=2775
PIDFile=/run/openvasd/openvasd.pid
ExecStart=/usr/local/bin/openvasd --feed-path /var/lib/openvas/plugins --feed-check-interval 3600 --api-key some_api_key --ospd-socket /run/ospd/ospd-openvas.sock --read-timeout 1 --result-check-interval 1 --listening 127.0.0.1:3000 --storage-type inmemory
SuccessExitStatus=SIGKILL
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF
```

Install systemd service files:

```shell
sudo cp -v $BUILD_DIR/ospd-openvas.service /etc/systemd/system/
sudo cp -v $BUILD_DIR/notus-scanner.service /etc/systemd/system/
sudo cp -v $BUILD_DIR/openvasd.service /etc/systemd/system/
```

Afterwards, the services need to be activated:

```shell
sudo systemctl daemon-reload
```

Start services and enable them on startup:

```shell
sudo systemctl enable ospd-openvas.service
sudo systemctl start ospd-openvas.service
sudo systemctl enable notus-scanner.service
sudo systemctl start notus-scanner.service
sudo systemctl enable openvasd.service
sudo systemctl start openvasd.service
```
