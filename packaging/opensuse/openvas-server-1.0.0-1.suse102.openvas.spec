# OpenVAS
# $Id$
# Description: RPM spec file for openvas-server
#
# Authors:
# Jan-Oliver Wagner <jan-oliver.wagner@intevation.de>
#
# Copyright:
# Copyright (c) 2008 Intevation GmbH, http://www.intevation.de
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

%define PACKAGE_NAME openvas-server
%define PACKAGE_VERSION 1.0.0
%define release 1.suse102.openvas
%define _prefix /usr

Summary: The Open Vulnerability Assessment (OpenVAS) Server
Name:    %PACKAGE_NAME
Version: %PACKAGE_VERSION
Release: %{release}
Source0: %{name}-%{version}.tar.gz
Patch0:  %{name}-%{version}-Makefile.diff
License: GNU GPLv2
Group: Productivity/Networking/Security
Vendor: OpenVAS Development Team, http://www.openvas.org 
Distribution: OpenSUSE 10.2
BuildRoot: %{_builddir}/%{name}-root
Prefix: %{_prefix}
BuildRequires: openvas-libnasl-devel

%package devel
Summary: Development files for openvas-server
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}

%description
openvas-server is the acutal server component
of the Network Vulnerabilty Scanner suite OpenVAS.

%description devel
This package contains the development files (mainly C header files)
for openvas-server.

%prep
%setup -b 0
%patch0

%build
%configure --prefix=%{_prefix}
make

%install
%makeinstall

%post
%{run_ldconfig}

%postun
%{run_ldconfig}

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc CHANGES COPYING
%{_mandir}/man?/*
%{_bindir}/openvas-mkrand
%{_bindir}/openvas-mkcert-client
%{_sbindir}/*
%{_localstatedir}/lib/openvas/*
%{_localstatedir}/log/openvas
%{_sharedstatedir}/openvas/*
%{_sysconfdir}/openvas/gnupg

%files devel
%defattr(-,root,root,-)
%{_includedir}/openvas/*
%{_bindir}/openvasd-config

%changelog
* Wed Apr 16 2008 Jan-Oliver Wagner <jan-oliver.wagner@intevation.de>
  Initial OpenSUSE 10.2 spec file, tested for i586
