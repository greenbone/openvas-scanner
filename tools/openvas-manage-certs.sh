#!/bin/sh
#
# openvas-manage-certs.sh - Manage certificate infrastructure for an OpenVAS installation
# Copyright (C) 2014 Greenbone Networks GmbH
#
# Authors:
# - Michael Wiegand <michael.wiegand@greenbone.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# Set default values for certificate parameters
# Parameters:
# Lifetime
if [ -z "$OPENVAS_CERTIFICATE_LIFETIME" ]
then
  OPENVAS_CERTIFICATE_LIFETIME=730
fi
# Country
if [ -z "$OPENVAS_CERTIFICATE_COUNTRY" ]
then
  OPENVAS_CERTIFICATE_COUNTRY="DE"
fi
# State
if [ -z "$OPENVAS_CERTIFICATE_STATE" ]
then
  OPENVAS_CERTIFICATE_STATE=""
fi
# Locality
if [ -z "$OPENVAS_CERTIFICATE_LOCALITY" ]
then
  OPENVAS_CERTIFICATE_LOCALITY="Osnabrueck"
fi
# Organization
if [ -z "$OPENVAS_CERTIFICATE_ORG" ]
then
  OPENVAS_CERTIFICATE_ORG="OpenVAS Users"
fi
# (Organization unit)
if [ -z "$OPENVAS_CERTIFICATE_ORG_UNIT" ]
then
  OPENVAS_CERTIFICATE_ORG_UNIT=
fi

# Hostname
if [ -z "$OPENVAS_CERTIFICATE_HOSTNAME" ]
then
  OPENVAS_CERTIFICATE_HOSTNAME=`hostname --fqdn`
  if [ $? -ne 0 ]
  then
    OPENVAS_CERTIFICATE_HOSTNAME="localhost"
  fi
fi

# Key size
if [ -z "$OPENVAS_CERTIFICATE_KEYSIZE" ]
then
  if [ -z "$OPENVAS_CERTIFICATE_SECPARAM" ]
  then
    OPENVAS_CERTIFICATE_SECPARAM="high"
  fi
fi

# Signature algorithm
if [ -z "$OPENVAS_CERTIFICATE_SIGNALG" ]
then
  OPENVAS_CERTIFICATE_SIGNALG="SHA256"
fi

LOGFILE="./openvas-manage-certs.log"

print_help ()
{
  echo "Usage:"
  echo "  $0 [OPTION] - Manage certificate infrastructure for an OpenVAS installation"
  echo
  echo "Options:"
  echo "  -h             Print help"
  echo "  -s             Generate a self-signed certificate"
  echo "  -i             Install a certificate"
  echo "  -c <location>  Install location for the certificate"
  echo "  -k <location>  Install location for the private key"
  echo "  -f             Force overwriting of existing files"
  echo "  -d             Print debug output"
  echo
  echo "Variables:"
  echo "The script honors the following environment variables to set certificate parameters:"
  echo "  OPENVAS_CERTIFICATE_LIFETIME   Days until the certificate will expire"
  echo "  OPENVAS_CERTIFICATE_COUNTRY    Country of certificate subject"
  echo "  OPENVAS_CERTIFICATE_STATE      State of certificate subject"
  echo "  OPENVAS_CERTIFICATE_LOCALITY   Locality of certificate subject"
  echo "  OPENVAS_CERTIFICATE_ORG        Organization of certificate subject"
  echo "  OPENVAS_CERTIFICATE_ORG_UNIT   Organizational unit of certificate subject"
  echo "  OPENVAS_CERTIFICATE_HOSTNAME   Name to use for the certificate"
  echo "  OPENVAS_CERTIFICATE_SIGNALG    Hash algorithm to use for signing"
  echo
  echo "  OPENVAS_CERTIFICATE_KEYSIZE    Size in bits of the generated key"
  echo "  or"
  echo "  OPENVAS_CERTIFICATE_SECPARAM   GnuTLS security level [low|normal|high|ultra]"
  echo

  exit 0
}

# The following TODOS are features deemed desirable which have not yet been
# implemented.
# TODO: Check certificate infrastructure
# TODO: Create a certificate signing request

# TODO: Import a certificate
# Does the certificate contain a private key?
# Do we take the key generated for the signing request?

# Ensure everything is ready to run, prepare temporary directory
set_up ()
{
  # Check if "certtool" binary is available
  if ! type certtool > /dev/null 2>&1
  then
    echo "ERROR: certtool binary not found!"
    exit 1
  fi

  CERT_DIR=`mktemp -d`

  echo "Writing certificate files to $CERT_DIR."
  echo

  KEY_FILENAME="$CERT_DIR/key.pem"
  CERT_FILENAME="$CERT_DIR/cert.pem"
  TEMPLATE_FILENAME="$CERT_DIR/openvas-cert.cfg"
}

# Create a self-signed certificate
create_self_signed ()
{
  umask 022

  # Create template using parameters
  if [ -n "$OPENVAS_CERTIFICATE_LIFETIME" ]
  then
    echo "expiration_days = $OPENVAS_CERTIFICATE_LIFETIME" >> $TEMPLATE_FILENAME
  fi
  if [ -n "$OPENVAS_CERTIFICATE_COUNTRY" ]
  then
    echo "country = \"$OPENVAS_CERTIFICATE_COUNTRY\"" >> $TEMPLATE_FILENAME
  fi
  if [ -n "$OPENVAS_CERTIFICATE_STATE" ]
  then
    echo "state = \"$OPENVAS_CERTIFICATE_STATE\"" >> $TEMPLATE_FILENAME
  fi
  if [ -n "$OPENVAS_CERTIFICATE_LOCALITY" ]
  then
    echo "locality = \"$OPENVAS_CERTIFICATE_LOCALITY\"" >> $TEMPLATE_FILENAME
  fi
  if [ -n "$OPENVAS_CERTIFICATE_ORG" ]
  then
    echo "organization = \"$OPENVAS_CERTIFICATE_ORG\"" >> $TEMPLATE_FILENAME
  fi
  if [ -n "$OPENVAS_CERTIFICATE_ORG_UNIT" ]
  then
    echo "unit = \"$OPENVAS_CERTIFICATE_ORG_UNIT\"" >> $TEMPLATE_FILENAME
  fi
  if [ -n "$OPENVAS_CERTIFICATE_HOSTNAME" ]
  then
    echo "cn = \"$OPENVAS_CERTIFICATE_HOSTNAME\"" >> $TEMPLATE_FILENAME
  fi

  if [ $DEBUG -eq 1 ]
  then
    echo "DEBUG: Using the following template ($TEMPLATE_FILENAME):"
    cat $TEMPLATE_FILENAME
  fi

  if [ -z "$OPENVAS_CERTIFICATE_KEYSIZE" ]
  then
    CERTTOOL_PRIVKEY_PARAM="--sec-param $OPENVAS_CERTIFICATE_SECPARAM"
  else
    CERTTOOL_PRIVKEY_PARAM="--bits $OPENVAS_CERTIFICATE_KEYSIZE"
  fi

  # Create a private key
  certtool --generate-privkey $CERTTOOL_PRIVKEY_PARAM --outfile "$KEY_FILENAME" >> "$LOGFILE" 2>&1
  if [ $? -ne 0 ]
  then
    echo "ERROR: Failed to generate private key, see $LOGFILE for details. Aborting."
    exit 1
  fi

  # TODO: Sleeping here to avoid certtool race condition
  sleep 1

  # Create a certificate
  certtool --generate-self-signed --hash "$OPENVAS_CERTIFICATE_SIGNALG" --load-privkey "$KEY_FILENAME" --outfile "$CERT_FILENAME" --template "$TEMPLATE_FILENAME" >> "$LOGFILE" 2>&1
  if [ $? -ne 0 ]
  then
    echo "ERROR: Failed to create self signed certificate, see $LOGFILE for details. Aborting."
    exit 1
  fi

}

# Install a certificate
# Where should the certificate and the key be installed to?
install_cert ()
{
  if [ -f "$KEY_INSTALL" ] && [ $FORCE -ne 1 ]
  then
    echo "$KEY_INSTALL exists already, not overwriting."
  else
    [ $DEBUG -eq 1 ] && echo "DEBUG: Copying $KEY_FILENAME to $KEY_INSTALL ..."
    cp "$KEY_FILENAME" "$KEY_INSTALL"
  fi
  if [ -f "$CERT_INSTALL" ] && [ $FORCE -ne 1 ]
  then
    echo "$CERT_INSTALL exists already, not overwriting."
  else
    [ $DEBUG -eq 1 ] && echo "DEBUG: Copying $CERT_FILENAME to $CERT_INSTALL ..."
    cp "$CERT_FILENAME" "$CERT_INSTALL"
  fi
}

# Clean up
clean_up ()
{
  if [ "$DEBUG" -ne 1 ]
  then
    rm -rf $CERT_DIR
  else
    echo "DEBUG: Not removing $CERT_DIR in debug mode."
  fi
}

# Parse command line options
if [ $# -eq 0 ]
then
  print_help
fi

INSTALL=0
CREATE_SELF_SIGNED=0
DEBUG=0
FORCE=0

while getopts hsic:k:fd OPTION
do
  case "$OPTION" in
    h)
      print_help
      ;;
    s)
      CREATE_SELF_SIGNED=1
      ;;
    i)
      INSTALL=1
      ;;
    c)
      CERT_INSTALL=$OPTARG
      ;;
    k)
      KEY_INSTALL=$OPTARG
      ;;
    f)
      FORCE=1
      ;;
    d)
      DEBUG=1
      ;;
    \?)
      print_help
      ;;
  esac
done

if [ $CREATE_SELF_SIGNED -eq 1 ]
then
  set_up
  create_self_signed
  # Currently installing a certificate without generating it is not yet
  # supported. Once this is the case, the check for $INSTALL can be separated.
  if [ $INSTALL -eq 1 ]
  then
    install_cert
  fi

  # If the files have been installed, clean up the generation directory.
  if [ $INSTALL -eq 1 ]
  then
    clean_up
  fi
fi

exit 0
