# Definition for the new Scanner HTTP API via JSON


## Requests

### start scan

The start scan command is used to start a scan. It is not necessary to provide a scan ID, in this case the scanner will generate a unique one. In either case the scan ID is returned in the response. Note that the scan ID must be a UUIDv4.

- Method: POST
- Path: `/scans`
- Parameters: None
- Request Body:
<pre>
  <code>
    {
      <a href="#scan_id">"scan_id"</a>: string,
      <a href="#targets">"targets"</a>: [{
        <a href="#target">"target"</a>: [string],
        <a href="#ports">"ports"</a>: [string],
        <a href="#credentials">"credentials"</a>: [{
          <a href="#service">"service"</a>: string,
          <a href="#port">"port"</a>: int,
          <a href="#up">"up"</a>: {
            <a href="#username">"username"</a>: string,
            <a href="#password">"password"</a>: string
          },
          <a href="#usk">"usk"</a>: {
            <a href="#username">"username"</a>: string,
            <a href="#password">"password"</a>: string,
            <a href="#private">"private"</a>: string
          },
          <a href="#snmp">"snmp"</a>: {
            <a href="#username">"username"</a>: string,
            <a href="#password">"password"</a>: string,
            <a href="#community">"community"</a>: string,
            <a href="#auth_algorithm">"auth_algorithm"</a>: string,
            <a href="#privacy_password">"privacy_password"</a>: string,
            <a href="#privacy_algorithm">"privacy_algorithm"</a>: string
          }
        }]
      }],
      <a href="#excluded">"excluded"</a>: [string],
      <a href="#scanner_parameters">"scanner_parameters"</a>: {key:value},
      <a href="#vts">"vts"</a>: {
        <a href="#vt_single">"vt_single"</a>: [{
          <a href="#oid">"oid"</a>: string,
          <a href="#vt_parameters">"vt_parameters"</a>: [{
            <a href="#parameter">"parameter"</a>: string,
            <a href="#value">"value"</a>: any
          }]
        }],
        <a href="#vt_group">"vt_group"</a>: [string]
      }
    }
  </code>
</pre>
- Status codes: 
  - 201 Created: the new scan was created. The address to the scan is returned
  - 400 bad request
- Response Body:
<pre>
  <code>
    {
      <a href="#scan_id">"scan_id"</a>: string
    }
  </code>
</pre>


### get scan

The get scan command returns information about a given scan. The information here are the same as they were given in start scan.

- Method: GET
- Path: `/scan/<scan_id>`
- Parameters: None
- Request: None
- Status codes:
  - 200 Ok
  - 404 Scan not found
- Response Body:
<pre>
  <code>
    {
      <a href="#scan_id">"scan_id"</a>: string,
      <a href="#targets">"targets"</a>: [{
        <a href="#target">"target"</a>: [string],
        <a href="#ports">"ports"</a>: [string],
        <a href="#credentials">"credentials"</a>: [{
          <a href="#service">"service"</a>: string,
          <a href="#port">"port"</a>: int,
          <a href="#up">"up"</a>: {
            <a href="#username">"username"</a>: string,
            <a href="#password">"password"</a>: string
          },
          <a href="#usk">"usk"</a>: {
            <a href="#username">"username"</a>: string,
            <a href="#password">"password"</a>: string,
            <a href="#private">"private"</a>: string
          },
          <a href="#snmp">"snmp"</a>: {
            <a href="#username">"username"</a>: string,
            <a href="#password">"password"</a>: string,
            <a href="#community">"community"</a>: string,
            <a href="#auth_algorithm">"auth_algorithm"</a>: string,
            <a href="#privacy_password">"privacy_password"</a>: string,
            <a href="#privacy_algorithm">"privacy_algorithm"</a>: string
          }
        }]
      }],
      <a href="#excluded">"excluded"</a>: [string],
      <a href="#scanner_parameters">"scanner_parameters"</a>: {key:value},
      <a href="#vts">"vts"</a>: {
        <a href="#vt_single">"vt_single"</a>: [{
          <a href="#oid">"oid"</a>: string,
          <a href="#vt_parameters">"vt_parameters"</a>: [{
            <a href="#parameter">"parameter"</a>: string,
            <a href="#value">"value"</a>: any
          }]
        }],
        <a href="#vt_group">"vt_group"</a>: [string]
      }
    }
  </code>
</pre>


### get results

This command is used to get all results of a single scan.

- Method: GET
- Path: `/scans/<scan_id>/results`
- Parameters: None
- Request: None
- Status codes:
  - 200 Ok
  - 404 Scan not found
- Response:
<pre>
  <code>
    [{
      <a href="#name">"name"</a>: string,
      <a href="#result_type">"result_type"</a>: string,
      <a href="#severity">"severity"</a>: float,
      <a href="#ip_address">"ip_address"</a>: string,
      <a href="#hostname">"hostname"</a>: string,
      <a href="#oid">"oid"</a>: string,
      <a href="#port">"port"</a>: int,
      <a href="#protocol">"protocol"</a>: string,
      <a href="#qod">"qod"</a>: int,
      <a href="#uri">"uri"</a>: string,
      <a href="#description">"description"</a>: string
    }]
  </code>
</pre>


### pop results

This command is used to get results of a single scan, without including the one received before. Use this in case only new results should be given.

- Method:  POST
- Path: `/scans/<scan_id>/results`
- Parameters: None
- Request: None
- Status codes:
  - 200 Ok
  - 404 Scan not found
- Response:
<pre>
  <code>
    [{
      <a href="#name">"name"</a>: string,
      <a href="#result_type">"result_type"</a>: string,
      <a href="#severity">"severity"</a>: float,
      <a href="#ip_address">"ip_address"</a>: string,
      <a href="#hostname">"hostname"</a>: string,
      <a href="#oid">"oid"</a>: string,
      <a href="#port">"port"</a>: int,
      <a href="#protocol">"protocol"</a>: string,
      <a href="#qod">"qod"</a>: int,
      <a href="#uri">"uri"</a>: string,
      <a href="#description">"description"</a>: string
    }]
  </code>
</pre>

### get status

The get status command requests the status of a given scan.

- Method: GET
- Path: `/scan/<scan_id>/status`
- Request: None
- Status codes: 
  - 200 Ok
  - 404 Scan not found
- Response:
<pre>
  <code>
    [{
      <a href="#start_time">"start_time"</a>: int,
      <a href="#end_time">"end_time"</a>: int,
      <a href="#status">"status"</a>: string,
      <a href="#progress">"progress"</a>: int,
      <a href="#alive_hosts">"alive_hosts"</a>: int,
      <a href="#dead_hosts">"dead_hosts"</a>: int,
      <a href="#excluded_host">"excluded_host"</a>: int,
      <a href="#total_host">"total_host"</a>: int,
    }]
  </code>
</pre>

### delete scan

The delete scan request deletes a scan from the scanner including all data corresponds to it. Unless the scan is not finished, this request will fail.

- Method: DELETE
- Path: `/scan/<scan_id>`
- Request: None
- Status codes: 
  - 200 Ok
  - 404 Scan not found
- Response: None

### stop scan

The stop scan request stops a running scan. Unless the scan is not running, this request will fail.

- Method: POST
- Path: `/scan/<scan_id>`
- Request: None
- Status codes:
  - 200 Ok
  - 404 Scan not found
- Response: None

### get vts

The get vts command is used to get information about VTs with the possibility to add a query for filtering. If no query is given, all VTs are returned.

- Method: GET
- Path: `/vts?<query>`
- Parameters:
  - query: this parameter is used to parse a query, to be able to filter vts. The query must be 
- Request: None
- Status codes:
  - 200 Ok
- Response:
<pre>
  <code>
    {
      <a href="#number_of_vts">"number_of_vts"</a>: int,
      <a href="#vts">"vts"</a>: [{
        <a href="#oid">"oid"</a>: string,
        <a href="#name">"name"</a>: string,
        <a href="#refs">"refs"</a>: {[
          <a href="#reference_typ">"reference_typ"</a>: string,
          <a href="#value">"value"</a>: string
        ]},
        <a href="#creation_time">"creation_time"</a>: int,
        <a href="#modification_time">"modification_time"</a>: int,
        <a href="#summary">"summary"</a>: string,
        <a href="#affected">"affected"</a>: string,
        <a href="#insight">"insight"</a>: string,
        <a href="#solution">"solution"</a>: string,
        <a href="#detection">"detection"</a>: {
          <a href="#detection_type">"detection_type"</a>: string,
          <a href="#info">"info"</a>: string
        },
        <a href="#severities">"severities"</a>: [{
          <a href="#severity_type">"severity_type"</a>: string,
          <a href="#value">"value"</a>: string,
          <a href="#date">"date"</a>: string
        }],
        <a href="#filename">"filename"</a>: string,
        <a href="#family">"family"</a>: string,
        <a href="#category">"category"</a>: int
      }] 
    }
  </code>
</pre>

### get vt

This command returns all information about a specific VT

- Method: GET
- Path: `/vts/<oid>`
- Parameters: None
- Request: None
- Status codes
  - 200 Ok
  - 404 VT not found
- Response:
<pre>
  <code>
    {
      <a href="#oid">"oid"</a>: string,
      <a href="#name">"name"</a>: string,
      <a href="#refs">"refs"</a>: {[
        <a href="#type">"type"</a>: string,
        <a href="#value">"value"</a>: string
      ]},
      <a href="#creation_time">"creation_time"</a>: int,
      <a href="#modification_time">"modification_time"</a>: int,
      <a href="#summary">"summary"</a>: string,
      <a href="#affected">"affected"</a>: string,
      <a href="#insight">"insight"</a>: string,
      <a href="#solution">"solution"</a>: string,
      <a href="#detection">"detection"</a>: {
        <a href="#type">"type"</a>: string,
        <a href="#info">"info"</a>: string
      },
      <a href="#severities">"severities"</a>: [{
        <a href="#type">"type"</a>: string,
        <a href="#value">"value"</a>: string,
        <a href="#date">"date"</a>: string
      }],
      <a href="#filename">"filename"</a>: string,
      <a href="#family">"family"</a>: string,
      <a href="#category">"category"</a>: int
    }
  </code>
</pre>

## Fields

### scan_id

This field contains the scan ID. The scan ID is used to identify different scans. It can be set freely, but normally contains an UUID.

### targets

This field contains a list of targets. It is only used for starting scans.

### target

This field contains a target. A target is a list of devices in the network. A devices can be identified by the following:
- IPv4 address (172.17.0.1)
- IPv6 address (2001:0DB8:0:CD30::1)
- IPv4 range (1.2.3.4-1.2.3.10)
- IPv6 range (2001:0DB8:0:CD30::1-2001:0DB8:0:CD30::9)
- IPv4 cidr notation (172.17.0.0/17)
- IPv6 cidr notation (2001:0DB8:0:CD30::1/60)
- hostname

### ports

This field contains a list of ports. Also port ranges can be given.

### credentials

This field contains a list of credentials for the target. Credentials are used to get access on a target machine via a specified authentication [service](#service).

### service

This field contains the authentication service used to get access to a target machine. Currently supported services are:
- ssh ([up](#up), [usk](#usk))
- smb ([up](#up))
- esxi ([up](#up))
- snmp ([snmp](#snmp))
The parentheses contain the available authentication methods. These are NOT part of the string used in the service field. Only one authentication method can be used. If multiple are given, the behavior is undefined.

### port

This field contains the port either used for the specified [service](#service) or which port a found [result](#results) corresponds to.

### up

This field is used for the authentication with username and password. Only one of the authentication methods ([up](#up), [usk](#usk), [snmp](#snmp)) can be used. If this one is used the field for the other two should be omitted.

### usk

This field is used for the authentication with username and security key. Only one of the authentication methods ([up](#up), [usk](#usk), [snmp](#snmp)) can be used. If this one is used the field for the other two should be omitted.

### snmp

This field is used for the authentication via snmp. Only one of the authentication methods ([up](#up), [usk](#usk), [snmp](#snmp)) can be used. If this one is used the field for the other two should be omitted.

### username

This field contains a username.

### password

This field contains a password.

### private

This field contains a path to a key-file. This key-file is then used for ssh authentication with a security key.

### community

This field contains a community string for snmp authentication.

### auth_algorithm

This field contains the algorithm used for snmp authentication. It can be either `md5` or `sha1`.

### privacy_password

This field contains the privacy password for snmp authentication.

### privacy_algorithm

This field contains the algorithm used for encryption of the privacy password. It can be either `aes` or `des`. If no encryption is required, this field can be omitted.

### excluded

This field contains a target similar to [target](#target). The only difference is the usage, as this will exclude specified targets from the scan.

### scanner_parameters

This field contains parameters for the scanner, that should apply for the scan.

### vts

This field contains the collection of Vulnerability Tests. It is either used in the start scan command, in which case also parameter can be defined for the tests or for the get vts command.

### vt_single

This field contains a list of single VTs, with the possibility to set its parameters.

### oid

This field contains an identifier of a VT.

### vt_parameters

This field contains a list of parameters for a single VT.

### parameter

This field contains the name of the VT parameter to set.

### value

This field contains a value for the corresponding field.

In case of [vt_parameters](#vt_parameters) this field contains the value of the VT parameter. It can be either an integer or a string. In case a bool value is required for the parameter, any value other than "" and 0 will be interpret as a True value.

### vt_group

This field contains a list of VT groups. Groups are defined by a filter string. The string consists of a key-value pair separated with a `=`. The key represents a field in the VT metadata, the value its actual value. Any data within a VT can be used as a filter, but normally the VT family is used. E.g. `"family=general"` or `"family=debian"`.

### details

This field enables the details either in the get scan or get vts command.

### pop_results

This field is a option to automatically delete results one the scanner, when receiving them. This will free up some memory.

### start_time

This field contains the start time of the scan in Unix time format. Theses are the seconds elapsed since 1st January 1970.

### end_time

This field contains the end time of the scan in Unix time format. Theses are the seconds elapsed since 1st January 1970.

### status

This field contains the status of the scan. It can be either queued, init, started, stopped or finished.

### progress

This field contains an approximated value between 0 and 100.

### results

This field contains a list of results for the corresponding scan.

### ip_address

This field contains an IP-Address the result corresponds to.

### host

This field contains a hostname the result corresponds to.

### protocol

This field contains the network communication protocol, the port corresponds to. It can be either tcp or udp.

### qod

This field is the quality of detection and contains a value between 0 and 100.

### uri

This field contains a Uniform Resource Identifier for a result.

### result_type

The type of a result, it can be either of type info, warning, error or alarm.

### reference_type

The type of a reference of a VT.

### detection_type

A type of a detection of a VT.

### severity_type

A type of a severity of a VT.

### description

This field contains a general description of the found result, like how a vulnerability was found, what error occurred etc.

### alive_hosts

This field contains the number of actual hosts that are alive. Those are the hosts of the target, that are scanned.

### dead_hosts

This field contains the number of hosts that are not reachable. These are excluded from the target.

### excluded_hosts

This field contains the number of hosts that were excluded within the scan start command ([excluded](#excluded)).

### total_hosts

This field contains the total number of hosts of the target that should be scanned.

### vts

This field contains a collection of VTs.

### name

This field is used for VTs as well as for results.

### refs

This field contains a list of references of a VT.

### creation_time

This field contains a timestamp of when the corresponding VT was created.

### modification_time

This field contains a timestamp of when the corresponding VT was last modified.

### summary

This field contains a summary in textual form of the VT.

### affected

This field contains information of what is affected by the vulnerability.

### insight

This field contains more detailed information about the vulnerability, than the summary.

### solution

This field contains a solution of how to fix the vulnerability.

### detection

This field contains a description, how the vulnerability was detected.

### severities

This field contains a list of severities

### date

This field contains a timestamp.

### filename

This field contains the filename of the file containing the VT.

### family

This field contains the family the VT belongs to.

### category

This field contains the category of the VT. It is used to determine the phase, in which is executed during a scan.
