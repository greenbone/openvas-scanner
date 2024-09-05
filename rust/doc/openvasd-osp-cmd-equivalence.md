# Migration Guide for API usage of previous OSP commands

This document shows the migration of OSP commands (implemented by ospd-openvas) to the new scanner API (implemented by openvasd). It only provides the XML for the command and its corresponding JSON counterpart, as well as the endpoint of the HTTP API. For further information of the commands either see [OSP](https://docs.greenbone.net/API/OSP/osp-22.4.html) or [Scanner API](https://greenbone.github.io/scanner-api/).

# Table of contents
1. [Help command](#Help-command)
2. [Get memory usage command](#Get-memory-usage-command)
3. [Start a scan](#Start-a-scan)
4. [Stop a scan](#Stop-a-scan)
5. [Delete a scan](#Delete-a-scan)
6. [Fetching results](#Fetching-results)
7. [Scan status and progress](#Scan-status-and-progress)
8. [Feed check](#Feed-check)
9. [Get VTs](#Get-VTs)
10. [Get Version](#Get-Version)
11. [Get scanner details](#Get-scanner-details)
12. [Get sensor performance](#Get-sensor-performance)

### Help command

there is a help command which includes all supported OSP commands and details. There is no equivalent command for Scanner API. Just refer to the Scanner API
``` xml
<help/>
``` 
### Get memory usage command

This command shows RSS, VMS and shared current memory usage. It is a debugging purpose command. There is no equivalent command for Scanner API.
``` xml
<get_memory_usage unit='mb'/>
``` 
### Start a scan

***With OSP***

To start a scan with OSP commands, it was just necessary one XML command which included the scan ID as parameter and the scan configuration

****gvm-cli --protocol OSP socket --sockpath /tmp/openvas.sock --xml****

start scan OSP command
``` xml
<start_scan scan_id='97079ee9-8917-49da-aa4f-4ef95f757ac1'>
  <targets>
    <target>
      <hosts>192.168.10.128</hosts>
      <ports>T:22,9390</ports>
      <alive_test>2</alive_test>
      <credentials>
      </credentials>
      <exclude_hosts/>
    </target>
  </targets>
  <vt_selection>
    <vt_single id='1.3.6.1.4.1.25623.1.0.14259'/>
    <vt_single id='1.3.6.1.4.1.25623.1.0.10330'/>
    <vt_single id='1.3.6.1.4.1.25623.1.0.108198'/>
  </vt_selection>
  <scanner_params>
    <test_empty_vhost>0</test_empty_vhost>
    <expand_vhosts>0</expand_vhosts>
    <unscanned_closed>0</unscanned_closed>
  </scanner_params>
</start_scan>
``` 
***With Scanner API***

while with Scanner API it is necessary to do it in two steps. First create the scan task in the server with 
``` cmd
Method: POST
Endpoint: /scans
Json body:
``` 
``` json
{
  "target": {
    "hosts": [
      "192.168.0.1-10"
    ],
    "excluded_hosts": [
      "192.168.0.5"
    ],
    "ports": [
      {
        "protocol": "tcp",
        "range": [
          {
            "start": 22,
            "end": 22
          }
        ]
      }
    ],
    "alive_test_methods": [
      "icmp"
    ],
    "credentials": [
      {
        "service": "ssh",
        "port": 22,
        "up": {
          "username": "user",
          "password": "pass"
        }
      }
    ]
  },
  "vts": [
    {
        "oid": "1.3.6.1.4.1.25623.1.0.90022"
    }
  ]
}

```
where "simple_scan_ssh_only.json" is the scan config. This HTTP request will get a response from the server which includes a scan_id. Later, every operation done on this task, must be done using the received scan_id. So for starting the stored scan you use the following POST method in the URL, passing the action as json object.

``` cmd
Method: POST
Endpoint: /scans/{scan_id}
Parameter scan_id: : is de Scan ID
Json body:
``` 
``` json
{"action": "start"}
``` 

### Stop a scan

As explained in the subsection above, you know the scan ID for OSP, because it is necessary for starting a new scan, while the scan ID is created by Openvasd when using Scanner API. Then the scan_id is necessary for both protocols.

***With OSP***
``` xml
<stop_scan scan_id='97079ee9-8917-49da-aa4f-4ef95f757ac1'/>
``` 

***With Scanner API***
``` cmd
Method: POST
Endpoint: /scans/{scan_id}
Parameter scan_id: : is de Scan ID
Json body:
``` 
``` json
{"action": "stop"}
``` 

### Delete a scan

With the known scan_id, a scan can be deleted. The scan must not be running. So it must be either stopped before or finished. In case of the new scanner API it could also be in the stored status.

***With OSP***
``` xml
<delete_scan scan_id='97079ee9-8917-49da-aa4f-4ef95f757ac1'/>
``` 

***With Scanner API***

For deleting a scan, the DELETE method is used on the scan URL containing the scan ID.
``` cmd
Method: DELETE
Endpoint: /scans/{scan_id}

Parameter scan_id: is de Scan ID
``` 

### Fetching results

Knowing the scan id, it is possible to fetch results. This command allows some options, like fetching just an amount of results.

***With OSP***

It is possible to tell OSPd if it must remove or preserve in memory the results. Also, it is possible to specify the max amount of results to be fetch.
``` xml
<get_scans scan_id='97079ee9-8917-49da-aa4f-4ef95f757ac1' pop_results='1' max_results='10'/>
``` 

***With Scanner API***

Results in Openvasd are stored with a result ID. This ID is useful to fetch results by ranges. Giving no ranges, all results are included in the response.
Results are not removed until the whole scan is deleted. Therefore it is necessary to specify the range of results if you want to fetch a given amount of results with out duplicate them in the responses. Passing a single number you get all results starting from the given result ID, or you can pass a range with start-end to fetch a max amount of results

``` cmd
Method: GET
Endpoint: /scans/{scan_id}/results?range=0-9

Parameter scan_id: is de Scan ID.
Optional Query: ?range=start-end, where end is optional as well.
``` 

### Scan status and progress

***With OSP***

OSP returns the scan status details in the response of same get_scans command for fetching results. Also, it is possible to get some scan progress information passing an argument to the command.
``` xml
<get_scans scan_id='97079ee9-8917-49da-aa4f-4ef95f757ac1' details='0' progress='1'/>
``` 

***With Scanner API***

Scanner API has a dedicated command for get the status and progress.
``` cmd
Method: GET
Endpoint: /scans/{scan_id}/status

Parameter scan_id: is de Scan ID
``` 

### Feed check

***With OSP***

This command performs some test and check if the feed lock file is in use or not. There is no equivalent command for Scanner API.
``` xml
<check_feed/>
``` 

***With Scanner API***

Although, there is some commands to test openvasd's health. Ready, will respond with 200 OK if the feed is already uploaded. These commands also provide the current feed version.
``` cmd
Method: GET
Endpoint: /health/ready 
       or /health/alive
       or /health/started
``` 
### Get VTs

Get a list of Vulnerability test present in the current feed. This includes Notus and NASL tests.

***With Osp***

You can get the whole feed, a single VT, or filter by family or modification date. "Details" shows the script dependency as OID or script name.
``` xml
<get_vts vt_id='1.3.6.1.4.1.25623.1.1.5.2014.322' details='1'/>
<get_vts filter='modification_time>1706848198' details='1'/>
``` 

***With Scanner API***

It is possible to get a list of supported OIDs, the whole feed information or information of a single VT. Filters are not implemented/supported.
``` cmd
Method: GET
Endpoint: /vts 
          /vts?information=bool
          /vts/{script_oid}

Parameter script_oid: get the metadata for the given script OID.
Optional Query: ?information=bool shows the whole feed metadata.
          
```

### Get Version

***With Osp***

A list of versions is returned (feed version,OSPd version, OSP protocol version, openvas version)
```  xml
<get_version/>
``` 


***With Scanner API***

Only the feed version and the HTTP version are available.
``` cmd
Method: HEAD
``` 

### Get scanner details

Return details about the scanner

***With Osp***

Return a Scanner description and the scanner preferences.
``` xml 
<get_scanner_details/>
``` 

***With Scanner API***

Return a list of scanner preferences.
``` cmd
Method: GET
Entrypoint: scans/preferences
``` 

### Get sensor performance

Return system report. There is currently no equivalent command for Scanner API

***With Osp***

More information about this command GOS GVMCG
``` xml
<get_performance start='1706848198' end='1706848198' title='CPU'/>
``` 


