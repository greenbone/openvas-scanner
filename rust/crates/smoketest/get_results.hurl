GET {{server}}/scans/{{scan_id}}/results
HTTP 200
[Captures]
id: jsonpath "$.*"
[Asserts]
variable "id" count == 56
jsonpath "$[0].id" == 0
jsonpath "$[0].type" == "host_start"
jsonpath "$[0].ip_address" == "127.0.0.1"
jsonpath "$[0].hostname" == ""
jsonpath "$[0].oid" == ""
jsonpath "$[0].message" toDate "%a %b %d %H:%M:%S %Y" format "%a %b %d" == "{{currentDate}}"

jsonpath "$[7].id" == 7
jsonpath "$[7].type" == "host_detail"
jsonpath "$[7].ip_address" == "::1"
jsonpath "$[7].hostname" == {{target_host}}
jsonpath "$[7].oid" == "1.3.6.1.4.1.25623.1.0.103997"
jsonpath "$[7].message" == "<host><detail><name>traceroute</name><value>::1</value><source><type>nvt</type><name>1.3.6.1.4.1.25623.1.0.51662</name><description>Traceroute</description></source></detail></host>"
jsonpath "$[7].detail.name" == "traceroute"
jsonpath "$[7].detail.value" == "::1"
jsonpath "$[7].detail.source.type" == "nvt"
jsonpath "$[7].detail.source.name" == "1.3.6.1.4.1.25623.1.0.51662"
jsonpath "$[7].detail.source.description" == "Traceroute"

GET {{server}}/scans/{{scan_id}}/results?range=0-1
HTTP 200
[Captures]
id: jsonpath "$.*"
[Asserts]
variable "id" count == 2

GET {{server}}/scans/{{scan_id}}/results?range=10
HTTP 200
[Captures]
id: jsonpath "$.*"
[Asserts]
variable "id" count == 46

GET {{server}}/scans/invalid_scanid/results
HTTP 404