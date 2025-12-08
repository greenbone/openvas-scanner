GET {{server}}/scans/{{scan_id}}/results/{{rid}}
HTTP 200
[Asserts]
jsonpath "$.id" == {{rid}}
jsonpath "$.type" == "host_detail"
jsonpath "$.ip_address" == "127.0.0.1"
jsonpath "$.hostname" == {{target_host}}
jsonpath "$.oid" == "1.3.6.1.4.1.25623.1.0.103997"
jsonpath "$.message" == "<host><detail><name>ports</name><value>8443</value><source><type>nvt</type><name>1.3.6.1.4.1.25623.1.0.900239</name><description>Check Open TCP Ports</description></source></detail></host>"
jsonpath "$.detail.name" == "ports"
jsonpath "$.detail.value" == "8443"
jsonpath "$.detail.source.type" == "nvt"
jsonpath "$.detail.source.name" == "1.3.6.1.4.1.25623.1.0.900239"
jsonpath "$.detail.source.description" == "Check Open TCP Ports"

GET {{server}}/scans/{{scan_id}}/results/999999
HTTP 404