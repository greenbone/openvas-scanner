POST {{server}}/container-image-scanner/scans
Content-Type: application/json
file,{{scan_config}}; # WARN: scan_config is set on the root of the file, not path of hurl execution 
HTTP 201
[Captures]
scan_id: body replace "\"" ""

GET {{server}}/container-image-scanner/scans/{{scan_id}}
HTTP 200
[Asserts]
jsonpath "$.scan_id" == {{scan_id}}

POST {{server}}/container-image-scanner/scans/{{scan_id}}
{
        "action": "start"
}
HTTP 204

GET {{server}}/container-image-scanner/scans/{{scan_id}}/status
HTTP 200

GET {{server}}/container-image-scanner/scans/{{scan_id}}/status
[Options]
retry: 3600 # about 60m
retry-interval: 1s
HTTP 200
[Asserts]
jsonpath "$.status" == "succeeded"

GET {{server}}/container-image-scanner/scans/{{scan_id}}/status
HTTP 200
[Captures]
host_info_all: jsonpath "$.host_info.all"
[Asserts]
jsonpath "$.start_time" exists
jsonpath "$.end_time" exists
jsonpath "$.host_info.all" > 0
jsonpath "$.host_info.excluded" == 0
jsonpath "$.host_info.dead" == 0
jsonpath "$.host_info.alive" == {{host_info_all}}
jsonpath "$.host_info.queued" == 0
jsonpath "$.host_info.finished" == {{host_info_all}}

GET {{server}}/container-image-scanner/scans/{{scan_id}}/results
HTTP 200
[Captures]
result_count: jsonpath "$.*" count 
[Asserts]
jsonpath "$.*" count > 3 # needed for further testing

GET {{server}}/container-image-scanner/scans/{{scan_id}}/results/{{result_count}}
HTTP 404

GET {{server}}/container-image-scanner/scans/{{scan_id}}/results?range={{result_count}}-{{result_count}}
HTTP 200
[Asserts]
jsonpath "$.*" count == 0

GET {{server}}/container-image-scanner/scans/{{scan_id}}/results?range=0-{{result_count}}
HTTP 200
[Asserts]
jsonpath "$.*" count == {{result_count}}

GET {{server}}/container-image-scanner/scans/{{scan_id}}/results?range=0-1
HTTP 200
[Asserts]
jsonpath "$.*" count == 2

GET {{server}}/container-image-scanner/scans/{{scan_id}}/results/2
HTTP 200
[Asserts]
jsonpath "$.id" == 2

DELETE {{server}}/container-image-scanner/scans/{{scan_id}}
HTTP 204

GET {{server}}/container-image-scanner/scans/{{scan_id}}
HTTP 404
