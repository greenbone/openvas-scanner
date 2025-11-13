GET {{server}}/scans/{{scan_id}}/status
HTTP 200
[Asserts]
jsonpath "$.start_time" exists
jsonpath "$.end_time" exists
jsonpath "$.status" == {{expected_status}}
jsonpath "$.host_info.all" == 0
jsonpath "$.host_info.excluded" == 0
jsonpath "$.host_info.dead" == 0
jsonpath "$.host_info.alive" == 0
jsonpath "$.host_info.queued" == 0
jsonpath "$.host_info.finished" == 0
jsonpath "$.host_info.remaining_vts_per_host.*" count == 0

GET {{server}}/scans/{{scan_id}}invalid_scan/status
HTTP 404