GET {{server}}/scans/{{scan_id}}/status
HTTP 200
[Asserts]
jsonpath "$.status" == "succeeded"

