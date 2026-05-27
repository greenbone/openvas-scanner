POST {{server}}/scans
Content-Type: application/json
file,{{scan_config}};
HTTP 201
[Captures]
scan_id: body replace "\"" ""

POST {{server}}/scans/{{scan_id}}
Content-Type: application/json
{
  "action": "start"
}
HTTP 204

GET {{server}}/scans/{{scan_id}}/status
[Options]
retry: 600
retry-interval: 1s
HTTP 200
[Asserts]
jsonpath "$.status" == "succeeded"

GET {{server}}/scans/{{scan_id}}/results
HTTP 200
[Asserts]
jsonpath "$.*" count == {{expected_result_count}}

DELETE {{server}}/scans/{{scan_id}}
HTTP 204
