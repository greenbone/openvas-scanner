POST {{server}}/scans
Content-Type: application/json
file,{{scan_config}};
HTTP 201

POST {{server}}/scans/{{scan_id}}
Content-Type: application/json
{
  "action": "start"
}
HTTP 204

GET {{server}}/scans/{{scan_id}}/status
[Options]
retry: {{retry_count}}
retry-interval: {{retry_interval_ms}}
HTTP 200
[Asserts]
jsonpath "$.status" == "succeeded"

GET {{server}}/scans/{{scan_id}}/results
HTTP 200
