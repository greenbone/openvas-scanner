POST {{server}}/scans
Content-Type: application/json
file,{{scan_config}}; # WARN: scan_config is set on the root of the file, not path of hurl execution 
HTTP 201
[Captures]
scan_id: body replace "\"" ""

POST {{server}}/scans/{{scan_id}}
{
        "action": "start"
}
HTTP 204

GET {{server}}/scans/{{scan_id}}/status
[Options]
retry: 240
retry-interval: 1s
HTTP 200
[Asserts]
jsonpath "$.status" == "running"

POST {{server}}/scans/{{scan_id}}
{
        "action": "stop"
}
HTTP 204

GET {{server}}/scans/{{scan_id}}/status
[Options]
retry: 10
retry-interval: 1s
HTTP 200
[Asserts]
jsonpath "$.status" == "stopped"

POST {{server}}/scans/{{scan_id}}
{
        "action": "start"
}
HTTP 204

GET {{server}}/scans/{{scan_id}}/status
[Options]
retry: 60
retry-interval: 1s
HTTP 200
[Asserts]
jsonpath "$.status" == "running"

