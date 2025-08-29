GET {{server}}/scans/{{scan_id}}/status
[Options]
delay: 500ms
HTTP 200
[Captures]
st: jsonpath "$.status"

