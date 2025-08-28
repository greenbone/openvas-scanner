POST {{server}}/scans
Content-Type: application/json
file,configs/simple_scan_ssh_only.json;
HTTP 201
[Captures]
scan_id: body replace "\"" ""
