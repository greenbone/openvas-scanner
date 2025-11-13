# POST {{server}}/scans
# {}
# HTTP 400

# POST {{server}}/scans
# HTTP 403

POST {{server}}/scans
Content-Type: application/json
file,configs/simple_scan_ssh_only.json;
HTTP 201
[Captures]
scan_id: body replace "\"" ""
