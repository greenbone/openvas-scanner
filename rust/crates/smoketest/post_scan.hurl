POST {{server}}/scans
{}
HTTP 400

# POST {{server}}/scans
# HTTP 403

POST {{server}}/scans
Content-Type: application/json
file,configs/discovery.json;
HTTP 201
[Captures]
scan_id: body replace "\"" ""
