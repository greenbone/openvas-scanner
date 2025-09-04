GET {{server}}/scans/{{scan_id}}/results
HTTP 200
[Captures]
id: jsonpath "$.*"
[Asserts]
variable "id" count == 3