GET {{server}}/vts
HTTP 200
[Captures]
vts: jsonpath "$.*"
[Asserts]
jsonpath "$[0]" contains "1.3.6.1.4.1.25623"
jsonpath "$[100000]" contains "1.3.6.1.4.1.25623"
variable "vts" count > 100000