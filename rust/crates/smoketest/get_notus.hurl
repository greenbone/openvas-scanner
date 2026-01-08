GET {{server}}/notus
HTTP 200
[Captures]
elements: jsonpath "$.*"
[Asserts]
jsonpath "$[0]" == "almalinux_10"
variable "elements" count > 100