GET {{server}}/notus
HTTP 200
[Captures]
elements: jsonpath "$.*"
[Asserts]
variable "elements" count > 100
