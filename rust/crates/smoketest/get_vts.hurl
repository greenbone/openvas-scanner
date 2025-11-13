GET {{server}}/vts
HTTP 200
[Captures]
id: jsonpath "$.*"
[Asserts]
jsonpath "$[0]" == "1.3.6.1.4.1.25623.1.0.02602"
jsonpath "$[14]" == "1.3.6.1.4.1.25623.1.0.100013"
jsonpath "$[223558]" == "1.3.6.1.4.1.25623.1.2.1.2025.81"
variable "id" count > 200000

# GET {{server}}/vts
# HTTP 503
# #The list of OIDs is currently updated. Please try again later.