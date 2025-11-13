POST {{server}}/notus/{{os}}
[
    "libzmq3-dev-4.3.0-4+deb10u1"
]
HTTP 200
[Asserts]
jsonpath "$.*[0].name" first == "libzmq3-dev"
jsonpath "$.*[0].installed_version" first == "4.3.0-4+deb10u1"
jsonpath "$.*[0].fixed_version.version" first == "4.3.1-4+deb10u1"
jsonpath "$.*[0].fixed_version.specifier" first == ">="

# POST {{server}}/notus/{{os}}
# [
#     "BAD_REQUEST_BODY"
# ]
# HTTP 400

# POST {{server}}/notus/{{os}}
# Content-Type: application/json
# {
#     "force": "501" 
# }
# HTTP 501