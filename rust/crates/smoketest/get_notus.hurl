GET {{server}}/notus
HTTP 200
[Asserts]
jsonpath "$[0]" == "almalinux_10"
jsonpath "$[1]" == "almalinux_8"
jsonpath "$[531]" == "ubuntu_9.10"