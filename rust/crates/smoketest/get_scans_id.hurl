GET {{server}}/scans/{{scan_id}}
HTTP 200
[Asserts]
jsonpath "$.scan_id" == {{scan_id}}
jsonpath "$.target.hosts[0]" == "{{target_host}}"
jsonpath "$.target.ports.[0].protocol" == "tcp"
jsonpath "$.target.ports.[1].protocol" == "udp"
jsonpath "$.target.ports.[0].range.[0].start" == 1
jsonpath "$.target.ports.[0].range.[0].end" == 5
jsonpath "$.target.excluded_hosts" isEmpty
jsonpath "$.target.credentials.[0].service" not exists
# jsonpath "$.target.credentials.[0].port" == 22
# jsonpath "$.target.credentials.[0].up.username" == "msfadmin"
# jsonpath "$.target.credentials.[0].up.password" == "***"
jsonpath "$.target.alive_test_ports" count == 3
jsonpath "$.target.alive_test_methods" isEmpty
jsonpath "$.target.reverse_lookup_unify" == null
jsonpath "$.target.reverse_lookup_only" == null

jsonpath "$.scan_preferences.[0].id" not exists
jsonpath "$.scan_preferences.[0].value" not exists
jsonpath "$.scan_preferences.[22].id" not exists
jsonpath "$.scan_preferences.[22].value" not exists

jsonpath "$.vts.[0].oid" == "1.3.6.1.4.1.25623.1.0.100034"
jsonpath "$.vts.[0].parameters" isEmpty
jsonpath "$.vts.[304].oid" == "1.3.6.1.4.1.25623.1.0.91984"
jsonpath "$.vts.[304].parameters" isEmpty


GET {{server}}/scans/{{scan_id}}invalid
HTTP 404
