GET {{server}}/vts
[Options]
retry: 3600 # about 60m, maybe called after cold start
retry-interval: 1s
connect-timeout: 1s
HTTP 200
[Asserts]
jsonpath "$.*" count > 100000

GET {{server}}/health/ready
HTTP 200

GET {{server}}/health/alive
HTTP 200

GET {{server}}/health/started
HTTP 200

