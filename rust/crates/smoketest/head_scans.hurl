HEAD {{server}}/scans
HTTP 204
[Asserts]
header "authentication" == "mTLS"
header "api-version" == "1"
header "feed-version" exists
header "date" exists

# HEAD {{server}}/scans
# HTTP 401