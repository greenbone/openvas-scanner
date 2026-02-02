HEAD {{server}}/
HTTP 404
#[Asserts]
#header "authentication" == "mTLS"
#header "api-version" == "1"
#header "feed-version" exists
#header "date" exists