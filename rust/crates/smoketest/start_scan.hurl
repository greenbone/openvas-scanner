POST {{server}}/scans/{{scan_id}}
{
        "action": "start"
}
HTTP 204


# POST {{server}}/scans/{{scan_id}}
# {
#         "action": "invalid"
# }
# HTTP 400

# POST {{server}}/scans/invalid
# {
#         "action": "start"
# }
# HTTP 404


