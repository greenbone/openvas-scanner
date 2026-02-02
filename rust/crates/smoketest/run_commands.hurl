#!/bin/bash

## Required environment variables:
# CLIENT_CERT
# CLIENT_KEY
# OPENVASD_SERVER

#HEAD /
hurl -k --cert $CLIENT_CERT --key $CLIENT_KEY --variable server=$OPENVASD_SERVER head.hurl --test
#HEAD /scans
hurl -k --cert $CLIENT_CERT --key $CLIENT_KEY --variable server=$OPENVASD_SERVER head_scans.hurl --test
hurl -k --variable server=$OPENVASD_SERVER head_scans_unauthorized.hurl --test
hurl -k --variable server=$OPENVASD_SERVER head_notus.hurl --test
hurl -k --variable server=$OPENVASD_SERVER head_vts.hurl --test
hurl -k --variable server=$OPENVASD_SERVER head_health_alive.hurl --test

#POST /scans
# scan_id=$(hurl -k --cert $CLIENT_CERT --key $CLIENT_KEY --variable server=$OPENVASD_SERVER post_scan.hurl --test)
scan_id=$(hurl -k --cert $CLIENT_CERT --key $CLIENT_KEY --variable server=$OPENVASD_SERVER post_scan.hurl)
echo "scan_id=$scan_id" > hurl_variables

#GET /scans/preferences
hurl -k --cert $CLIENT_CERT --key $CLIENT_KEY --variable server=$OPENVASD_SERVER get_scans_preferences.hurl --test
#GET /scans/{id}
hurl -k --cert $CLIENT_CERT --key $CLIENT_KEY --variable server=$OPENVASD_SERVER --variables-file config.env --variables-file hurl_variables get_scans_id.hurl --test
#POST /scans/{id}
hurl -k --cert $CLIENT_CERT --key $CLIENT_KEY --variable server=$OPENVASD_SERVER --variables-file hurl_variables start_scan.hurl --test

# run until it finishes or fails

status=$(hurl -k --cert $CLIENT_CERT --key $CLIENT_KEY --variable server=$OPENVASD_SERVER get_status.hurl --variables-file hurl_variables |jq  -r ".status")
while [[ "$status" != "succeeded" && "$status" != "stopped" && "$status" && "failed" ]]; do
    status=$(hurl -k --cert $CLIENT_CERT --key $CLIENT_KEY --variable server=$OPENVASD_SERVER  get_status.hurl --variables-file hurl_variables |jq -r ".status")
done

#GET /scans/{id}/results
hurl -k --cert $CLIENT_CERT --key $CLIENT_KEY --variable server=$OPENVASD_SERVER --variables-file config.env --variables-file hurl_variables --variable currentDate="$(date '+%a %b %d')" get_results.hurl --test
#GET /scans/{id}/results/{rid}
hurl -k --cert $CLIENT_CERT --key $CLIENT_KEY --variable server=$OPENVASD_SERVER --variables-file config.env --variables-file hurl_variables get_scans_id_results_rid.hurl --test
#GET /scans/{id}/status
hurl -k --cert $CLIENT_CERT --key $CLIENT_KEY --variable server=$OPENVASD_SERVER --variables-file config.env --variables-file hurl_variables get_status_assert.hurl get_status.hurl --test
#GET /vts
hurl -k --cert $CLIENT_CERT --key $CLIENT_KEY --variable server=$OPENVASD_SERVER get_vts.hurl --test
#DELETE /scans{id}
hurl -k --cert $CLIENT_CERT --key $CLIENT_KEY --variable server=$OPENVASD_SERVER --variables-file hurl_variables delete.hurl --test

#GET /health/alive
hurl -k --cert $CLIENT_CERT --key $CLIENT_KEY --variable server=$OPENVASD_SERVER get_health_alive.hurl --test
#GET /health/ready
hurl -k --cert $CLIENT_CERT --key $CLIENT_KEY --variable server=$OPENVASD_SERVER get_health_ready.hurl --test
#GET /health/started
hurl -k --cert $CLIENT_CERT --key $CLIENT_KEY --variable server=$OPENVASD_SERVER get_health_started.hurl --test

#GET /notus
hurl -k --cert $CLIENT_CERT --key $CLIENT_KEY --variable server=$OPENVASD_SERVER get_notus.hurl --test
#POST /notus/debian_10


#Post, Start and Stop and delete scan
scan_id=$(hurl -k --cert $CLIENT_CERT --key $CLIENT_KEY --variable server=$OPENVASD_SERVER post_scan.hurl)
echo "scan_id=$scan_id" > hurl_variables
hurl -k --cert $CLIENT_CERT --key $CLIENT_KEY --variable server=$OPENVASD_SERVER --variables-file hurl_variables start_scan.hurl --test
hurl -k --cert $CLIENT_CERT --key $CLIENT_KEY --variable server=$OPENVASD_SERVER --variables-file hurl_variables stop_scan.hurl --test
hurl -k --cert $CLIENT_CERT --key $CLIENT_KEY --variable server=$OPENVASD_SERVER --variables-file hurl_variables delete.hurl --test

#Delete a running scan
scan_id=$(hurl -k --cert $CLIENT_CERT --key $CLIENT_KEY --variable server=$OPENVASD_SERVER post_scan.hurl)
echo "scan_id=$scan_id" > hurl_variables
hurl -k --cert $CLIENT_CERT --key $CLIENT_KEY --variable server=$OPENVASD_SERVER --variables-file hurl_variables start_scan.hurl --test
hurl -k --cert $CLIENT_CERT --key $CLIENT_KEY --variable server=$OPENVASD_SERVER --variables-file hurl_variables delete.hurl --test
