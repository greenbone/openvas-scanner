#!/usr/bin/env bash
set -e

PROFILE=${PROFILE:-release}
OPENVASD_PATH=/opt/openvasd_target/${PROFILE}/openvasd

mkdir -p /run/redis
redis-server /etc/redis/redis.conf

until redis-cli -s /run/redis/redis.sock ping > /dev/null 2>&1; do
    echo "Waiting for Redis..."
    sleep 1
done

export API_KEY=${API_KEY:-changeme}

# A small hack so simply copying the binary works even if
# the host system is NixOS. This doesn't have any effect
# for other systems.
if [ -f  $OPENVASD_PATH ]; then
    patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 $OPENVASD_PATH 2>/dev/null || true
    chmod +x $OPENVASD_PATH
else
    echo "ERROR: openvasd binary not found at $OPENVASD_PATH"
    exit 1
fi

cat > /etc/openvas/openvasd.toml << EOF
[scanner]
type = "${SCANNER_TYPE:-openvas}"

[storage]
type = "redis"

[listener]
address = "0.0.0.0:3000"

[endpoints]
enable_get_scans = true
key = "${API_KEY:-changeme}"
EOF

# Start openvasd
exec $OPENVASD_PATH --config /etc/openvas/openvasd.toml
