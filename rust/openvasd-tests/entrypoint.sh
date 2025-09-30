#!/usr/bin/env bash
set -e

OPENVASD_PATH=/opt/openvasd_target/debug/openvasd

redis-server --daemonize yes --bind 127.0.0.1 --port 6379

until redis-cli ping > /dev/null 2>&1; do
    echo "Waiting for Redis..."
    sleep 1
done

export API_KEY=${API_KEY:-changeme}

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

[storage.redis]
url = "127.0.0.1:6379"

[listener]
address = "0.0.0.0:3000"

[endpoints]
enable_get_scans = true
key = "${API_KEY:-changeme}"
EOF

# Start openvasd
exec $OPENVASD_PATH --config /etc/openvas/openvasd.toml
