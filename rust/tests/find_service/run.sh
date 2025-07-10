#!/usr/bin/env bash
set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Get the rust directory (two levels up from the script)
RUST_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
# Test directory is where this script is located
TEST_DIR="$SCRIPT_DIR"

echo "Script directory: $SCRIPT_DIR"
echo "Rust directory: $RUST_DIR"

# Change to rust directory for cargo commands
cd "$RUST_DIR"

echo "Building Docker container..."
docker build -t openvas-find-service-test "$TEST_DIR/"

echo "Starting Docker container..."
CONTAINER_ID=$(docker run -d --rm -v "$TEST_DIR:/workspace" openvas-find-service-test /bin/bash -c "
service mysql start
service apache2 start  
service ssh start
service vsftpd start
service dovecot start
service postfix start
service xinetd start
/usr/local/bin/netbus-sim.sh &
sleep infinity
")

echo "Waiting for services to start..."
sleep 10

CONTAINER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER_ID")
echo "Container IP: $CONTAINER_IP"

echo "Running scannerctl with test script..."
cargo run --bin scannerctl execute script "$TEST_DIR/test_find_service.nasl" --target "$CONTAINER_IP"

# echo "Cleaning up..."
# docker stop "$CONTAINER_ID"
