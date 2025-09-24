#!/bin/sh

../../target/release/openvasd  -c local-logging.conf > container-image-scanner.log & 
echo $! > container-image-scanner.pid; 
echo "container-image-scanner started with PID:" $(cat container-image-scanner.pid)
