#!/bin/sh

../target/release/container-scanning  --notus-address http://localhost:6969/notus -c local-logging.conf -d example.db > container-image-scanner.log & 
echo $! > container-image-scanner.pid; 
echo "container-image-scanner started with PID:" $(cat container-image-scanner.pid)
