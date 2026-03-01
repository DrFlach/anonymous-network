#!/bin/bash
# Kill any existing anon-router process
pkill -9 -f "anon-router" 2>/dev/null
sleep 1

# Remove stale config to pick up new defaults
rm -f config.json

# Build
cd /home/DrFlachAdmin/Desktop/anonymous-network
go build -o anon-router ./cmd/router/
if [ $? -ne 0 ]; then
    echo "BUILD FAILED"
    exit 1
fi
echo "Build successful"

# Run
exec ./anon-router -debug
