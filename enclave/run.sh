#!/bin/sh
# Enclave init/entrypoint script, adapted from
# suiverify/nautilus-attestation-backend/src/attestation-backend/run.sh.
#
# Sets up loopback networking, bridges inbound VSOCK traffic to the plain
# TCP server the Rust binary binds (see enclave/src/vsock/listener.rs), and
# opens the outbound socat tunnels the Rust binary's oauth/http services
# dial as plain localhost HTTP (see enclave/src/services/http.rs). All
# VSOCK<->TCP bridging lives here in shell, not in Rust.

set -e

export LD_LIBRARY_PATH=/lib:$LD_LIBRARY_PATH

busybox ip addr add 127.0.0.1/32 dev lo
busybox ip link set dev lo up
echo "127.0.0.1 localhost" > /etc/hosts
echo "127.0.0.1 3" >> /etc/hosts

if [ -f "/enclave.env" ]; then
    set -a
    . /enclave.env
    set +a
fi

export ENCLAVE_MODE=nitro

# Outbound tunnels: enclave -> host (CID 3) -> internet.
# Enclave code just calls localhost:<port> over plain HTTP; parent_forwarder.sh
# on the host bridges each of these onward to the real service.
echo "Setting up outbound VSOCK tunnels..."
socat TCP-LISTEN:8002,reuseaddr,fork VSOCK-CONNECT:3:8002 &   # Google OAuth
socat TCP-LISTEN:8003,reuseaddr,fork VSOCK-CONNECT:3:8003 &   # GitHub API
socat TCP-LISTEN:8004,reuseaddr,fork VSOCK-CONNECT:3:8004 &   # Walrus publisher/aggregator
socat TCP-LISTEN:8005,reuseaddr,fork VSOCK-CONNECT:3:8005 &   # Walrus Memory relayer

# Inbound: gateway -> host -> VSOCK -> here -> localhost:4000 (the enclave binary).
echo "Bridging inbound VSOCK port 4000 -> localhost:4000..."
socat VSOCK-LISTEN:4000,reuseaddr,fork TCP:localhost:4000 &

echo "Starting memorai enclave on port 4000..."
/enclave > /tmp/server.log 2>&1 &
ENCLAVE_PID=$!

# Log shipping: tail is resilient to VSOCK drops independently of the server.
(tail -f /tmp/server.log 2>/dev/null | socat - VSOCK-CONNECT:3:5000 2>/dev/null) &

wait $ENCLAVE_PID
