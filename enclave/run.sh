#!/bin/sh
# Enclave init/entrypoint script, adapted from
# suiverify/nautilus-attestation-backend/src/attestation-backend/run.sh.
#
# Sets up loopback networking, bridges inbound VSOCK traffic to the plain
# TCP server the Rust binary binds (see enclave/src/vsock/listener.rs), and
# opens the outbound socat tunnels the Rust binary reaches by hostname over
# HTTPS (see enclave/src/services/http.rs). All VSOCK<->TCP bridging lives
# here in shell, not in Rust.
#
# TLS terminates *inside* the enclave. Each upstream hostname resolves to its
# own loopback alias via /etc/hosts, socat listens there on :443, and the
# bytes it forwards are already encrypted -- the host pipes a stream it
# cannot read, and the certificate is checked in here against the real name.
# Letting the host terminate TLS would hand the operator every client secret
# and refresh token in plaintext.

set -e

export LD_LIBRARY_PATH=/lib:$LD_LIBRARY_PATH

busybox ip addr add 127.0.0.1/32 dev lo
busybox ip link set dev lo up
echo "127.0.0.1 localhost" > /etc/hosts
echo "127.0.0.1 3" >> /etc/hosts

# One loopback alias per upstream, since they all need to listen on :443.
# Must stay in sync with the Upstream constants in services/http.rs.
for alias in 127.0.0.2 127.0.0.3 127.0.0.4 127.0.0.5; do
    busybox ip addr add "$alias/32" dev lo
done
echo "127.0.0.2 www.googleapis.com"    >> /etc/hosts
echo "127.0.0.3 api.github.com"        >> /etc/hosts
echo "127.0.0.4 oauth2.googleapis.com" >> /etc/hosts
echo "127.0.0.5 github.com"            >> /etc/hosts

if [ -f "/enclave.env" ]; then
    set -a
    . /enclave.env
    set +a
fi

export ENCLAVE_MODE=nitro

# Outbound tunnels: enclave -> host (CID 3) -> internet.
# Each listener is bound to the loopback alias its hostname resolves to, so
# the enclave can dial four different upstreams that all expect :443.
echo "Setting up outbound VSOCK tunnels..."
socat TCP-LISTEN:443,bind=127.0.0.2,reuseaddr,fork VSOCK-CONNECT:3:8002 &  # www.googleapis.com
socat TCP-LISTEN:443,bind=127.0.0.3,reuseaddr,fork VSOCK-CONNECT:3:8003 &  # api.github.com
socat TCP-LISTEN:443,bind=127.0.0.4,reuseaddr,fork VSOCK-CONNECT:3:8006 &  # oauth2.googleapis.com
socat TCP-LISTEN:443,bind=127.0.0.5,reuseaddr,fork VSOCK-CONNECT:3:8007 &  # github.com
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
