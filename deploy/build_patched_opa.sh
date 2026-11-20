#!/bin/sh
# Build exact OPA v1.22.4 source with patched golang.org/x/net.
# This script runs ONLY in the isolated Go builder container.
set -eu

git clone --depth 1 --branch v1.22.4 https://github.com/open-policy-agent/opa.git /tmp/opa-src
cd /tmp/opa-src
test "$(git rev-parse HEAD)" = "ba39415db4b3c90cd68942a74b3cc2223ec2b23c"

# Minimal module upgrade for CVE-2026-78661. Never edit an official binary.
GOTOOLCHAIN=local go get golang.org/x/net@v0.62.0
test "$(GOTOOLCHAIN=local go list -m -f '{{.Version}}' golang.org/x/net)" = "v0.62.0"

mkdir -p /out
CGO_ENABLED=0 GOTOOLCHAIN=local go build -trimpath -tags=opa_wasm -ldflags="-s -w" -o /out/opa .
/out/opa version
go version -m /out/opa | grep -E '[[:space:]]golang\.org/x/net[[:space:]]+v0\.62\.0([[:space:]]|$)'
