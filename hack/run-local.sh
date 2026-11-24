#!/usr/bin/env bash
# Runs autopeer locally the way a peer sees it: the fake login provider
# (hack/fakeidp, log in as any ASN and mntner) on :8098 and autopeer with an
# in-memory peers repo on :8099, where PRs merge at once. Nothing reaches
# GitHub or a cluster, so there's no live BGP state. Ctrl-C stops both.
set -euo pipefail
cd "$(dirname "$0")/.."

work=$(mktemp -d)
cleanup() {
	kill $(jobs -p) 2>/dev/null || true
	wait 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT INT TERM

go build -o "$work/autopeer" ./cmd/autopeer
go build -o "$work/fakeidp" ./hack/fakeidp
head -c 32 /dev/urandom | base64 >"$work/cookie-key"
sed "s|@WORK@|$work|g" hack/run-local.yaml >"$work/config.yaml"

"$work/fakeidp" --listen 127.0.0.1:8098 --issuer http://localhost:8098 &
"$work/autopeer" --config "$work/config.yaml" --fake-repo &

echo
echo "autopeer: http://localhost:8099  (log in with the fake provider;"
echo "          add 4242423818 to your ASNs to be admin). Ctrl-C to stop."
echo
wait
