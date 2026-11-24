#!/usr/bin/env bash
# Multi-node k3s in Docker (one server, two router agents, each its own
# network namespace). Proves:
#   - a DaemonSet rolling update completes (followers are Ready)
#   - only the leader's pod is an endpoint of the Service, before and after
#   - only the leader's node has the tunnels
#   - failover when the leader's node disappears
# Needs Docker with privileged containers. Never touches a real cluster.
set -euo pipefail
cd "$(dirname "$0")/../.."
IMG=${IMG:-ghcr.io/oscrx/dn42-operator:dev}
BIRD_IMG=${BIRD_IMG:-dn42-bird:dev}
K3S=${K3S:-rancher/k3s:v1.34.1-k3s1}
NET=dn42-k3s
S=dn42-k3s-server A=dn42-k3s-a B=dn42-k3s-b

cleanup() { docker rm -f $S $A $B >/dev/null 2>&1 || true; docker network rm $NET >/dev/null 2>&1 || true; }
cleanup
[ -n "${KEEP:-}" ] || trap cleanup EXIT

K() { docker exec -i $S kubectl "$@"; }
log() { echo "[$(date +%T)] $*"; }
fail() { echo "FAIL: $*"; K -n dn42 get pods -o wide || true; K -n dn42 get lease dn42-operator -o yaml || true; exit 1; }
waitfor() { # waitfor <seconds> <description> <command...>
  local t=$1 d=$2; shift 2
  for _ in $(seq 1 "$t"); do if "$@" >/dev/null 2>&1; then return 0; fi; sleep 1; done
  fail "timed out after ${t}s: $d"
}

log "starting k3s"
docker network create $NET >/dev/null
docker run -d --privileged --name $S --hostname $S --network $NET -e K3S_TOKEN=dn42test \
  "$K3S" server --disable=traefik,metrics-server,servicelb,local-storage >/dev/null
waitfor 120 "api server" docker exec $S kubectl get --raw /readyz
for n in $A $B; do
  docker run -d --privileged --name $n --hostname $n --network $NET \
    -e K3S_URL=https://$S:6443 -e K3S_TOKEN=dn42test "$K3S" agent >/dev/null
done
for n in $A $B; do waitfor 120 "node $n" sh -c "docker exec $S kubectl get node $n -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}' | grep -q True"; done

log "importing images"
for n in $A $B; do
  docker save "$IMG" | docker exec -i $n ctr -n k8s.io images import - >/dev/null
  docker save "$BIRD_IMG" | docker exec -i $n ctr -n k8s.io images import - >/dev/null
done
K label node $A $B dn42.oscarr.nl/router=true >/dev/null

log "deploying the chart"
K create namespace dn42 >/dev/null
K label namespace dn42 pod-security.kubernetes.io/enforce=privileged >/dev/null
K -n dn42 create secret generic dn42-wireguard-keys \
  --from-literal=autopeer="$(docker run --rm --entrypoint sh "$BIRD_IMG" -c 'head -c32 /dev/urandom | base64')" >/dev/null
# helm runs here, not in the cluster: the test renders the chart exactly as
# ArgoCD does (helm template, CRDs included) and applies the result.
helm template dn42 charts/dn42-operator --namespace dn42 --include-crds \
  -f test/k3s/values.yaml \
  --set operator.image.repository="${IMG%:*}" --set operator.image.tag="${IMG##*:}" \
  --set bird.image.repository="${BIRD_IMG%:*}" --set bird.image.tag="${BIRD_IMG##*:}" \
  | K apply -f - >/dev/null
K wait --for=condition=Established crd/dn42peers.dn42.oscarr.nl >/dev/null
K apply -f - < test/k3s/extra.yaml >/dev/null

leader() { K -n dn42 get lease dn42-operator -o jsonpath='{.spec.holderIdentity}' 2>/dev/null; }
endpoints() { # ready endpoints of the Service as node names
  K -n dn42 get endpointslices -l kubernetes.io/service-name=dn42-endpoint \
    -o jsonpath='{range .items[*].endpoints[*]}{.nodeName}={.conditions.ready}{"\n"}{end}' | grep '=true' | cut -d= -f1 | sort | tr '\n' ' '
}
links() { docker exec "$1" ip link show 2>/dev/null | grep -o 'wg-[a-z0-9]*' | sort | tr '\n' ' '; }
# consistent [node...]: exactly one leader, it is the only endpoint and the
# only node with tunnels; the other given nodes have none.
consistent() {
  local l; l=$(leader); [ -n "$l" ] || return 1
  [ "$(endpoints)" = "$l " ] || return 1
  [ "$(links "$l")" = "wg-aa wg-bb " ] || return 1
  for n in "$@"; do [ "$n" = "$l" ] || [ -z "$(links "$n")" ] || return 1; done
}
report() { log "leader=$(leader) endpoints=[$(endpoints)] links: $A=[$(links $A)] $B=[$(links $B)]"; }

waitfor 180 "bird pods" sh -c "[ \"\$(docker exec $S kubectl -n dn42 get pods -l app.kubernetes.io/name=dn42-bird -o jsonpath='{range .items[*]}{.status.phase} {end}')\" = 'Running Running ' ]"
waitfor 180 "rollout" K -n dn42 rollout status ds/dn42-operator --timeout=5s
waitfor 60 "consistent state" consistent $A $B
report
ready=$(K -n dn42 get pods -l app.kubernetes.io/name=dn42-operator -o jsonpath='{range .items[*]}{.status.conditions[?(@.type=="Ready")].status}{" "}{end}')
[ "$ready" = "True True " ] || fail "both pods should be Ready (leader and follower): $ready"
log "OK: both pods Ready, only the leader is an endpoint"

birdpods() { K -n dn42 get pods -l app.kubernetes.io/name=dn42-bird -o jsonpath='{range .items[*]}{.metadata.uid}/{.status.containerStatuses[0].restartCount} {end}'; }
BIRD0=$(birdpods)
log "rolling update of the operator"
K -n dn42 rollout restart ds/dn42-operator >/dev/null
K -n dn42 rollout status ds/dn42-operator --timeout=180s || fail "rolling update stalled"
waitfor 60 "consistent state after rollout" consistent $A $B
report
[ "$(birdpods)" = "$BIRD0" ] || fail "BIRD pods were restarted by the operator rollout: $BIRD0 -> $(birdpods)"
log "OK: rolling update completed, BIRD not restarted"

log "bird.conf change: reconfigured, not restarted"
L=$(leader)
lastreconf() { K -n dn42 exec "$(K -n dn42 get pods -l app.kubernetes.io/name=dn42-bird --field-selector spec.nodeName=$L -o name)" -- \
  birdc -s /var/run/dn42-bird/bird.ctl show status | grep 'Last reconfiguration'; }
R0=$(lastreconf)
sleep 1
K -n dn42 get configmap dn42-bird-conf -o yaml | sed 's/scan time 2;/scan time 3;/' | K apply -f - >/dev/null
waitfor 150 "operator saw the bird.conf change" sh -c "docker exec $S kubectl -n dn42 logs -l app.kubernetes.io/name=dn42-operator --tail=-1 | grep -q 'bird.conf changed'"
[ "$(lastreconf)" != "$R0" ] || fail "BIRD was not reconfigured ($R0)"
docker exec "$L" grep -q 'scan time 3' /var/lib/dn42-router/conf/bird.conf || fail "shared bird.conf not updated"
[ "$(birdpods)" = "$BIRD0" ] || fail "BIRD restarted on a bird.conf change"
log "OK: bird.conf change applied without a BIRD restart"

L=$(leader); F=$A; [ "$L" = "$A" ] && F=$B
restarts() { K -n dn42 get pods -l app.kubernetes.io/name=dn42-operator --field-selector spec.nodeName=$1 \
  -o jsonpath='{.items[0].status.containerStatuses[?(@.name=="operator")].restartCount}'; }
podready() { K -n dn42 get pods -l app.kubernetes.io/name=dn42-operator --field-selector spec.nodeName=$1 \
  -o jsonpath='{.items[0].status.conditions[?(@.type=="Ready")].status}' | grep -q True; }
R0=$(restarts "$L")
log "failover: stopping leader node $L"
T0=$(date +%s)
docker stop -t 0 "$L" >/dev/null   # a hard node loss: no graceful teardown
waitfor 90 "failover to $F" consistent "$F"
log "OK: failover to $F after $(( $(date +%s) - T0 ))s"
report

log "bringing $L back"
docker start "$L" >/dev/null
waitfor 180 "operator on $L restarted" sh -c "[ \"\$(docker exec $S kubectl -n dn42 get pods -l app.kubernetes.io/name=dn42-operator --field-selector spec.nodeName=$L -o jsonpath='{.items[0].status.containerStatuses[?(@.name==\"operator\")].restartCount}')\" -gt $R0 ]"
waitfor 120 "$L pod Ready again" podready "$L"
waitfor 60 "consistent with both nodes" consistent $A $B
[ "$(leader)" = "$F" ] || fail "leadership moved back to $L"
report
log "OK: $L rejoined as follower"
echo PASS
