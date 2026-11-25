# dn42-operator

Kubernetes operator for a [DN42](https://dn42.dev) router. It turns `DN42Peer`
objects into WireGuard links and BIRD BGP sessions on the node it runs on, and
reports their state back on the objects.

It runs next to BIRD in a privileged host-network pod. The node keeps only
the static plumbing (the VRF, loopback dummies, uplink); the operator adds and
removes the per-peer tunnels.

## DN42Peer

```yaml
apiVersion: dn42.oscarr.nl/v1alpha1
kind: DN42Peer
metadata:
  name: iedon                  # wg-iedon, BIRD protocol peer_iedon
  namespace: dn42
spec:
  asn: 4242422189
  listenPort: 22189            # optional for 424242xxxx: 2 + last 4 digits
  endpoint: "[2001:bc8:1640:5bdb:dc00:ff:fe60:c2e3]:60887"   # optional; IPv6 only (host:port resolves AAAA)
  publicKey: 08dzv758I5APqJizgw/W6O+FceyHSCbx/L/GZ3TL5TQ=
  localLinkLocal: fe80::3818   # optional, default fe80::3818
  neighbor: fe80::2189:177
  link: {latency: 2, bandwidth: 24, crypto: 34}   # optional; else latency measured, bw 24, crypto 34
  keyRef: iedon                # optional: key in the key Secret; else the shared autopeer key
```

```
$ kubectl get dn42peers
NAME    ASN          PORT    VALID   STATE         HANDSHAKE   ROUTES   AGE
iedon   4242422189   22189   True    Established   47s         412      3d
neo     4201270001           False                                      1m
```

The CRD (`charts/dn42-operator/crds/`, generated) checks each object on its own: name
`^[a-z][a-z0-9]{0,11}$` (`wg-<name>` fits the 15-character interface limit),
ASN in a DN42 range (4242420000-4242429999, 4201000000-4201999999,
64512-65534, 76100-76199), `listenPort` 20000-29999, link-local
`neighbor`/`localLinkLocal`, a 32-byte base64 key, link values in the DN42
community ranges, and no unknown fields.

The operator repeats these checks (`internal/peer`, reusable by the autopeer
app and the CI gate) and adds the ones across objects. A peer that fails is
`Valid=False` and skipped. Whatever already exists for it stays as it is.

| Reason | When |
|---|---|
| `PortConflict` | the effective listen port is used by an older peer |
| `NeighborConflict` | ASN + neighbor is already an older peer |
| `ListenPortRequired` | no `listenPort` and the ASN isn't 424242xxxx, so "2 + last 4 digits" doesn't apply |
| `BIRDRejected` | BIRD's `configure check` refused the rendered snippet |

Of two conflicting peers, the newer one (by creation time) is invalid, so a
new peer can never break an existing one.

Other conditions: `TunnelReady` (link configured and a handshake within 3
minutes; reasons such as `KeyMissing`, `InterfaceConflict`, `VRFMissing`,
`NoHandshake`) and `SessionEstablished` (BIRD reports `Established`).

## What a pass does

Every change to a `DN42Peer` or the key Secret triggers a pass, plus a full
pass every 60s. Status and metrics are written every 30s.

1. **Tunnels**, on `wg-<name>` for each valid peer with a key: create the link
   with alias `managed-by=dn42-operator`, then set the private key, listen
   port, peer key, endpoint, allowed IPs `fe80::/10, fd00::/8` and a 25s
   keepalive. The link joins the VRF with `accept_ra=0` and
   `accept_redirects=0`, gets the link-local address and comes up. Only what
   differs is changed. The endpoint is left alone while the handshake is
   fresh, so a peer that roamed isn't pulled back.
2. **Cleanup**: links with the alias but no `DN42Peer` are deleted. Links
   without the alias (`dn42-lo`, the uplink, anything Talos made) are never
   touched. If a link `wg-<name>` exists without the alias, the peer reports
   `InterfaceConflict` and the link is left alone (the migration case).
3. **BIRD**: `<name>.conf` in the peers directory, rendered from typed fields
   only:

   ```
   protocol bgp peer_iedon from dnpeers {
     description "AS4242422189 iedon";
     neighbor fe80::2189:177 as 4242422189;
     interface "wg-iedon";
     ipv6 {
       import where dn42_import(2, 24, 34);
       export where dn42_export(2, 24, 34);
     };
   }
   ```

   New files are written, `configure check` runs, and only then `configure`.
   If the check fails, the new snippets are added back one at a time to find
   the bad one. That one is rolled back and marked `BIRDRejected`; the rest go
   through. The operator speaks the control socket protocol itself, so no
   `birdc` binary is needed.
4. **Latency** (only when `spec.link` is unset): once a day the leader sends
   10 pings over the underlay to where WireGuard currently sees the peer
   (the source of its last packets; for peers without `spec.endpoint` once
   they have connected), else to the configured endpoint. It maps the median RTT to the
   DN42 latency community: 1 ≤2.7ms, 2 ≤7.3ms, 3 ≤20ms, 4 ≤55ms, 5 ≤148ms,
   6 ≤403ms, 7 ≤1097ms, 8 ≤2981ms, else 9. The result goes to
   `status.measuredLatency`, `measuredRTT` and `latencyMeasuredAt`, and the
   next pass renders it. Until the first measurement (or the first
   connection of a peer without endpoint), and when the endpoint doesn't
   answer (at least 5 of 10 replies are needed; retried hourly), the
   default 5 is used. `kubectl get dn42peers -o wide` shows the effective
   latency.
   **Transit** (with `--transit-probe-source`): see [Transit probe](#transit-probe).
5. **Service**: `spec.ports` of the endpoint Service (one UDP port `wg-<name>`
   per tunnel), via server-side apply with field manager `dn42-operator`.

### Safety rules

- If the peers, the Secret or the links can't be listed, the pass stops and
  changes nothing. An API outage is never read as "no peers".
- **Mass deletion guard**: a pass that would delete more than one link and
  more than `--max-delete-fraction` (default 0.5) of the managed links deletes
  nothing. It logs an error and sets `dn42_operator_deletions_blocked`. To
  confirm, set `confirmDeletions: "<count>"` in the ConfigMap
  `dn42-operator-control`. It must equal the number of pending deletions, and
  the next pass then goes ahead. Remove the key afterwards.
- BIRD is reconfigured, never restarted, by the operator: peer changes and
  bird.conf changes both go through `configure check` and `configure`.
- Nothing free-form reaches BIRD: names match a strict pattern, and the ASN,
  link values and neighbor address are an integer, integers and a
  `netip.Addr`. BIRD protocols are named `peer_<name>`, so a peer name can't
  collide with a BIRD keyword. **bird.conf must not define symbols starting
  with `peer_`.**

## Running it

The Helm chart `charts/dn42-operator` (published as
`oci://ghcr.io/oscrx/charts/dn42-operator`, signed) installs, in its
release namespace:

- the `DN42Peer` CRD (`crds/`, generated by `make generate`);
- RBAC: a namespaced Role to read/watch `DN42Peer`, write its status, read
  the one key Secret, read the control ConfigMap, patch the endpoint Service
  (only if `operator.endpointService` is set), get/list/patch pods (the
  leader label; pod names are generated, so no resourceNames), and the
  Lease. Nothing cluster-wide.
- two DaemonSets on nodes matching `nodeSelector` (default
  `dn42.oscarr.nl/router=true`), host network, privileged. BIRD and the
  operator are separate so an operator update never restarts BIRD;
  `dn42-bird` uses `OnDelete`. They share `/var/run/dn42-bird` (socket),
  `/var/lib/dn42-router/peers` (snippets) and `/var/lib/dn42-router/conf`
  (the live bird.conf) on the host (`hostPaths`).

You provide the namespace (PodSecurity `privileged`), the key Secret
(`operator.keySecret`), and bird.conf as a fixed-name ConfigMap
(`bird.config.configMapName`, or `bird.config.create` with `content`).
bird.conf must define the `dnpeers` template and include
`/etc/bird/peers/*.conf`; the operator `configure`s BIRD when it changes,
after `configure check`. With a standby node, set
`operator.cleanupOnShutdown` and `operator.teardownOnLeaseLoss` to true (off
by default, which suits a single router).
See `values.yaml` for the rest.

`images/bird/Dockerfile` is the BIRD image (`make bird-image`), built from
the upstream source at a pinned tag and commit; the integration tests run on
it too. It is published as `ghcr.io/oscrx/bird2:<BIRD version>`, and the
chart pins it by tag and digest.

`deploy/` keeps examples for what the chart doesn't install: the floating
LoadBalancer endpoint (`service-endpoint.yaml`, `externalTrafficPolicy:
Local`; keep a placeholder port in git and tell ArgoCD to ignore
`spec.ports`), autopeer, and a peer.

The key Secret (`--key-secret`, default `dn42-wireguard-keys`) holds base64
WireGuard private keys. The data key `autopeer` (`--shared-key`) is for peers
without `keyRef`.

### Leader election

Every router node runs the pod. A Lease (`dn42-operator`, identity = node
name) picks the active one, and the operator labels its own pod
`dn42.oscarr.nl/leader=true|false`. The endpoint Service selects
`dn42.oscarr.nl/leader: "true"`, so with `externalTrafficPolicy: Local` the
LB address is announced only from the leader's node.

- **leader**: builds everything, sets its label to `true` and clears the
  label on any other pod still marked leader (one that lost the lease without
  reaching the API).
- **follower** (the lease is held by someone else): removes all managed links
  and peer snippets, so BIRD has only its static config, and sets its label to
  `false`.
- **just started**, lease not seen yet: changes nothing. A restarted leader
  takes its own lease back immediately (same identity), so a restart doesn't
  flap the tunnels.
- **losing the lease** (`--teardown-on-lease-loss`, default on): the pass in
  progress is cancelled and links are removed **before** the lease is
  released (the lock is wrapped so client-go's release waits). Off, on a
  single router: an API outage stops changes but keeps the tunnels, and links
  only go once another holder is seen.
- **on shutdown** (`--cleanup-on-shutdown`, default on): links are removed,
  then the lease is released, so a key is never live on two nodes. Off, on a
  single router, an operator restart doesn't flap any session.
- **standing down**: `standDown: "true"` in the control ConfigMap makes the
  leader remove everything and report not ready until the key is gone
  (rollback, maintenance).

`/readyz` means healthy in the current role: the last pass worked and the
API server accepted the label that matches the role. Followers are Ready too,
so DaemonSet rolling updates proceed. If the label can't be written, the pod
is not Ready, so it never sits in the Service with a label that doesn't match
its role. Without `POD_NAME` there is no label; readiness is then just
"healthy", and the Service must not select on the label.

`make k3s-test` proves this on a throwaway three-node k3s in Docker (server
plus two router agents):

- a rolling update completes
- only the leader is an endpoint and has tunnels
- after a hard stop of the leader's node, the other node takes over (about
  20s: lease expiry plus probes)
- the returning node comes back as a follower

### Flags

`--namespace` (`POD_NAMESPACE`), `--identity` (`NODE_NAME`), `--vrf`
(`vrf-dn42`, must exist; it is never created), `--bird-socket`,
`--peers-dir`, `--bird-template` (`dnpeers`), `--endpoint-service`,
`--control-configmap`, `--max-delete-fraction`, `--pod-name` (`POD_NAME`),
`--leader-label`, `--metrics-bind-address`
(`:9842`), `--health-probe-bind-address` (`:9843`). The pod uses the host
network, so pick free ports. Transit probe: `--transit-probe-source`,
`--transit-targets`, `--transit-table` (`4243`), `--transit-mark`
(`0x420000`), `--transit-rule-priority` (`80`), `--bird-transit-arg`.

### Transit probe

Some peers run a stateful firewall that drops our packets of a connection
whose replies it never sees. When BIRD sends traffic out through such a peer
and the far end replies via another one, the TCP handshake passes but our
ACK and data are dropped: connections stall for seconds or hang. Pings, BFD
and the BGP session over the link all look fine.

With `--transit-probe-source` set to one of our addresses in the VRF (the
router's address on `dn42-lo`), the leader connects to a few TCP services
(`--transit-targets`; default the anycast resolver `fd42:d42:d42:53::1:53`
and wiki `fd42:d42:d42:80::1:80`) through each established peer that has a
route to them, and compares that with the same targets over our normal
routes. The connections are forced through the peer with a routing table of
their own (`--transit-table`, holding /128 routes via the peer's link and an
unreachable default) and an `ip rule` for their fwmark
(`--transit-mark`, priority `--transit-rule-priority`, ahead of the VRF's
l3mdev rule). The mark is set before connect, so the SYN goes through the
peer too: a firewall that never sees a connection start lets the rest
through and would hide the problem. Nothing else carries the mark, so real
traffic is untouched. Replies come back however the far end routes to us.

A target counts as broken when the probe through the peer connects but gets
no answer within 1.5 s (or doesn't connect), while the control answers; one
broken target makes the probe `Broken`. The verdict changes only after two
probes in a row agree: re-probed after 5 minutes when a probe disagrees,
hourly while broken or inconclusive, daily while healthy. It is kept in
`status.transit` (`healthy`, `lastResult`, `message`, `probedAt`) and shown
as the `TransitHealthy` condition (`Unknown` until confirmed; reason
`Confirming` while a change awaits its second probe) and the
`dn42_peer_transit_healthy` metric:

    kubectl get dn42peer baragoon -o jsonpath='{.status.transit}'

With `--bird-transit-arg` the import calls
`dn42_import_transit(latency, bandwidth, crypto, transit_ok)` instead of
`dn42_import(latency, bandwidth, crypto)`; unknown counts as ok. bird.conf
decides what to do with it, for example demoting routes that only use the
peer for transit:

    function dn42_import_transit(int link_latency; int link_bandwidth; int link_crypto; bool transit_ok) -> bool
    {
      if !dn42_import(link_latency, link_bandwidth, link_crypto) then return false;
      if !transit_ok && bgp_path.len > 1 then bgp_local_pref = 10;
      return true;
    }

Roll it out in two steps: first add the function to bird.conf, then turn on
`--bird-transit-arg`. It is a separate function rather than a fourth
`dn42_import` argument because BIRD checks a new bird.conf against the
current snippets and new snippets against the current bird.conf; a changed
signature would fail both checks.

### Metrics

`dn42_operator_leader`, `dn42_operator_passes_total`,
`dn42_operator_pass_errors_total{stage}`,
`dn42_operator_link_changes_total{op}`, `dn42_operator_deletions_blocked`,
`dn42_operator_bird_up`, and per peer (`peer`, `asn` labels):
`dn42_peer_valid`, `dn42_peer_tunnel_ready`,
`dn42_peer_handshake_age_seconds`, `dn42_peer_bgp_established`,
`dn42_peer_routes_imported`, `dn42_peer_endpoint_rtt_seconds`,
`dn42_peer_transit_healthy`.

## Development

```
make generate     # deepcopy + CRD (controller-gen)
make verify       # toolchain, generated code, vet, lint, tests
make test         # unit tests with -race, any OS
make integration  # Linux tests in a privileged container, on the BIRD image
make k3s-test     # rolling update + failover on a 3-node k3s in Docker
make image
```

The integration tests (`-tags integration`, `test/integration.Dockerfile`)
build a real `vrf-dn42`, WireGuard links and BIRD in the container. A second
network namespace plays the peer, with its own WireGuard link and BIRD. They
check:

- the handshake, and BGP `Established` over link-local inside the VRF
- create, change and delete
- a snippet BIRD rejects
- an API outage
- follower teardown
- links without the alias surviving

They need `--privileged` and must not run on a host.

## autopeer

`cmd/autopeer` is the web front end. It has its own image,
`ghcr.io/oscrx/dn42-autopeer`: distroless nonroot, with only the autopeer
binary in it. It is the one public-facing part, so it runs with the least
privilege: its own namespace with PodSecurity `restricted`, and read-only
access to `dn42peers` in the router's namespace for the status page. It never
writes to the cluster; changes go out as PRs.

The Helm chart `charts/dn42-autopeer` (`oci://ghcr.io/oscrx/charts/dn42-autopeer`,
signed) installs the Deployment, its Service and ConfigMap, and the read-only Role in
`peersNamespace`. The config is `config:` in the values, rendered as-is; see
`deploy/autopeer-config.example.yaml`. Secrets come from `existingSecret`,
mounted at `/secrets`. Routing (Gateway/Ingress, certificates) is left to
you, or to `extraObjects`.

The flow:

1. **Login** with one of the configured providers. Each one is a generic
   OAuth 2.0 / OpenID Connect client: Authorization Code with PKCE (S256)
   always, and nonce plus ID-token verification when `issuer` is set (OIDC
   discovery). Without `issuer`, it uses `authURL`/`tokenURL`/`userinfoURL`
   (plain OAuth, identity from userinfo).
2. **Ownership**: `claims.asn` names the claim with the ASNs the login may
   manage. Dotted paths, numbers, `AS…` strings and lists all work. The
   provider vouches for them: autopeer keeps no registry of its own (the
   peers repo's gate checks each ASN has an aut-num object). No accounts: the login lives in an AES-GCM encrypted cookie. It ends
   after `sessionTTL` (1h) without activity, since every page view renews
   it, and `sessionMaxAge` (12h) after logging in however active. A session
   can't be revoked on its own: rotating `cookieKeyFile` logs everyone out.
3. **Form**: ASN (from the login), name (suggested from the login's name
   claim, e.g. its mntner), WireGuard public key, optional IPv6 endpoint, link-local address
   (suggested as `fe80::<last 4 digits of the ASN>`), optional MTU. These
   are checked with the same code as the
   operator, against the peers already in the repo: name, port, ASN +
   neighbor, and not our own link-local address. `listenPort` is always
   written explicitly: 2 + the last 4 digits if that's free, otherwise the
   highest free port. Peers use the shared autopeer key (no `keyRef`).
4. **PR**: `peers/<asn>-<name>.yaml` on a new branch in the peers repo,
   through a GitHub App (JWT → installation token → branch, file, PR). The
   page shows the WireGuard and BIRD config for the peer's side.
5. **Status**: the home page lists the login's peers from the repo, plus
   new ones still in an open PR. It shows live state (BGP state, handshake,
   routes, Valid) from the cluster when `kubernetes.enabled`. Each peering
   has a page with its details and the peer's config, our key taken from
   `status.publicKey` (the shared key until it is live), and with
   `lookingGlass` set, links to the session, its routes and the ASN's whois
   in a bird-lg-go looking glass.
6. **Edit and removal**: every peering of an ASN you may manage gets Edit
   and Remove buttons. Edit changes only the peer's own fields (public key,
   endpoint, link-local address), keeping name, ASN, our port, link values
   and `keyRef` (a peer's own key on our side, instead of the shared one),
   and opens a PR updating the file. Remove opens a PR deleting it.
7. **Admin** (`admin.enabled`): a login that shows the router's own ASN,
   through one of `admin.providers`, may manage the peerings of every DN42
   ASN, with the same PRs. Peering with the router's own ASN is refused for
   everyone.

Peers in open PRs count as taken: a second request can't reuse their name,
port or ASN + neighbor while the first is in review, and a peer with an
open PR can't be removed. One deployment serves several hosts
(`extraPublicURLs`). A login's redirect URI is the configured base matching
the request's host, so a forged `Host` header can't send it elsewhere.
Submissions and removals are rate limited per login and in total
(`limits`, in memory).

To try it as a peer would, `make run-local` starts autopeer on
http://localhost:8099 with a fake login provider (`hack/fakeidp`: log in as
any ASNs and mntner; add the router's ASN to be admin) and `--fake-repo`, an
in-memory peers repo where PRs merge at once. Nothing reaches GitHub or a
cluster, so there is no live BGP state. The tests run the full
flow against a fake OIDC/OAuth provider that enforces PKCE and nonce, and the
GitHub App client against a fake GitHub API.

### Before go-live

Verified with real logins on 2026-11-24, on both hosts
(`autopeer.dn42.oscarr.nl`, and `autopeer.oscrx.dn42` inside DN42):

- **Kioubit** (AS4242423914): OIDC, public client with PKCE; ASNs in
  `dn42.asn`, mntner in `dn42.effective_mnt`.
- **OAuth.dn42 / iEdon** (`auth.iedon.net`, and `oauth.dn42` for the .dn42
  host): OIDC, confidential client; ASNs in `dn42.asn`, mntner in
  `dn42.active_mnt`.
- **HExpNetwork WebAuth** (AS4242420298): OIDC (the same Auth42 software as
  OAuth.dn42), public client; same claims.

The claims carry the ASNs the login's mntner may manage (`mnt-by` in the
registry), which is what autopeer checks. Burble's "Auth42" is not a
separate provider: it's the software behind OAuth.dn42 and HExpNetwork
WebAuth.

Still to do before announcing it widely: one peering added and edited by
someone else than the router's owner. Every real login so far was an admin
(our own ASN), so the normal-user path (only your own ASNs, the PR waiting
for the peers repo check, the merge, the tunnel coming up) has only run in
the tests and `make run-local`.

## peercheck (CI gate for the peers repo)

`cmd/peercheck` is the gate the peers repo (`oscrx/dn42-peers`) runs on
every PR and push. It reuses `internal/peer`, so the operator, autopeer and
CI share one definition of a valid peer. Its checks:

- **Every file**: one YAML document, a strict schema (no unknown fields, no
  `status`, no metadata besides `name`/`namespace`), the right
  kind/apiVersion, a namespace of `dn42` or none, the
  `peers/<asn>-<name>.yaml` name matching the object, and the spec
  validation.
- **Registry**: the ASN has an aut-num object, from a registry clone
  (`--registry-dir`) or a cached list (`--asn-list`).
- **Across files**: no duplicate name, port or ASN + neighbor; a conflict is
  reported on the file the PR touches.
- **PR rules**:
  - The App (`--app-login`) may only touch `peers/` and may not set or
    change `keyRef` (deleting a peer that has one is fine). Breaking either
    fails the check.
  - `--local-asn`: a peer with the router's own ASN fails the check.
  - Human PRs pass but are not auto-mergeable.
  - Auto-merge needs an App PR that changes exactly one peer file.

Trees are read from git objects, not the worktree (`--worktree` is for
local runs). Under Actions it writes `auto-mergeable=` to `$GITHUB_OUTPUT`
and emits error annotations. The fixtures are in
`internal/peercheck/testdata/cases/<case>/`: the head tree, the base
versions and `case.yaml` with the diff, author and expected outcome.

## Not done yet

- autopeer: a first peering by someone else (see "Before go-live").

## CI and releases

Same conventions as tlsa-dnsendpoint-controller; see
[.github/PIPELINE.md](.github/PIPELINE.md).

- `ci.yaml`, on every push and PR:
  - tests with `-race`, and checks for tidy modules, gofmt, current generated code and the toolchain
  - golangci-lint, a zizmor audit of the workflows
  - multi-arch builds of all three images
  - the Renovate validator and kubeconform
  - the privileged integration tests
  - the k3s test (on main)
- `release.yaml`, on a `v*` tag:
  - tests first, without any cache
  - signed images: `ghcr.io/oscrx/dn42-operator` and `dn42-autopeer`
  - then the GitHub release
- `bird-image.yaml`, when `images/bird/` changes on main: integration tests,
  then `ghcr.io/oscrx/bird2` tagged with the BIRD version (`2.20.0`, `2.20`,
  `2.20.0-<commit>`), signed
- Actions and base images are pinned by digest. Renovate keeps them current
  and automerges digests and minor bumps once CI is green. Kubernetes minors
  and BIRD releases are reviewed by hand. BIRD stays on 2.x; a patch and a
  newer minor come as separate PRs.

`make verify` runs the test and lint jobs locally; `make help` lists the
rest.

## License

MIT, see [LICENSE](LICENSE).

## More nodes

The design for a second DN42 node (`DN42Node`, internal tunnels, iBGP,
local_pref across nodes, no internal leaks to DN42) is in
[docs/ibgp.md](docs/ibgp.md). Not built yet; v0.1 is one node.
