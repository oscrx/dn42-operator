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
  endpoint: "[2001:bc8:1640:5bdb:dc00:ff:fe60:c2e3]:60887"   # optional; host:port also works
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

The CRD (`config/crd/`) checks each object on its own: name
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
   10 pings to the endpoint over the underlay. It maps the median RTT to the
   DN42 latency community: 1 ≤2.7ms, 2 ≤7.3ms, 3 ≤20ms, 4 ≤55ms, 5 ≤148ms,
   6 ≤403ms, 7 ≤1097ms, 8 ≤2981ms, else 9. The result goes to
   `status.measuredLatency`, `measuredRTT` and `latencyMeasuredAt`, and the
   next pass renders it. Until the first measurement, and when the endpoint
   doesn't answer (at least 5 of 10 replies are needed; retried hourly), the
   default 5 is used. `kubectl get dn42peers -o wide` shows the effective
   latency.
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

`deploy/` has example manifests (the real ones live elsewhere):

- `namespace.yaml`: the namespace with `pod-security.kubernetes.io/enforce: privileged`.
- `rbac.yaml`: read/watch `DN42Peer`, write its status, read the one key
  Secret, patch the one Service, read the control ConfigMap, get/list/patch
  pods (the leader label; pod names are generated, so no resourceNames), and
  the Lease.
- `router.yaml`: two DaemonSets on nodes labelled `dn42.oscarr.nl/router=true`,
  host network, privileged. BIRD and the operator are separate pods so an
  operator update never restarts BIRD; `dn42-bird` uses `OnDelete`. They
  share `/var/run/bird` (socket) and `/var/lib/dn42-router/peers` (snippets)
  on the host. bird.conf is a fixed-name ConfigMap mounted as a directory,
  and `--bird-config` makes the operator `configure` BIRD when it changes.
  Earlier layout, for reference: one pod with two containers:
  - `bird`, with a static `bird.conf` that includes `/etc/bird/peers/*.conf`
    and defines the `dnpeers` template and `dn42_import`/`dn42_export(lat, bw, crypto)`
  - `operator`
  
  The two share `/etc/bird/peers` and `/run/bird` as emptyDirs.
  `images/bird/Dockerfile` is the BIRD image (`make bird-image`); the
  integration tests run on it too.
- `service-endpoint.yaml`: the floating LoadBalancer endpoint with
  `externalTrafficPolicy: Local`. Keep a placeholder port in git and tell
  ArgoCD to ignore `spec.ports`.

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
- **losing the lease**: links are removed synchronously, before another
  replica can take it. **On shutdown** (`--cleanup-on-shutdown`, default on),
  links are removed and then the lease is released, so a key is never live on
  two nodes.

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
network, so pick free ports.

### Metrics

`dn42_operator_leader`, `dn42_operator_passes_total`,
`dn42_operator_pass_errors_total{stage}`,
`dn42_operator_link_changes_total{op}`, `dn42_operator_deletions_blocked`,
`dn42_operator_bird_up`, and per peer (`peer`, `asn` labels):
`dn42_peer_valid`, `dn42_peer_tunnel_ready`,
`dn42_peer_handshake_age_seconds`, `dn42_peer_bgp_established`,
`dn42_peer_routes_imported`, `dn42_peer_endpoint_rtt_seconds`.

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
access to `dn42peers` in `dn42` for the status page. It never writes to the
cluster; changes go out as PRs. Example config: `deploy/autopeer-config.example.yaml`.
Example namespace, Deployment (with a git-sync sidecar for the registry)
and RBAC: `deploy/autopeer.yaml`.

The flow:

1. **Login** with one of the configured providers. Each one is a generic
   OAuth 2.0 / OpenID Connect client: Authorization Code with PKCE (S256)
   always, and nonce plus ID-token verification when `issuer` is set (OIDC
   discovery). Without `issuer`, it uses `authURL`/`tokenURL`/`userinfoURL`
   (plain OAuth, identity from userinfo).
2. **Ownership**: `claims.asn` names the claim with the ASNs the login may
   manage. Dotted paths, numbers, `AS…` strings and lists all work.
   `claims.mntner` names a claim with mntners; their ASNs come from
   `mnt-by:` in a DN42 registry clone (`data/aut-num`), reloaded on an
   interval. No accounts: the login lives in an AES-GCM encrypted cookie for
   `sessionTTL`.
3. **Form**: ASN (from the login), name, WireGuard public key, optional
   endpoint, link-local address. These are checked with the same code as the
   operator, against the peers already in the repo: name, port, ASN +
   neighbor, and not our own link-local address. `listenPort` is always
   written explicitly: 2 + the last 4 digits if that's free, otherwise the
   highest free port. Peers use the shared autopeer key (no `keyRef`).
4. **PR**: `peers/<asn>-<name>.yaml` on a new branch in the peers repo,
   through a GitHub App (JWT → installation token → branch, file, PR). The
   page shows the WireGuard and BIRD config for the peer's side.
5. **Status**: the home page lists the login's peers from the repo, plus
   new ones still in an open PR. It shows live state (BGP state, handshake,
   routes, Valid) from the cluster when `kubernetes.enabled`.
6. **Edit and removal**: an autopeer (no `keyRef`) gets Edit and Remove
   buttons. Edit changes only the peer's own fields (public key, endpoint,
   link-local address), keeping name, ASN, our port and link values, and
   opens a PR updating the file. Remove opens a PR deleting it.
   Hand-managed peers can't be changed through the app; the gate enforces
   the same rule.

Peers in open PRs count as taken: a second request can't reuse their name,
port or ASN + neighbor while the first is in review, and a peer with an
open PR can't be removed. One deployment serves several hosts
(`extraPublicURLs`). A login's redirect URI is the configured base matching
the request's host, so a forged `Host` header can't send it elsewhere.
Submissions and removals are rate limited per login and in total
(`limits`, in memory).

`--fake-repo` keeps PRs in memory for local runs. The tests run the full
flow against a fake OIDC/OAuth provider that enforces PKCE and nonce, and the
GitHub App client against a fake GitHub API.

### To check before go-live

The provider details are unverified; everything marked `CHECK` in the
example config:

- **Kioubit** (AS4242423914): the OIDC issuer URL and its client
  registration (message Kioubit on IRC to activate the domain). Which scope
  releases the ASN, and the claim name and format for ASN and/or mntner.
- **OAuth.dn42 / iedon** (auth.iedon.net): the exact issuer (discovery
  path), self-service registration, and whether the ASN or mntner is in the
  ID token or only in userinfo (`useUserinfo`). Also the claim names.
- **HExpNetwork WebAuth** (AS4242420298): everything (OIDC or not,
  endpoints, claims, registration).
- **Auth42 / burble**: OIDC or plain OAuth, endpoints, claim names (subject,
  mntner/ASN), and registration.
- For all four: does the claim mean "may manage" (`mnt-by`) or only
  "authenticated as"? Do they support PKCE for confidential clients? Which
  redirect URIs are allowed (`dn42.oscarr.nl` and `autopeer.oscrx.dn42`)?

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
  - The App (`--app-login`) may only touch `peers/`, may not set `keyRef`,
    and may not change or delete hand-managed (`keyRef`) peers. Breaking any
    of these fails the check.
  - Human PRs pass but are not auto-mergeable.
  - Auto-merge needs an App PR that changes exactly one peer file.

Trees are read from git objects, not the worktree (`--worktree` is for
local runs). Under Actions it writes `auto-mergeable=` to `$GITHUB_OUTPUT`
and emits error annotations. The fixtures are in
`internal/peercheck/testdata/cases/<case>/`: the head tree, the base
versions and `case.yaml` with the diff, author and expected outcome.

## Not done yet

- autopeer: the provider checks above.
- Tag a release so the peers repo workflow's pinned
  `go install .../cmd/peercheck@v0.1.0` resolves (after the repo is public).

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
  - signed images: `ghcr.io/oscrx/dn42-operator`, `dn42-autopeer` and `bird2`
  - then the GitHub release
- Actions and base images are pinned by digest. Renovate keeps them current
  and automerges digests and minor bumps once CI is green. Kubernetes minors
  and the BIRD base image are reviewed by hand.

`make verify` runs the test and lint jobs locally; `make help` lists the
rest. None of the workflows has run on GitHub yet. Locally they pass
actionlint and zizmor, the Renovate config validates, and their commands
pass.

## License

MIT, see [LICENSE](LICENSE).

## More nodes

The design for a second DN42 node (`DN42Node`, internal tunnels, iBGP,
local_pref across nodes, no internal leaks to DN42) is in
[docs/ibgp.md](docs/ibgp.md). Not built yet; v0.1 is one node.
