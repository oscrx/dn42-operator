# Design: more than one DN42 node (iBGP)

Status: design only. v0.1 runs one node (talos4). Nothing here is needed for
the talos4 cutover, and the v1alpha1 `DN42Peer` stays as it is: everything
below is new fields with one-node defaults or a new kind.

## Model

**`DN42Node`** (namespaced, `dn42.oscarr.nl/v1alpha1`): one per own router.

```yaml
apiVersion: dn42.oscarr.nl/v1alpha1
kind: DN42Node
metadata:
  name: talos4            # = Kubernetes node name; internal links are wgi-<other node>
spec:
  routerID: 10.38.18.4    # next node 10.38.18.5
  loopback: fd69:420:cafe:ffff::1/128      # from fd69:420:cafe:ffff::/64; dn42-lo on that node
  servicePrefix: fd69:420:cafe:10::/64     # optional, node-local services
  egress: true            # owns the LAN/cluster exit (only talos4 talks to OPNsense)
  wireguard:
    publicKey: …          # this node's key for internal links
    keyRef: node-talos4   # private key in dn42-wireguard-keys (never the autopeer key)
    endpoint: "[2a05:…]:23800"   # reachable by the other nodes
    listenPortBase: 23800        # wgi-<peer> ports: base + index of the other node
```

Internal links follow from the set of `DN42Node` objects: a full mesh, one
link per pair. Each node's operator builds only its own ends
(`wgi-<other>`) in `vrf-dn42`, with link-locals derived per pair
(`fe80::<routerID last octet>`), the node's own key, and allowed IPs
`fe80::/10, fd00::/8` like peers.

**`DN42Peer`** gets `spec.node` (default: the only node, so existing files
don't change). A peer belongs to exactly one node; that node's operator
builds its tunnel and session.

## Active/active versus the standby lease

Today one Lease picks the single active router; a standby takes over the
floating endpoint. With two DN42 nodes both are active for their own peers.
So the lease moves from "the router" to "the floating endpoint": only peers
with `node: floating` (autopeers on the LB /128) follow the lease, and
each node always runs its own `node: <name>` peers. Open decision: whether
a node may also be the standby for the floating group (likely yes).

## BIRD

New, static in bird.conf (rendered per node from the node's own values:
`router id`, the route-collector source):

```
define INTERNAL = (4242423818, 1, 1);   # large community: never leaves the AS

template bgp ibgp {
  vrf "vrf-dn42";
  local as OWNAS;
  neighbor as OWNAS;
  direct;                 # 2–3 nodes: sessions over the wgi-* link-locals
  ipv6 {
    next hop self ebgp;   # routes learned over eBGP get our address as next hop
    import where ibgp_import(INTERNAL_LATENCY);
    export where ibgp_export();
  };
}
```

The operator renders one `protocol bgp node_<other> from ibgp` per internal
link with `neighbor fe80::… as OWNAS; interface "wgi-<other>";` and
`ibgp_import(<latency of that link>)`. For more nodes the template changes to
multihop between loopbacks (`source address` = own loopback), and a route
reflector can be added without touching `DN42Peer`.

Filters:

- `ibgp_export()`: routes learned over eBGP (`source = RTS_BGP` from a
  dnpeers protocol), the /48 static (every node announces it), the node's
  loopback and servicePrefix, plus `fd69:420:cafe:ff::/64` only from the
  egress node. Loopbacks and node prefixes carry `INTERNAL`.
- `ibgp_import(lat)`: keep local_pref from the eBGP side (200 − 10·latency)
  and subtract `10·lat` of the internal link. A node then prefers its own
  exit unless another node's is better by more than the internal hop. The
  DN42 link communities are **not** updated on iBGP (the internal link is
  ours, not a DN42 link).
- `dn42_export()` gains `if (bgp_large_community ~ [INTERNAL]) || is_internal_net() then return false;`.
  Only the /48 and learned DN42 routes go to peers; node /64s and loopbacks
  never do.
- Route collector: one session per node, from that node's loopback
  (`local fd69:420:cafe:ffff::<n>`), exporting the same set as to peers.

IGP: none with two nodes (direct sessions). From three nodes on, Babel
(latency metric) on the `wgi-*` links for loopbacks and node prefixes only;
DN42 routes stay in BGP. BIRD then resolves next hops recursively
(`gateway recursive` / `igp table`), and `bgp_igp_metric` becomes the tie
breaker instead of the fixed subtraction.

## LAN and cluster stay behind talos4

Only the egress node (talos4) has the OPNsense route for
`fd69:420:cafe::/48` in table 42 and exports `fd69:420:cafe:ff::/64` (the
cluster Gateways) into iBGP. On every other node the kernel protocol installs
that /64 via `wgi-talos4` in table 42, so DN42 traffic for the Gateways
arriving there crosses the internal tunnel. VRF isolation is the same on
every node: the same Talos plumbing (`vrf-dn42`, `dn42-lo` with its own
loopback, `dn42-null` catch-all), and no other node has a LAN exit.

## Operator changes, when this is built

1. `DN42Node` type and validation (router ID unique, loopback in
   `ffff::/64` and unique, ports don't collide with peer ports).
2. Internal links: the same netdev code with `wgi-` names; internal links
   are excluded from the mass-deletion guard's peer count but obey it.
3. Rendered per node: the `router id`/route-collector lines (bird.conf becomes
   a template with node values) and the `node_<other>` sessions.
4. `DN42Peer.spec.node`, and the lease scoped to the floating group.
5. peercheck: `node` must name an existing `DN42Node`; internal prefixes may
   never appear in a peer file.
