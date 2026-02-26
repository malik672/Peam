# Discovery

`Discovery` handles initial peer acquisition and periodic re-dialing of bootstrap nodes.

## Bootstrap dialing

On startup and every `discovery_interval_secs` seconds, the node dials all addresses listed in `bootnodes`. These are multiaddr strings of the form:

```
/ip4/1.2.3.4/tcp/30303/p2p/12D3KooWBootA
```

If a bootnode is already connected, the dial is a no-op.

## mDNS

When running on a local network, mDNS is active and automatically discovers peers that are broadcasting on the same LAN segment. This is primarily useful for local development and devnet testing.

Set `LEAN_ETH_REQUIRE_MDNS=1` to make the mDNS smoke test fail hard if no peers are discovered within the timeout.

## discv5 (planned)

Full discv5 integration (bootstrap ENR, peer table management, subnet advertisement) is planned. See `src/networking/discovery.rs`.

## Peer table

Discovered peers are handed off to `PeerManager`, which tracks their connection state and score. The networking stack does not currently persist the peer table across restarts.
