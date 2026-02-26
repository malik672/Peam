# Peer Management

`PeerManager` maintains the peer registry and scoring state.

## Peer scoring

Each peer has an integer score. Scores change as follows:

| Event | Effect |
|-------|--------|
| Valid gossip message | +`topic_score` (per-topic weight from config) |
| Invalid / malformed message | negative delta |
| Rate limit exceeded | negative delta |
| Periodic decay tick | score -= `score_decay_amount` |
| Score falls below `ban_threshold` | peer is banned |

Score decay runs on a background task at `score_decay_interval_secs` frequency.

## Trusted peers

Peers listed in `trusted_peers` are exempt from score-based banning. They can have arbitrarily low scores and will not be disconnected. This is useful for validators operating behind a relay or for test harnesses.

## Ban/unban

When a peer's score falls below `ban_threshold`:
1. The peer is added to the ban list.
2. The libp2p swarm is instructed to disconnect and block the peer.

Bans are not currently persisted across restarts.

## Discovery integration

`Discovery` maintains a set of bootstrap nodes (`bootnodes`) and dials them periodically (every `discovery_interval_secs`). Newly discovered peers are added to the peer registry.

Wide-area discovery via discv5 is planned but not yet fully integrated.
