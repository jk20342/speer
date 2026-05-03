# architecture

speer is a small p2p stack in c: a public `speer.h` host / peer / stream api, plus
lower-level libp2p-ish pieces for examples and rust ffi. crypto, wire encoding,
transports, discovery, and relay code live here without big external deps.

## layout

```text
speer/
|-- include/        public headers
|-- src/crypto/     ed25519, noise/x25519, sha, hkdf, aeads, rsa/ecdsa helpers
|-- src/wire/       packet, protobuf, asn.1, tls/quic framing
|-- src/util/       varints, length prefixes, constant-time helpers
|-- src/infra/      host, peer, stream, sockets, buffer pool
|-- src/libp2p/     noise, yamux, multistream, peer ids, multiaddrs, identify
|-- src/transport/  tcp
|-- src/discovery/  mdns, dht
|-- src/relay/      circuit relay, dcutr
|-- src/quic/       quic v1 packets, keys, header protection
|-- src/tls/        tls 1.3, x.509 (optional web pki in cmake)
|-- examples/       c demos (full tui chat: rust `speer-chat`)
`-- tests/          unit, integration, fuzz, protocol checks
```

## build-time pieces

```text
SPEER_ENABLE_MDNS    on by default
SPEER_ENABLE_DHT     on by default
SPEER_ENABLE_RELAY   on by default
SPEER_ENABLE_WEBPKI  off by default
```

`SPEER_ENABLE_WEBPKI` pulls in `src/tls/` for x.509-heavy paths; default builds
can still compile other tls pieces without it.

## public api

main header: `include/speer.h`.

```c
speer_host_t *host = speer_host_new(seed, &cfg);
speer_host_set_callback(host, on_event, user_data);
while (running) speer_host_poll(host, 100);
speer_host_free(host);
```

model: one host from a 32-byte seed, poll from your loop, events in the callback,
streams via `speer_stream_open` / `speer_stream_write` / `speer_stream_read`,
explicit closes. the host api does not expose a raw socket fd — use short poll
timeouts or a dedicated thread if you integrate with another loop.

## native speer path

`speer.h` sits on a poll-based udp stack: noise-style handshake, encrypted
packets, connection ids, stream frames. caps: `SPEER_MAX_PACKET_SIZE` (1350),
plus defaults for peer/stream counts.

```text
host poll -> recv -> peer by conn id -> handshake/decrypt -> stream frame -> callback
```

## libp2p over tcp

`speer_libp2p_tcp.h` plus `src/libp2p/`, `src/transport/`, `src/wire/`:

```text
tcp -> libp2p noise xx -> yamux -> multistream -> app protocol
```

rust `speer-chat` (and c `examples/chat`) use this stack; chat uses mdns, protobuf
frames, `/speer/chat/1.0.0`.

## discovery

mdns: local hints only, not proof of identity. dht: practical kademlia (routing,
lookups, bounded store, libp2p kad protobuf).

## relay and dcutr

`src/relay/`: circuit v2 protobuf, relay client/server, dcutr. speer-native path
uses `RELAY_FRAME_*` over tcp; libp2p hop uses yamux stream
`/libp2p/circuit/relay/0.2.0/hop`, `relay_client_attach_libp2p_hop()`, uvarint-framed
hop/stop protobuf. `relay_public_hop_check` (network) checks reserve to
`RELAY_STATE_RESERVED` against public relays; oversize vouchers parse but are not
copied into the small struct buffer. dcutr state is per-`speer_peer_t`;
`speer_host_poll_ex(..., SPEER_POLL_DCUTR)` runs `speer_dcutr_poll` by default.

## quic and tls

quic: v1 framing and crypto helpers only, not a full connection engine. tls: 1.3
record/handshake coverage with tests; web pki optional via cmake.

## thread model

assume one thread drives `speer_host_*` / streams. buffer pool locking does not
make the whole api thread-safe — use a queue/channel if you multithread.

## memory model

explicit: `speer_host_new` / `speer_host_free`, `speer_stream_open` /
`speer_stream_close`, `speer_peer_close`. host teardown frees library-owned
resources; long-term key storage is the app’s responsibility.

## protocol status

| area | status | notes |
| --- | --- | --- |
| native host api | working core | udp poll, peers, streams |
| libp2p noise xx | working core | peer id bound to noise session |
| yamux | working core | tcp mux |
| multistream | working core | stream protocol pick |
| mdns | working core | hints only |
| dht | practical core | kad + libp2p protobuf |
| tls 1.3 | core tested | optional web pki build |
| quic v1 | partial | packets, keys, not full stack |
| circuit relay | partial | speer framing + v2 hop interop (`relay_public_hop_check`) |
| dcutr | partial | host poll, stun, per-peer state |

## rust crates

- [`speer-sys-rust`](https://github.com/jk20342/speer-sys-rust) — ffi
- [`speer-rust`](https://github.com/jk20342/speer-rust) — safe wrapper
- [`speer-rust-chat`](https://github.com/jk20342/speer-rust-chat) — tui app

## libp2p ffi facade

stable `speer_*` entrypoints for rust: identify and kad helpers, `/ipfs/kad/1.0.0`
roundtrip on an existing noise/yamux session; kad ping checked on public
bootstrap nodes; wider bootstrap discovery still loose.
