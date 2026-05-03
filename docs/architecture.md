# architecture

speer is a small p2p stack in c (solo-maintained). one library, **two
entrypoints**—pick based on who you talk to:

| if your peer is… | use | on the wire |
| --- | --- | --- |
| another speer `speer.h` host | `include/speer.h` | udp datagrams + `packet.c` framing (noise **xx** inside; **not** libp2p tcp/quic) |
| kubo, py-libp2p, rust-libp2p, … on **tcp** | `include/speer_libp2p_tcp.h` | tcp → multistream `/noise` → noise xx (length-prefixed) → yamux → stream protos |

the tcp session follows the same security/mux upgrade shape as those stacks
(`examples/libp2p_tcp_full_session.c` has been run against a py-libp2p listener:
noise, yamux, `/echo/1.0.0`).

the public `speer.h` host / peer / stream api is the first row. the second row
is the lower-level tcp session + helpers that examples and the rust ffi compose.

## layout

```text
speer/
|-- include/        public headers installed for users
|-- src/crypto/     ed25519, x25519/noise pieces, sha, hkdf, aeads, rsa/ecdsa helpers
|-- src/wire/       packet, protobuf, asn.1, tls message, quic frame encoding
|-- src/util/       varints, length prefixes, constant-time helpers
|-- src/infra/      host, peer, stream, sockets, metrics, buffer pool
|-- src/libp2p/     noise, yamux, multistream, peer ids, multiaddrs, identify
|-- src/transport/  tcp helpers
|-- src/discovery/  mdns and dht
|-- src/relay/      circuit relay and dcutr
|-- src/quic/       quic packets, initial keys, header protection
|-- src/tls/        tls 1.3 and x.509/web pki, optional in cmake
|-- examples/       small demos and the bigger terminal chat demo
`-- tests/          unit, integration, fuzz, and protocol checks
```

## build-time pieces

cmake controls the optional parts:

```text
SPEER_ENABLE_MDNS    on by default
SPEER_ENABLE_DHT     on by default
SPEER_ENABLE_RELAY   on by default
SPEER_ENABLE_WEBPKI  off by default
```

web pki pulls in `src/tls/`. the tls/quic code exists in the tree, but the web
pki path is not part of the default library build unless `SPEER_ENABLE_WEBPKI`
is turned on.

## public api

the main api is in `include/speer.h`.

```c
speer_host_t *host = speer_host_new(seed, &cfg);
speer_host_set_callback(host, on_event, user_data);

while (running) {
    speer_host_poll(host, 100);
}

speer_host_free(host);
```

the public model is:

- create one host with a 32-byte seed
- poll it from your event loop
- handle events in the callback
- open streams with `speer_stream_open`
- write/read stream data with `speer_stream_write` and `speer_stream_read`
- close streams/peers/hosts explicitly

the public host api does not currently expose a socket fd. if you need tight
integration with another event loop, poll speer with a short timeout or wrap it
on its own thread and communicate with message passing.

## native speer path

the `speer.h` api drives the internal host / peer / stream code over **udp
datagrams** (`SOCK_DGRAM`). `packet.c` wraps **noise xx** and transport data in
custom initial / handshake / 1rtt packets (quic-ish) with cids and stream
frames—it is **not** libp2p’s byte-stream transport (no multistream, no
length-prefixed noise messages over tcp, and not interop with libp2p quic
either). another kubo or py-libp2p peer will not parse these packets; interop
with them needs `speer_libp2p_tcp_session_*` (or another stack). two speer
native hosts agree on this packet format.

roughly:

```text
host poll
  -> receive packet
  -> find peer by connection id
  -> advance handshake or decrypt transport packet
  -> dispatch stream frame
  -> call app callback
```

packet size is capped by `SPEER_MAX_PACKET_SIZE` (`1350`). default caps also
exist for peers and streams.

## libp2p over tcp

the tcp path is `include/speer_libp2p_tcp.h` plus `src/libp2p/`, `src/transport/`,
`src/wire/`. it is the stack that **other libp2p implementations expect** on tcp:
multistream, noise xx with libp2p handshake payloads, yamux, then per-stream
multistream.

the chat demo and rust chat app use this path:

```text
tcp dial/listen
  -> multistream /noise + noise xx
  -> multistream /yamux/1.0.0 + yamux
  -> multistream on each stream for app protocol
  -> app frames
```

`speer_chat.c` uses mdns discovery, tcp, this path, protobuf chat frames, and
file transfer over `/speer/chat/1.0.0`.

## discovery

`src/discovery/mdns.*` handles local-network discovery. records should be
treated as hints, not identity proof.

`src/discovery/dht.*` and `dht_libp2p.*` implement a practical kademlia core:
routing table work, iterative lookups, store/provide style values, bounded
values, and libp2p kad protobuf/stream handling.

## relay and dcutr

`src/relay/` contains circuit relay helpers, a relay client, a relay server, and
partial dcutr support.

the dcutr code keeps per-peer state and handles connect/sync messages. the
candidate trust check currently covers ipv4 candidates in the same `/24` as the
known authenticated peer address. it is useful scaffolding, not a full nat
traversal stack.

## quic and tls

`src/quic/` has quic v1 packet/framing pieces, initial key derivation, header
protection, and flow helpers. it is not a full quic connection stack yet.

`src/tls/` has tls 1.3 record/handshake/key-schedule code and x.509 helpers.
tests cover the record layer, handshake paths, negative vectors, key update, hrr
paths, auth checks, and optional openssl smoke checks when the tool is
available.

## thread model

use the public host / peer / stream api from one event-loop thread. the buffer
pool has an internal lock, but that does not make the whole host api generally
thread-safe.

for multithreaded apps, keep speer on one thread and send commands/events across
a channel or queue.

## memory model

speer uses explicit ownership:

- `speer_host_new` / `speer_host_free`
- `speer_stream_open` / `speer_stream_close`
- `speer_peer_close` for peer shutdown

the library checks allocations and cleans up host-owned resources on
`speer_host_free`. long-term key storage is still the app's job.

## protocol status

| area | status | notes |
| --- | --- | --- |
| native host api | working core | poll-based udp host, peers, streams |
| libp2p noise xx | working core | signed libp2p payload binds peer id to noise session |
| yamux | working core | stream mux used by tcp chat path |
| multistream | working core | protocol selection for libp2p-style streams |
| mdns | working core | local discovery, records are hints |
| dht | practical core | routing table, lookups, bounded store values, libp2p protobuf |
| tls 1.3 | core tested | optional web pki build path |
| quic v1 | partial | packets, initial keys, frames, header protection |
| circuit relay | partial | relay helpers/client/server |
| dcutr | partial | per-peer state, ipv4 candidate filtering |

## rust crates

the rust side is split into three repos:

- [`speer-sys-rust`](https://github.com/jk20342/speer-sys-rust): raw bindgen ffi
- [`speer-rust`](https://github.com/jk20342/speer-rust): safe rust wrapper over the public api
- [`speer-rust-chat`](https://github.com/jk20342/speer-rust-chat): ratatui chat app

`speer-sys-rust` maps to the c headers directly. `speer-rust` is the safe crate
most rust apps should use. `speer-rust-chat` is a standalone app using the
**libp2p tcp session** (not rust-libp2p crates): ffi into the same path as
`speer_libp2p_tcp_session_*` in c.

## libp2p ffi facade

the exported libp2p facade keeps rust bindings on stable `speer_*` names instead
of exposing every internal dht or relay struct. current facade coverage is
identify encode/decode and kad message helpers, plus a `/ipfs/kad/1.0.0`
roundtrip over an already authenticated tcp/noise/yamux session. kad ping has
been checked against public libp2p bootstrap nodes; broader bootstrap discovery
is still experimental.

relay and dcutr remain separate experimental surfaces until the relay client is
running over normal libp2p streams and has interop tests.
