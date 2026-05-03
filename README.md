# speer

a small libp2p-ish stack in c. solo-maintained; scope is a lot for one person
but here we are.

**two entrypoints (same repo, different wire):**

| api | wire | peers |
| --- | --- | --- |
| `speer.h` | udp + speer `packet.c` format (noise **xx** embedded; not libp2p tcp/quic) | native speer only |
| `speer_libp2p_tcp.h` | tcp + multistream + noise xx + yamux | kubo, py-libp2p, rust-libp2p, … on tcp |

`examples/libp2p_tcp_full_session.c` dials a normal libp2p tcp host (noise → yamux
→ stream proto); it has been checked against py-libp2p.

it has noise xx, libp2p over tcp, yamux, mdns, dht bits, partial quic, and a
tls 1.3 core. no external deps.

source size: 19,180 lines across 121 `.c`/`.h` files in `src/` and `include/`
(16,747 nonblank). tests, examples, rust, and build output are not counted.

more detail:

- [architecture](docs/architecture.md)
- [security](docs/SECURITY.md)

## build

```bash
make
make examples
make test
```

windows with mingw:

```powershell
mingw32-make
.\tests\run_tests.ps1
```

## quick use

native speer host over udp (speer-to-speer only on the wire):

```c
#include "speer.h"

speer_host_t* host = speer_host_new(seed, NULL);
speer_peer_t* peer = speer_connect(host, peer_pk, "1.2.3.4:4242");
speer_stream_t* s = speer_stream_open(peer, 0);
speer_stream_write(s, (uint8_t*)"hello", 5);

while (running) speer_host_poll(host, 100);
```

libp2p-over-tcp session (interop with other libp2p implementations on tcp):

```c
#include "speer_libp2p_tcp.h"
#include "transport_tcp.h"

speer_libp2p_identity_t id;
/* fill id from keys - copy pattern in examples/libp2p_tcp_full_session.c */
int fd;
speer_tcp_dial(&fd, "127.0.0.1", 4001);
speer_libp2p_tcp_session_t session;
speer_libp2p_tcp_session_init_dialer(&session, fd, &id);
/* then yamux + multistream per stream - same example file */
```

full bootstrap including yamux + protocol open is in
`examples/libp2p_tcp_full_session.c`.

## examples

```bash
./examples/echo_server
./examples/chat <peer_pubkey> <host:port>
./examples/libp2p_ping demo
./examples/libp2p_quic_ping
```

the terminal chat demo with mdns/tcp/noise/yamux lives in the rust workspace crate
`speer-chat` (`rust/speer-chat`).

## install

cmake install exports both cmake and pkg-config metadata:

```bash
cmake -S . -B build -DSPEER_BUILD_TESTS=OFF
cmake --build build
cmake --install build
```

then consumers can use either `find_package(speer)` or `pkg-config speer`.

## rust

rust repos:

- [`speer-sys-rust`](https://github.com/jk20342/speer-sys-rust) - raw ffi
- [`speer-rust`](https://github.com/jk20342/speer-rust) - safe rust wrapper
- [`speer-rust-chat`](https://github.com/jk20342/speer-rust-chat) - terminal chat app

## status

- noise xx: full
- yamux: full
- mdns: full, but treat records as hints
- dht: practical core
- tls 1.3: core pieces
- quic v1: packet codec, not a full connection stack yet
- relay / dcutr: partial

## license

MIT
