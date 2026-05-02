# speer

a small libp2p-ish stack in c.

it has noise xx, libp2p over tcp, yamux, mdns, dht bits, partial quic, and a
tls 1.3 core. no external deps.

source size: 17,791 lines across 111 `.c`/`.h` files in `src/` and `include/`
(15,550 nonblank). tests, examples, rust, and build output are not counted.

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

native speer host over udp:

```c
#include "speer.h"

speer_host_t* host = speer_host_new(seed, NULL);
speer_peer_t* peer = speer_connect(host, peer_pk, "1.2.3.4:4242");
speer_stream_t* s = speer_stream_open(peer, 0);
speer_stream_write(s, (uint8_t*)"hello", 5);

while (running) speer_host_poll(host, 100);
```

libp2p tcp pieces are lower-level and can be used directly:

```c
#include "transport_tcp.h"
#include "libp2p_noise.h"
#include "yamux.h"

speer_transport_ops_t* tcp = speer_tcp_transport();
void* conn = tcp->dial(NULL, "1.2.3.4", 4001);

speer_libp2p_noise_ctx_t noise;
speer_libp2p_noise_init(&noise, 1, libp2p_priv, libp2p_pub);
speer_libp2p_noise_handshake(&noise, conn, tcp);

speer_yamux_t mux;
speer_yamux_init(&mux, 1);
speer_yamux_stream_t* stream = speer_yamux_open_stream(&mux);
```

## examples

```bash
./examples/echo_server
./examples/chat <peer_pubkey> <host:port>
./examples/speer_chat
./examples/libp2p_ping demo
./examples/libp2p_quic_ping
```

`examples/speer_chat` is the bigger terminal chat demo. it uses mdns discovery,
tcp, noise xx, yamux, protobuf chat frames, and basic file transfer.

## install

cmake install exports both cmake and pkg-config metadata:

```bash
cmake -S . -B build -DSPEER_BUILD_TESTS=OFF
cmake --build build
cmake --install build
```

then consumers can use either `find_package(speer)` or `pkg-config speer`.

## rust

split repos:

- [`speer-sys-rust`](https://github.com/jk20342/speer-sys-rust) - raw ffi
- [`speer-rust`](https://github.com/jk20342/speer-rust) - safe rust wrapper
- [`speer-rust-chat`](https://github.com/jk20342/speer-rust-chat) - terminal chat app

the rust crates are developed in this workspace right now, then pushed to those
repos when they are ready.

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
