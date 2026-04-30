# speer

A tiny libp2p in C. Full QUIC v1 + TLS 1.3 + Web PKI in ~20k LOC, zero dependencies.

## Build

```bash
make              # libspeer.a + libspeer.so
make examples
```

On **Windows** with MinGW, `mingw32-make` (or GNU Make with `OS=Windows_NT`) builds `libspeer.a` and `speer.dll`; the Makefile links `-lws2_32 -liphlpapi -ladvapi32`. Unit tests: PowerShell `.\tests\run_tests.ps1` from this directory.

## Usage

speer exposes the stack at every level. Pick the layer you need.

### Layer 1: speer-native (Noise + reliable UDP)

```c
#include "speer.h"

speer_host_t* host = speer_host_new(seed, NULL);
speer_peer_t* peer = speer_connect(host, peer_pk, "1.2.3.4:4242");
speer_stream_t* s = speer_stream_open(peer, 0);
speer_stream_write(s, (uint8_t*)"hello", 5);

while (running) speer_host_poll(host, 100);
```

### Layer 2: libp2p over TCP

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

### Layer 3: QUIC v1

```c
#include "quic_pkt.h"

speer_quic_keys_t client_keys, server_keys;
speer_quic_keys_init_initial(&client_keys, &server_keys, dcid, dcid_len);

speer_quic_pkt_t pkt = {
    .is_long = 1, .pkt_type = QUIC_PT_INITIAL, .version = QUIC_VERSION_V1,
    .pkt_num = 0, .pn_length = 1,
    .payload = crypto_frame, .payload_len = crypto_frame_len,
};
speer_quic_pkt_encode_long(out, sizeof(out), &out_len, &pkt, &client_keys);
```

### Layer 4: TLS 1.3 + Web PKI

```c
#include "tls13_handshake.h"
#include "x509_webpki.h"
#include "ca_bundle.h"

speer_tls13_t tls;
speer_tls13_init_handshake(&tls, SPEER_TLS_ROLE_CLIENT,
    cert_priv, cert_pub,
    SPEER_LIBP2P_KEY_ED25519, libp2p_pub, 32, libp2p_priv, 32,
    "h3", "example.com");

speer_tls13_handshake_start(&tls);

speer_x509_t leaf;
speer_x509_parse(&leaf, peer_cert_der, peer_cert_der_len);
speer_x509_verify_chain(speer_ca_bundle_default(),
                          &leaf, intermediates, num_intermediates,
                          "example.com", time(NULL));
```

## Examples

```bash
./examples/echo_server          # Layer 1
./examples/chat <peer_pubkey>   # Layer 1
./examples/libp2p_ping demo     # Layer 2
./examples/libp2p_quic_ping     # Layer 3
```

## Build flags

| Flag           | Default  | Adds                                       |
|----------------|----------|--------------------------------------------|
| (none)         | on       | Layer 1 + 2: Noise + TCP + libp2p MVP      |
| `SPEER_QUIC`   | on       | Layer 3: QUIC v1 + TLS 1.3 + libp2p certs  |
| `SPEER_WEBPKI` | opt-in   | Layer 4: bignum, RSA, ECDSA, RFC 5280      |
| `SPEER_RELAY`  | on       | Circuit Relay v2 + DCUtR                   |

## License

MIT
