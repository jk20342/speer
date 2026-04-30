# speer Architecture

## Overview

speer is a layered implementation of the libp2p protocol stack in C. It provides four distinct layers that can be used independently or together, from low-level crypto primitives to high-level P2P abstractions.

## Layered Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 4: Web PKI (Optional)                                 │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐                       │
│ │  X.509   │ │   RSA    │ │ ECDSA    │                       │
│ │  Parser  │ │  (bignum)│ │ P-256    │                       │
│ └──────────┘ └──────────┘ └──────────┘                       │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│ Layer 3: QUIC v1                                            │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐         │
│ │  QUIC    │ │   TLS    │ │  Frame   │ │  Header  │         │
│ │  Packets │ │   1.3    │ │  Codec   │ │  Protect │         │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘         │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│ Layer 2: libp2p over TCP                                    │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐         │
│ │  Noise   │ │  Yamux   │ │Multistream│ │  PeerID  │         │
│ │  XX      │ │   Mux    │ │  Select  │ │          │         │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘         │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: speer-native (Noise + UDP)                         │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐         │
│ │   UDP    │ │  Noise   │ │ ChaCha20 │ │ Stream   │         │
│ │  Socket  │ │   XX     │ │Poly1305  │ │  Mgmt    │         │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘         │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│ Foundation Layer (Crypto & Utils)                            │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐         │
│ │  Ed25519 │ │  X25519  │ │ SHA-256  │ │  HKDF    │         │
│ │  AES-GCM │ │ ChaCha20 │ │ SHA-512  │ │ varint   │         │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘         │
└─────────────────────────────────────────────────────────────┘
```

## Module Descriptions

### Crypto (`src/crypto/`)

The cryptographic primitives layer provides all necessary crypto without external dependencies:

- **Ed25519**: Digital signatures using DJB's Ed25519 curve
- **X25519**: ECDH key exchange (Curve25519)
- **AES-GCM**: AES-256 in Galois Counter Mode (uses x86 AES-NI when available)
- **ChaCha20-Poly1305**: AEAD cipher for Noise protocol
- **SHA-2**: SHA-256, SHA-384, SHA-512 hash functions
- **HKDF**: HMAC-based Extract-and-Expand Key Derivation Function
- **bignum**: Arbitrary precision arithmetic for RSA/ECDSA

### Wire Format (`src/wire/`)

Protocol encoding/decoding:

- **varint**: Variable-length integer encoding (Protocol Buffers style)
- **length_prefix**: Length-prefixed message framing
- **protobuf**: Minimal protobuf encoder/decoder
- **ASN.1**: DER encoder/decoder for X.509
- **packet**: speer-native packet format
- **quic_frame**: QUIC frame types (STREAM, ACK, CRYPTO, etc.)
- **tls_msg**: TLS 1.3 message encoding

### Infrastructure (`src/infra/`)

Core networking infrastructure:

- **host**: Main event loop, peer management
- **peer**: Peer connection state machine
- **stream**: Stream multiplexing over connections
- **socket**: Cross-platform UDP socket wrapper
- **buffer_pool**: Memory-efficient buffer management
- **sig_dispatch**: Signal handling utilities

### libp2p Protocol (`src/libp2p/`)

libp2p-specific protocols:

- **libp2p_noise**: Noise XX handshake with libp2p extensions
- **yamux**: Yet Another Multiplexer (stream multiplexing)
- **multistream**: Protocol negotiation
- **identify**: Peer identification protocol
- **peer_id**: Peer ID generation and encoding
- **multiaddr**: Network address encoding

### Discovery (`src/discovery/`)

Peer discovery mechanisms:

- **mdns**: Multicast DNS local peer discovery
- **dht**: Kademlia DHT for global peer routing

### Transport (`src/transport/`)

Transport layer implementations:

- **transport_tcp**: TCP transport for libp2p

### QUIC (`src/quic/`)

QUIC protocol implementation:

- **quic_pkt**: QUIC packet processing
- **quic_tls**: QUIC-TLS integration
- **header_protect**: QUIC header protection (AES-GCM/ChaCha)

### TLS (`src/tls/`)

TLS 1.3 and PKI:

- **tls13_handshake**: TLS 1.3 handshake state machine
- **tls13_record**: TLS 1.3 record layer
- **tls13_keysched**: TLS 1.3 key schedule
- **x509_libp2p**: libp2p TLS certificate handling
- **x509_webpki**: Web PKI certificate validation
- **ca_bundle**: Embedded CA root certificates

### Relay (`src/relay/`)

Circuit relay for NAT traversal:

- **circuit_relay**: Circuit Relay v2 protocol
- **relay_client**: Relay client implementation
- **dcutr**: Direct Connection Upgrade through Relay (hole punching)

## Data Flow

### Connection Establishment (Layer 1)

```
┌─────────┐                    ┌─────────┐
│  Host A │                    │  Host B │
│ (Initiator)                  │(Responder)│
└────┬────┘                    └────┬────┘
     │                              │
     │  1. Noise XX msg1 (ephemeral)│
     │ ─────────────────────────────>
     │                              │
     │  2. Noise XX msg2 (ephemeral, static)
     │ <─────────────────────────────
     │                              │
     │  3. Noise XX msg3 (static)   │
     │ ─────────────────────────────>
     │                              │
     │  4. Encrypted traffic        │
     │ <────────────────────────────>
     │                              │
```

The Noise XX handshake provides mutual authentication and forward secrecy:

1. Both parties exchange ephemeral keys
2. Both parties exchange static (identity) keys
3. Shared secrets are derived from ephemeral and static keys
4. Traffic encryption keys are derived via HKDF

### Packet Structure (Layer 1)

```
┌──────────────────────────────────────────────────────────────┐
│                        Packet Format                          │
├─────────┬─────────┬─────────┬──────────┬────────┬───────────┤
│ Version │  Type   │ CID Len │    CID   │ Pkt Num│  Payload  │
│  1 byte │ 1 byte │ 1 byte  │ variable │ varint │  encrypted│
├─────────┴─────────┴─────────┴──────────┴────────┴───────────┤
│                        Encrypted Region                       │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Stream Frame: [type][stream_id][offset][len][data...]  │  │
│  └───────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### Stream Multiplexing

Multiple streams are multiplexed over a single peer connection:

```
┌─────────────────────────────────────────┐
│           Peer Connection              │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐  │
│  │ Stream 0│ │ Stream 1│ │ Stream 2│  │
│  │ (Ctrl)  │ │ (App A) │ │ (App B) │  │
│  └────┬────┘ └────┬────┘ └────┬────┘  │
│       │           │           │        │
│       └───────────┴───────────┘        │
│                   │                     │
│           ┌───────────────┐             │
│           │  Packet Queue  │             │
│           │   (Encrypted)  │             │
│           └───────────────┘             │
└─────────────────────────────────────────┘
```

## Thread Safety

speer is currently single-threaded by design:

- All APIs are **not** thread-safe
- Use a single event loop thread for all speer operations
- For multi-threaded applications, use message passing to communicate with the speer thread

This design simplifies reasoning about concurrency and eliminates lock overhead.

## Memory Management

speer uses explicit memory management:

- **Host**: Allocated with `speer_host_new()`, freed with `speer_host_free()`
- **Peer**: Created automatically on connection, freed with `speer_peer_close()`
- **Stream**: Created with `speer_stream_open()`, freed with `speer_stream_close()`

All internal allocations use `malloc()`/`calloc()` with NULL checks. The library cleans up all resources on host free.

## Event Loop Integration

speer uses a poll-based event loop:

```c
// Application main loop
while (running) {
    // Check for network events (non-blocking or with timeout)
    int processed = speer_host_poll(host, 100);
    
    // Do other application work...
    process_application_logic();
}
```

For integration with existing event loops:
- Get the socket fd with `speer_host_get_socket_fd()` (when exposed)
- Add to your poll/epoll/select set
- Call `speer_host_poll(host, 0)` when socket is readable

## Protocol Compliance

| Protocol | Status | Notes |
|----------|--------|-------|
| libp2p Noise XX | Full | libp2p signed payload encrypted in messages 2/3 |
| Yamux | Full | Stream multiplexing with windowed flow control |
| mDNS Discovery | Full | Local peer discovery (claims treated as untrusted hints) |
| Kademlia DHT | Partial | Routing table, iterative lookups, STORE tokens |
| QUIC v1 | Partial | Initial packet support, packet number reconstruction, basic framing |
| TLS 1.3 | Partial | Client + server handshake; CertificateVerify and Finished verified |
| Circuit Relay v2 | Partial | Reservation auth, signed STOP binding |
| DCUtR | Partial | Per-peer state, anti-spoofed candidate addresses |

### TLS 1.3 details

- Client and server flows are both implemented. The server emits
  ServerHello / EncryptedExtensions / Certificate / CertificateVerify /
  Finished and the client sends its Finished as a second flight.
- `CertificateVerify` is parsed as `(sigalg, length-prefixed signature)`,
  the RFC 8446 §4.4.3 signed-content blob is rebuilt over the
  transcript-hash captured immediately after `Certificate`, and the
  signature is verified through `sig_dispatch` against the SPKI public
  key extracted from the leaf certificate.
- `Finished` is verified by computing the expected MAC with
  `speer_tls13_finished_mac` over the post-CertificateVerify transcript
  hash and comparing in constant time.
- The outer X.509 self-signature is verified in addition to the
  embedded libp2p extension; when a Web PKI bundle is supplied,
  `speer_x509_verify_chain` is invoked which enforces critical
  extensions, leaf `serverAuth` EKU, intermediate `keyCertSign` KU, and
  `path_len_constraint`.
- Cipher suites: `AES_128_GCM_SHA256`, `AES_256_GCM_SHA384`, and
  `CHACHA20_POLY1305_SHA256`. Key share: `x25519` (with `secp256r1`
  hooks). Sigalgs: `ed25519`, `ecdsa_secp256r1_sha256`,
  `rsa_pss_rsae_sha256`. Post-handshake KeyUpdate advances application
  traffic secrets; mutual authentication and full HRR are partial.
- The record layer caps sequence numbers below `2^48`, enforces the
  RFC 8446 §5.1 record-size limit, validates the legacy version
  bytes (`0x0303`), rejects `inner_type = 0`, and produces / consumes
  records on a per-direction sequence counter.

### libp2p Noise

- `write_s` / `read_s` carry the libp2p signed payload (built with
  `speer_libp2p_noise_payload_make`) instead of the bare 32-byte static
  key, so the peer's signature over `noise-libp2p-static-key:<static>`
  binds the PeerID to the Noise session.
- Both the embedded public key and the 64-byte signature are required
  on the receive path; payloads missing either field are rejected.

## Security Considerations

### Cryptographic Primitives

- All crypto from well-established libraries/standards (NaCl, RFC 7748, RFC 8439)
- No custom crypto algorithms
- Constant-time implementations where critical
- Secure memory wiping via `volatile` writes

### Key Management

- Private keys stored in 32-byte arrays
- Memory wiped on host free
- Keys never serialized to disk by the library
- Application responsible for secure key generation

### Attack Surface

- All network input is bounds-checked
- Protocol state machines validate transitions
- Maximum packet size enforced (1350 bytes)
- Connection limits prevent resource exhaustion

### Implemented (Security)

- TCP transport rate limit (concurrent connection cap and per-second
  accept budget in `transport_tcp.c`).
- HKDF expand bounds: `n <= 255` and `info_len <= 256` are enforced.
- ChaCha block counter cap: `speer_chacha_block_counter_at_max` allows
  callers to detect the 2^32 block ceiling per nonce and rotate before
  the counter wraps into the IETF 96-bit nonce.
- Constant-time tag/MAC comparisons via `speer_ct_memeq`, including the
  `n == 0` early-return.
- Cryptographic Connection IDs (`speer_random_bytes_or_fail` instead of
  the previous LCG) so peers cannot predict CIDs.
- DHT STORE tokens (HMAC-keyed by per-node secret + sender address) to
  block cross-network store amplification.
- Critical extension enforcement and EKU/KU/path-len policy checks in
  `x509_webpki.c`; unknown critical extensions fail the chain.
- Per-peer DCUTR state with anti-spoofed candidate addresses (only
  /24 IPv4 / /48 IPv6 prefixes matching the authenticated session
  address are accepted in `CONNECT` candidates).

### Not Implemented (Security)

- Certificate pinning
- Peer blacklisting beyond the rate-limit window
- DDoS protection beyond the transport rate limit

## Performance Characteristics

- **Memory**: ~1KB per peer + stream buffers
- **Latency**: 1-RTT connection establishment (Noise XX)
- **Throughput**: Limited by ChaCha20-Poly1305 (~2-4 Gbps per core)
- **Concurrency**: Single-threaded, poll-based event loop

## File Organization

```
speer/
├── include/
│   └── speer.h              # Public API header
├── src/
│   ├── crypto/              # Cryptographic primitives
│   ├── wire/                # Protocol encoding
│   ├── infra/               # Core infrastructure
│   ├── libp2p/              # libp2p protocols
│   ├── transport/           # Transport implementations
│   ├── tls/                 # TLS 1.3 + PKI
│   ├── quic/                # QUIC protocol
│   ├── relay/               # Circuit relay
│   └── discovery/           # Peer discovery
├── tests/                   # Unit and integration tests
├── examples/                # Example applications
└── docs/                    # Documentation
```
