# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

Please report security vulnerabilities to the project maintainers via email or private issue. Do not disclose publicly until a fix is released.

## Threat Model

### Assets Protected

1. **Private Keys**: Ed25519 signing keys and Noise ephemeral keys
2. **Data Confidentiality**: Payload data in transit
3. **Data Integrity**: Protection against tampering
4. **Peer Identity**: Verification of remote peer identity

### Trust Assumptions

- The local machine is not compromised
- The peer's public key is correctly obtained out-of-band, **or** when
  speer is acting as a Web PKI TLS client the application has supplied
  a valid `speer_ca_bundle_t` with the trusted root certificates that
  should be used to terminate the chain. Without a CA bundle the TLS
  layer falls back to libp2p-only authentication: the leaf certificate
  is authenticated by the embedded libp2p extension only, which
  authenticates the peer's libp2p identity (PeerID) but not a DNS name.
- Network attackers can read, modify, and replay packets

### Trust model for discovery and relay

- **mDNS** records are treated as **untrusted hints**. A peer that
  appears in mDNS must still complete a Noise XX or TLS 1.3 handshake
  before the application should associate any data with that PeerID.
- **DHT** STORE/PROVIDE records are likewise untrusted hints. The
  STORE RPC is gated by an HMAC token that is bound to the requester's
  source address (per Kademlia BEP 5). Values are rejected when length
  is zero or above `DHT_VALUE_MAX_SIZE`.
- **Circuit Relay** requires that the relay be authenticated through
  Noise; reservations and `STOP` messages are bound to the
  authenticated PeerID, and reservation-less `STOP` is rejected.
- **DCUtR** punching candidates that are received over the relayed
  control stream are restricted to the same /24 (IPv4) or /48 (IPv6)
  prefix as the authenticated session address, so a relay cannot
  redirect the connection to a third-party host.

### Attackers

- Passive network observers
- Active network attackers (MITM)
- Malicious peers
- Resource exhaustion attackers

## Security Features

### Cryptographic Primitives

| Primitive | Usage | Standard |
|-----------|-------|----------|
| Ed25519 | Peer identity, signatures | RFC 8032 |
| X25519 | ECDH key exchange | RFC 7748 |
| ChaCha20-Poly1305 | AEAD encryption | RFC 8439 |
| AES-256-GCM | AEAD encryption (QUIC) | NIST SP 800-38D |
| SHA-256/512 | Hashing, KDF | FIPS 180-4 |
| HKDF-SHA256 | Key derivation | RFC 5869 |

### Protocol Security

- **Noise XX**: Mutual authentication, forward secrecy, 1-RTT
- **Identity Binding**: libp2p public key + signature payload is
  encrypted in Noise XX messages 2/3 (`write_s` / `read_s`), so the
  Noise transport binds to the libp2p PeerID rather than just the
  static curve key.
- **Perfect Forward Secrecy**: Ephemeral keys discarded after handshake
- **Anti-replay**: Packet numbers prevent replay attacks. ChaCha20
  block counters cannot wrap into the IETF nonce; QUIC keys reject
  packet numbers outside the receive window.
- **TLS 1.3**: Both the inner libp2p extension signature and the outer
  X.509 self-signature on the leaf certificate are verified.
  `CertificateVerify` and `Finished` are checked in constant time.
- **Constant-time helpers**: `speer_ct_memeq` and curve-25519 branchless
  scalar multiplication are used on secret data; field functions
  marked "public-data-only" are only invoked on non-secret inputs
  (signature verification).
- **RNG hardening**: `speer_random_bytes_or_fail` returns an explicit
  error and zeroes the buffer when the OS RNG fails. Every key
  derivation, nonce, ephemeral, certificate, and Connection ID
  generation path now fails closed on RNG error.

## Known Limitations

### Current Implementation

- No certificate pinning for Web PKI mode
- No built-in peer reputation system
- No automatic key rotation
- Memory protections rely on OS (no secure heap)

### Not Implemented

- Constant-time AES-GCM for side-channel resistance
- Formal verification of crypto code
- Hardware security module (HSM) integration

## Security Best Practices

### For Applications

1. **Key Generation**: Use cryptographically secure random for seed values.
   Always check the return code of the RNG; the helper that returns
   an error is the canonical entry point:
   ```c
   uint8_t seed[32];
   if (speer_random_bytes_or_fail(seed, 32) != 0) {
       /* Refuse to derive any keys. */
       return -1;
   }
   ```

2. **Key Storage**: Persist keys encrypted, never plaintext
3. **Peer Verification**: Verify peer public keys out-of-band
4. **Timeouts**: Set appropriate handshake and keepalive timeouts

### For Deployment

1. Run with minimal privileges
2. Enable ASLR and DEP/NX
3. Use firewall rules to restrict ports
4. Monitor for unusual connection patterns
