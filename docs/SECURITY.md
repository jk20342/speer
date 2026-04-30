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
- The peer's public key is correctly obtained out-of-band
- Network attackers can read, modify, and replay packets

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
- **Identity Binding**: Public keys authenticated via handshake
- **Perfect Forward Secrecy**: Ephemeral keys discarded after handshake
- **Anti-replay**: Packet numbers prevent replay attacks

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

1. **Key Generation**: Use cryptographically secure random for seed values
   ```c
   uint8_t seed[32];
   speer_random_bytes(seed, 32);  // Use this, not all zeros!
   ```

2. **Key Storage**: Persist keys encrypted, never plaintext
3. **Peer Verification**: Verify peer public keys out-of-band
4. **Timeouts**: Set appropriate handshake and keepalive timeouts

### For Deployment

1. Run with minimal privileges
2. Enable ASLR and DEP/NX
3. Use firewall rules to restrict ports
4. Monitor for unusual connection patterns
