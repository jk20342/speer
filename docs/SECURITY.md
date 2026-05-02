# security

speer is still young, so treat it like experimental networking code. it has
real crypto and a real threat model, but it has not had a third-party security
audit.

## supported versions

`0.1.x` is the supported line.

## reporting

please report security issues privately to the maintainers first. do not post a
public issue with exploit details until there is a fix or mitigation.

## what speer tries to protect

- private identity keys, mainly ed25519/libp2p keys and noise static keys
- payload confidentiality and integrity after the handshake
- peer identity binding, so a session is tied to the expected key or peer id
- protocol state, so malformed packets do not casually walk the state machines

## threat model

assume the network is hostile. attackers can read packets, modify packets,
replay packets, race discovery records, and open lots of connections.

do not assume discovery is trust. mdns and dht records are hints. a peer still
needs to complete noise xx or tls/libp2p authentication before the app should
treat it as that peer.

do assume the local machine is trusted. speer does not try to defend against a
compromised host process, debugger, swap inspection, or a malicious app using
the library incorrectly.

## crypto used

- ed25519 for identity signatures
- x25519 for key agreement
- chacha20-poly1305 for noise traffic
- aes-gcm for quic/tls paths, with accelerated code where available
- sha-256 / sha-384 / sha-512 and hkdf for hashing and key schedule work
- rsa and ecdsa-p256 support for the optional web pki path

the project keeps these implementations in-tree and does not depend on openssl
or libsodium for the core library.

## protocol security

- noise xx is used for the main authenticated key exchange.
- libp2p noise carries the signed libp2p payload in `write_s` / `read_s`, so the
  session binds to the peer id instead of only a raw static curve key.
- packet numbers, stream state, and frame lengths are checked before data is
  accepted.
- `speer_ct_memeq` is used for constant-time tag and mac comparisons.
- `speer_random_bytes_or_fail` is the fallible rng helper. connection ids,
  tls/quic randomness, dht token secrets, and generated keys use the fail-closed
  path where the code needs a hard failure.

## tls and web pki

tls 1.3 and web pki code exists, but web pki is optional in cmake:

```bash
cmake -S . -B build -DSPEER_ENABLE_WEBPKI=ON
```

when a ca bundle is supplied, the web pki path verifies the chain, critical
extensions, key usage / extended key usage, and path length constraints. without
a ca bundle, libp2p tls identity checks can authenticate the peer id, but that
does not prove a dns name.

certificate pinning is not built in.

## discovery, relay, and dcutr

- mdns records are untrusted hints.
- dht store values are bounded by `DHT_VALUE_MAX_SIZE`, and store tokens are
  hmac-bound to the sender address.
- circuit relay state is tied to authenticated peer ids.
- dcutr is partial. the current candidate trust check is ipv4-only and only
  accepts candidates in the same `/24` as the authenticated session address.

## resource limits

the public api has built-in caps like `SPEER_MAX_PACKET_SIZE`,
`SPEER_MAX_PEERS`, and `SPEER_MAX_STREAMS`. the tcp helper layer also has
connection and accept-rate limits.

this is not full ddos protection. production apps should still add their own
limits, logging, backoff, and firewall rules.

## current gaps

- no formal verification
- no third-party audit
- no secure heap or locked memory
- no automatic key rotation
- no peer reputation / ban list beyond local rate limits
- no certificate pinning
- quic and relay/dcutr are not full production stacks yet

## app guidance

use `speer_random_bytes_or_fail` for seeds and refuse to start if it fails:

```c
uint8_t seed[32];
if (speer_random_bytes_or_fail(seed, sizeof(seed)) != 0) {
    return -1;
}
```

store long-term keys encrypted. verify peer ids or public keys through a channel
your app trusts. run the host from one event-loop thread unless the specific
component says otherwise.

for deployments, run with minimal privileges, keep ports narrow, enable normal
platform hardening like aslr/dep, and monitor connection spikes.
