# Contract: edTLS certificate v2

**Package**: `github.com/oluies/neverlur/edtls`
**Schema version**: 2 (was 1)
**Design note**: `docs/wire-edtls-cert-v2.md`

## X.509 layout

- Self-signed X.509v3 over Ed25519 (unchanged from v1 except for the additional extensions below).
- `SubjectPublicKeyInfo` carries the Ed25519 public key.
- Two new critical extensions:

| OID                          | Name                  | Contents                                  |
|------------------------------|-----------------------|-------------------------------------------|
| `1.3.6.1.4.1.<PEN>.1.1`      | `neverlur.pqPublicKey`| `OCTET STRING` of 1952-byte ML-DSA-65 pub |
| `1.3.6.1.4.1.<PEN>.1.2`      | `neverlur.pqSignature`| `OCTET STRING` of 3309-byte ML-DSA-65 sig |

`<PEN>` is the Private Enterprise Number assigned to the Neverlur project (TBD; the design note tracks the assignment). Until assigned, a placeholder under `1.3.6.1.4.1.99999.x.y` is used in test fixtures only; production certs require the assigned arc.

## PQ signature input

`pqSignature` is `mldsa65.Sign(skPQ, SHA-512(tbsCertificate) || pqPublicKeyBytes)`. The TBSCertificate is the standard X.509 `tbsCertificate` ASN.1 DER bytes (the bytes that the Ed25519 self-signature also covers). Including `pqPublicKeyBytes` in the signed message binds the PQ pub to the cert.

## Server contract

```go
func Listen(network, laddr string, id *HybridIdentity) (net.Listener, error)
func Server(conn net.Conn, id *HybridIdentity) *tls.Conn
func NewTLSServerConfig(id *HybridIdentity) *tls.Config
```

The `Listen`/`Server`/`NewTLSServerConfig` API takes a `*HybridIdentity` instead of `ed25519.PrivateKey`. A migration shim `NewTLSServerConfigLegacy(ed25519.PrivateKey)` is provided **only** during the pre-cutover window; it emits `event=pq.downgrade` on every accepted connection and is removed in the post-cutover release.

## Client contract

```go
func Dial(network, addr string, peer *HybridIdentityPublic, me *HybridIdentity) (*tls.Conn, error)
func Client(rawConn net.Conn, peer *HybridIdentityPublic, me *HybridIdentity) *tls.Conn
func NewTLSClientConfig(me *HybridIdentity, peer *HybridIdentityPublic) *tls.Config
```

`VerifyPeerCertificate` now:
1. Parses the cert.
2. Verifies the Ed25519 self-signature (as today).
3. Locates the two critical extensions; rejects if missing or unparseable.
4. Verifies `mldsa65.Verify(extPub, SHA-512(tbsCertificate) || extPub, extSig)`.
5. Asserts `cert.PublicKey == peer.EdPub` AND `extPub == peer.PQPub`.

Any failure returns `ErrVerificationFailed` (existing error, unchanged shape).

## Tests

`edtls/server_test.go` / `edtls/client_test.go`:
- `TestHybridHandshakeRoundtrip`
- `TestRejectClassicalOnlyCertAfterCutover`
- `TestRejectMissingPQExtension`
- `TestRejectForgedPQSignature`
- `TestRejectMismatchedPQKey` (cert presents a PQ key not matching `peer.PQPub`).
