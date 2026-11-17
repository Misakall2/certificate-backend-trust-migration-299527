# Certificate verification backends

forge can verify X.509 certificate signatures through one of two
explicitly selectable backends. Chain policy (validity period,
issuer/subject matching, key usage, basic constraints, path length
constraints, name constraints, critical extension handling) is
implemented once in `pki.verifyCertificateChain()` and is shared by
both backends, so a given chain produces a comparable conclusion on
either backend. Certificate *issuance* (signing) is unchanged and does
not depend on the selected backend.

## Backends

| Backend | Implementation | Runtime |
| --- | --- | --- |
| `forge` (default) | Pure JavaScript (existing forge code) | Every runtime forge supports, including browsers |
| `node` | Node.js built-in `crypto` (`crypto.X509Certificate`, `KeyObject`) | Node.js >= 15.6 (developed and tested on Node 24) |

The default is `forge`; existing code behaves as before unless a
backend is explicitly selected.

No new package dependencies were added. The `node` backend only uses
the Node.js built-in `crypto` module. In browser builds the `crypto`
module is mapped to `false` (see the `browser` field in
`package.json`), so the backend simply reports itself as unavailable.

## Selecting a backend

```js
var forge = require('node-forge');
var pki = forge.pki;

// per chain verification call
pki.verifyCertificateChain(caStore, chain, {
  verificationBackend: 'node',   // 'forge' (default), 'node', or a
                                 // custom backend object
  validityCheckDate: new Date()  // optional injected verification time
});

// single signature check
pki.verifyCertificateSignature(issuerCert, cert, {backend: 'node'});

// availability check
if(!pki.getCertificateVerificationBackend('node').isAvailable()) {
  // fall back explicitly, in application code
}
```

See `examples/verify-backend.js` for a runnable version.

There is **no implicit fallback**: when a backend is selected and the
verification fails or the backend rejects a certificate, the failure is
reported; it is never retried with another backend. Falling back is a
policy decision left to the caller.

The `node` backend accepts forge certificate objects, PEM strings, and
DER encodings (binary string, `Buffer`, or `Uint8Array`). Accepting raw
encodings allows certificates whose public key algorithm the pure-JS
parser cannot represent (for example ECDSA) to be verified. The `forge`
backend accepts forge certificate objects and PEM strings.

## Algorithm scope

The `node` backend verifies signatures using a fixed allowlist:

| Algorithm | OID | Notes |
| --- | --- | --- |
| SHA-256/384/512 with RSA (PKCS#1 v1.5) | 1.2.840.113549.1.1.11/12/13 | |
| RSASSA-PSS | 1.2.840.113549.1.1.10 | parameters must satisfy the policy below |
| ECDSA with SHA-256/384/512 | 1.2.840.10045.4.3.2/3/4 | only verifiable with the `node` backend |

RSASSA-PSS parameters carried by a certificate must satisfy a fixed
policy: hash is SHA-256/384/512, the mask generation function is MGF1
with the same hash, and the salt length is at least 20 octets. A
certificate may not weaken the policy through its own parameters;
violations are rejected with
`forge.pki.InsecureSignatureParameters` even when the signature itself
is cryptographically valid. An empty or absent PSS parameter block
means the RFC 4056 defaults (SHA-1) and is therefore rejected.

Rejected by the `node` backend allowlist (verified by the `forge`
backend where forge supports them): MD5-with-RSA, SHA-1-with-RSA,
ECDSA-with-SHA-1/SHA-224, DSA, and anything else not listed above.

The `forge` backend supports what forge has always supported: RSA
PKCS#1 v1.5 with MD5/SHA-1/SHA-256/384/512 and RSASSA-PSS. It cannot
parse non-RSA public keys; combinations it does not support are
reported explicitly (see error codes) rather than failing silently.

## Error codes

Backend errors are `Error` objects with a `code` from
`pki.certificateVerificationError` and a `stage` (`backend`, `import`,
`parse`, or `verify`). `pki.isCertificateVerificationError(e)`
identifies them. Error objects never contain private key material.

| Code | Meaning |
| --- | --- |
| `forge.pki.VerificationBackendUnavailable` | The selected backend is not usable in this runtime (eg: `node` backend in a browser or Node.js < 15.6) |
| `forge.pki.CertificateParseFailed` | The certificate encoding could not be parsed |
| `forge.pki.UnsupportedSignatureAlgorithm` | The signature algorithm is not supported / not allowed by the selected backend |
| `forge.pki.UnsupportedKeyAlgorithm` | The public key algorithm is not supported by the selected backend |
| `forge.pki.InsecureSignatureParameters` | RSASSA-PSS parameters violate the fixed policy |

A signature *mismatch* is not an error: signature verification returns
`false`, and chain verification reports
`pki.certificateError.bad_certificate` with `verifyBackend` and `stage`
fields identifying which backend reported it. Parse failure,
unsupported algorithm, and signature mismatch are therefore always
distinguishable.

## Caching

The `node` backend caches **immutable parse results only**: imported
certificate records (DER encoding, signature parameters, key usage,
native key handle), keyed by the SHA-256 fingerprint of the certificate
DER, and native keys keyed by the SHA-256 fingerprint of the subject
public key info. It never caches verification outcomes, never keys
anything by subject/issuer name (two certificates with the same name
but different keys are distinct entries), and never shares entries
across backends — each backend instance has its own private cache, so
no success judgment made by one backend can be reused by another.
`backend.clearCache()` empties the cache.

## Trust chain validation

Chain building and policy checks remain in
`pki.verifyCertificateChain()`:

- Trust anchors come only from the caller-provided CA store. A
  certificate being self-signed, or a root name appearing in the chain,
  does not establish trust.
- The verification time is injectable via
  `options.validityCheckDate` (pass `null` to skip validity checks).
  Every layer checks validity period, issuer/subject relationship, key
  usage, basic constraints, and path length constraints, plus name
  constraints and unsupported critical extensions.
- When several CA store entries share a subject name (eg: cross-signed
  roots), candidates are tried in store order, each in isolation — a
  failed candidate does not affect the others. The number of candidates
  tried per certificate is bounded deterministically by
  `options.maxIssuerCandidates` (default 8).

## Differences between backends (migration checklist) and rollback

For chains using RSA with SHA-2 signatures — the common case — both
backends reach the same conclusion. Known, intentional differences:

1. SHA-1 and MD5 signature algorithms verify on the `forge` backend
   but are rejected by the `node` backend allowlist with
   `forge.pki.UnsupportedSignatureAlgorithm`.
2. ECDSA certificates can only be parsed/verified by the `node`
   backend; the `forge` backend reports
   `forge.pki.UnsupportedKeyAlgorithm`.
3. RSASSA-PSS certificates whose parameters use SHA-1 (including an
   empty/absent parameter block, i.e. the RFC 4056 defaults) are
   rejected by the `node` backend policy. Note the pure-JS parser
   additionally cannot parse certificates with an *empty* PSS parameter
   block at all (`forge.pki.CertificateParseFailed` on the `forge`
   backend) — a pre-existing limitation, not a behavior change.
4. Typed backend errors (unsupported algorithm, unavailable backend)
   propagate out of `pki.verifyCertificateChain()` instead of being
   swallowed as a generic verification failure, so the cause is
   attributable to a specific policy or backend capability. With the
   default `forge` backend this only affects chains containing
   certificates whose signature algorithms forge does not support,
   which previously failed opaquely as well.

Rollback: the default backend is unchanged (`forge`), so existing code
needs no changes. To roll back a migration, remove the
`verificationBackend` option (or set it to `'forge'`); no other code
changes are required. To remove the feature entirely, revert the commit
that introduced it — all changes are additive to `lib/` plus tests,
docs, and examples.

## Tests

`tests/unit/x509-verify-backend.js` covers: expired certificates, wrong
signatures, untrusted roots, self-signed certificates not in the trust
store, intermediate constraints (path length, key usage), algorithm
rejection (SHA-1/MD5, insecure PSS parameters), backend unavailability,
cross-signed candidate bounds, cache semantics, absence of implicit
fallback in both directions, and comparable conclusions across backends
for the same valid and invalid chains. RSA chains are generated locally
at test time; ECDSA and RSASSA-PSS certificates are fixed fixtures
(`tests/unit/x509-verify-backend-fixtures.js`) generated locally with
`tests/support/generate-x509-verify-fixtures.sh`. No certificates are
downloaded and no real service is contacted. Tests that require the
`node` backend are skipped automatically in browser (karma) runs, where
the `forge`-backend tests continue to verify the pure-JS path.
