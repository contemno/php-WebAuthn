# Security Review & Secure Downstream Usage

This document is a security review of this vendored copy of
[`lbuchs/WebAuthn`](https://github.com/lbuchs/WebAuthn) and a checklist for consuming it
safely in a downstream application. It also records the defensive patches applied to this
copy (search the source for `SECURITY PATCH`).

> **Maintenance note.** Upstream is only lightly maintained (2 commits in 2025, both minor).
> Treat this as a pinned dependency: review upstream diffs before bumping, and re-apply the
> patches below if you rebase onto a newer upstream.

## Executive summary

The library's **core assertion/registration verification is largely sound**: challenges are
generated with `random_bytes` (32 bytes / 256 bits), the challenge / `type` / `rpIdHash`
checks are strict and type-safe, `openssl_verify(...) === 1` correctly treats the `-1` error
return as failure, COSE public-key parameters are strictly length-validated, and every
`ByteBuffer` read accessor is bounds-checked.

The weaknesses are concentrated in four areas: (1) one clear verification bug (origin
matching), (2) attestation trust that is almost entirely opt-in and can be undermined even
when enabled, (3) parser/serialization hardening gaps, and (4) an insecure example
(`_test/server.php`) that is widely copied. The most security-relevant items have been
patched in this copy; several deeper attestation-completeness gaps remain and must be
compensated for at the integration layer (see [Residual gaps](#residual-gaps)).

## Findings

Severity reflects impact **as a downstream dependency**. "Patched" means fixed in this copy;
"Integrator" means you must handle it in your application.

### High

| # | Finding | Location | Status |
|---|---------|----------|--------|
| H1 | **Origin match was an unanchored suffix regex.** `preg_match('/'.preg_quote($rpId).'$/i', $host)` has no start anchor and no dot boundary, so `evilexample.com` matched rpId `example.com`. Browsers enforce the true rule, so this is primarily a defense-in-depth failure, but any non-browser / native / relaxed client relying on the server check was bypassable. | `WebAuthn.php` `_checkOrigin` | **Patched** — now `host === rpId \|\| str_ends_with($host, '.'.$rpId)`, case-insensitive, with an empty-host guard. |
| H2 | **Attacker-supplied x5c intermediates were trusted as CA anchors.** Every `validateRootCertificate` appended the attacker's chain file to the *trusted* CA argument (3rd) of `openssl_x509_checkpurpose`; `_createX5cChainFile` only filters self-signed certs (a weak SKI/AKI string heuristic). A non-self-signed attacker intermediate could become a trust anchor, defeating root pinning **even when roots are configured**. | `Packed/Tpm/U2f/Apple/AndroidKey/AndroidSafetyNet` + `FormatBase::_createX5cChainFile` | **Patched** — the chain is now passed as the 4th *untrusted* argument. |
| H3 | **CBOR decoder had no recursion-depth limit.** Repeated tag/array/map bytes drive one recursion level per byte; a few-KB `attestationObject` could exhaust the PHP stack and crash the worker (DoS). | `CborDecoder.php` | **Patched** — depth is bounded (`MAX_DEPTH = 32`) and exceeding it throws. |

### Medium

| # | Finding | Location | Status |
|---|---------|----------|--------|
| M1 | **`ByteBuffer` was a PHP object-injection gadget.** `_data` is always a string, yet it was `serialize()`d and then `unserialize()`d again with no `allowed_classes`, so unserializing a crafted `ByteBuffer` could instantiate arbitrary objects (POP chain). | `ByteBuffer.php` `unserialize` / `__unserialize` | **Patched** — `['allowed_classes' => false]` on both, non-string results coerced to empty. |
| M2 | **FIDO MDS JWS signature was never verified.** `queryFidoMetaDataService` split the signed BLOB but used only the payload; trust rested on TLS alone, so a MITM/TLS-strip could inject arbitrary attestation roots. | `WebAuthn.php` `queryFidoMetaDataService` | **Patched** — signature verified against the embedded `x5c` (RS256/ES256, with raw→DER for ECDSA); pass `$jwtRootCertificates` to also pin the chain to the FIDO/GlobalSign root. |
| M3 | **Attestation trust is opt-in and silently degrades.** With no `addRootCertificates()` call, root validation is skipped and *any* attestation cert is accepted; `none` (`None::validateAttestation` returns `true`) and self-attestation are accepted with no restriction on which format a client may send. `checkpurpose(..., -1, ...)` disables EKU enforcement; no revocation (CRL/OCSP) anywhere. | `WebAuthn.php` / `None.php` | **Integrator** — see checklist. |
| M4 | **AndroidSafetyNet has no timestamp/freshness check** and validates the leaf only by CN string; the response is replayable. (SafetyNet is also deprecated by Google.) | `AndroidSafetyNet.php` | **Integrator** — prefer not enabling this format. |
| M5 | **TPM never binds `pubArea` to the credential key**; **Packed/AndroidKey omit spec-mandated cert checks** (alg↔key binding, AAGUID extension, Android key-attestation extension/challenge). AAGUID is never cross-checked against the attestation cert. | `Tpm.php`, `Packed.php`, `AndroidKey.php` | **Integrator** — see [Residual gaps](#residual-gaps). |
| M6 | **The example `_test/server.php` teaches insecure patterns**: echoes raw exception messages, never invalidates the session challenge after use, trusts fully client-controlled `userId`/`userName`, disables clone detection (`prevSignatureCnt=null`) and root-mismatch failure (`failIfRootMismatch=false`), and its state-changing GET endpoints have no CSRF/origin guard. | `_test/server.php` | **Integrator** — do not copy verbatim. |

### Low / Informational

- Challenge and `rpIdHash` comparisons are type-safe but **not constant-time** (`hash_equals`
  unused). Low practical risk — the values are non-secret / single-use.
- **Clone detection and credential→user binding are opt-in / delegated.** `prevSignatureCnt`
  defaults to `null` (no check); `allowCredentials` / `userHandle` ownership are marked
  "TO BE VERIFIED BY IMPLEMENTATION". Challenge single-use/expiry is entirely the caller's job.
- **User-verification enforcement is decoupled from the args.** Requesting
  `userVerification: 'required'` in `getGetArgs`/`getCreateArgs` does **not** enforce it — you
  must also pass `requireUserVerification=true` to `processGet`/`processCreate`.
- CBOR duplicate map keys are accepted (`// todo dup`); `ByteBuffer::fromBase64Url` uses
  non-strict `base64_decode` so its `=== false` guard is dead code; `composer.json` floor
  `php >=8.0` permits end-of-life PHP 8.0/8.1.

## Using this library securely downstream

A checklist for integrators. The library gives you primitives; several controls are your
responsibility.

**Ceremony & challenge**
- Construct a **fresh `WebAuthn` instance per ceremony**. Store `getChallenge()` server-side
  (session or DB), bind it to the user/session, enforce **single use and a short expiry**, and
  **delete it immediately after** `processCreate`/`processGet` — the library does not.

**Attestation**
- Restrict `$allowedFormats` (constructor) to exactly what you need. **Do not accept `none`**
  if you rely on attestation for anything.
- If attestation assurance matters, call `addRootCertificates()` with the vendor roots and
  keep `failIfRootMismatch=true` (its default) in `processCreate`. Without this, attestation
  certificates are self-asserted and prove nothing.
- Be aware attestation from **TPM / Packed / AndroidKey / SafetyNet** is weaker than the spec
  requires here (see [Residual gaps](#residual-gaps)); do not treat their AAGUID/model claims
  as authenticated. Prefer not enabling **android-safetynet** (deprecated, replayable).

**User & key checks**
- Always pass `requireUserPresent=true`, and `requireUserVerification=true` wherever you need
  UV — the args-level `userVerification` setting is **not** enforced on its own.
- **Persist the signature counter** and pass `prevSignatureCnt` on every `processGet` so clone
  detection actually runs; decide your policy on a regression (block / step-up).
- **Enforce credential-ID → user binding and `userHandle` ownership yourself** — the library
  explicitly delegates these ("TO BE VERIFIED BY IMPLEMENTATION"). Look up the public key by
  the asserted credential ID *scoped to the authenticating user*, never globally.

**Transport & wrapper**
- Serve over **HTTPS only**; add **CSRF protection** on the ceremony endpoints; cap request
  body size (mitigates the CBOR-recursion DoS class); return **generic error messages** to
  clients (do not echo `WebAuthnException::getMessage()`).
- **Do not copy `_test/server.php` verbatim.** It is a demo and disables several of the
  controls above.

**Metadata service**
- If you use `queryFidoMetaDataService`, pass the FIDO Alliance / GlobalSign root as
  `$jwtRootCertificates` so the downloaded BLOB's signature chain is pinned, not just
  TLS-protected. This repo ships `_test/rootCertificates/globalSign.pem`.

**Platform hygiene**
- **Never `unserialize()` untrusted data** into these classes (patched, but do not rely on it).
- Pin PHP to a **supported version** (8.2+ at time of writing; the composer floor permits EOL
  8.0/8.1).
- Pin this library version and review upstream diffs before upgrading, given low maintenance.

## Residual gaps

These are real deviations from the WebAuthn spec that were **not** patched here (they require
larger, format-specific changes and careful test vectors). Compensate at the integration
layer — e.g. by restricting `$allowedFormats`, enforcing root pinning, and not trusting
unauthenticated AAGUID/model metadata:

- **TPM** (`Tpm.php`): `pubArea` is never bound to the credential public key, and
  `certInfo.attested.name` is not verified — the TPM statement is not tied to the credential key.
- **Packed** (`Packed.php`): self-attestation does not verify `alg` matches the credential
  key's algorithm; full attestation does not verify the `id-fido-gen-ce-aaguid` extension
  against `authData`'s AAGUID, nor Basic Constraints / cert version.
- **AndroidKey** (`AndroidKey.php`): the Android key-attestation extension
  (`1.3.6.1.4.1.11129.2.1.17`) is not parsed — no `attestationChallenge == clientDataHash`
  check, no `allApplications`/origin/purpose constraints, no AAGUID binding.
- **AndroidSafetyNet** (`AndroidSafetyNet.php`): no `timestampMs` freshness window; leaf
  identity is only a CN string check.
- **General**: no certificate revocation checking (CRL/OCSP); `checkpurpose(..., -1, ...)`
  performs no EKU/purpose enforcement.

## Applied patches (this copy)

All are tagged `SECURITY PATCH` in-source and covered by `_test/securityTests.php`:

1. `WebAuthn.php` — exact-or-dotted-suffix origin match (H1).
2. `Packed/Tpm/U2f/Apple/AndroidKey/AndroidSafetyNet.php` — attacker x5c chain moved to the
   untrusted argument of `openssl_x509_checkpurpose` (H2).
3. `CborDecoder.php` — recursion depth bound (H3).
4. `ByteBuffer.php` — `allowed_classes => false` on unserialize (M1).
5. `WebAuthn.php` — FIDO MDS JWS signature verification with optional root pinning (M2).

Run the tests with:

```sh
php _test/securityTests.php
```
