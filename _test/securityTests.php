<?php

/*
 * Standalone assertion tests for the SECURITY PATCH changes.
 * Run:  php _test/securityTests.php
 *
 * No PHPUnit dependency (the project ships none); this mirrors the plain-PHP
 * style of the rest of _test/. Exit code is non-zero if any assertion fails.
 */

require_once __DIR__ . '/../src/WebAuthn.php';

use lbuchs\WebAuthn\WebAuthn;
use lbuchs\WebAuthn\WebAuthnException;
use lbuchs\WebAuthn\Binary\ByteBuffer;
use lbuchs\WebAuthn\CBOR\CborDecoder;

$failures = 0;
$passes = 0;

function check($label, $condition) {
    global $failures, $passes;
    if ($condition) {
        $passes++;
        echo "  PASS  $label\n";
    } else {
        $failures++;
        echo "  FAIL  $label\n";
    }
}

/**
 * Invoke the private _checkOrigin via reflection so we can test the matcher
 * in isolation for a given rpId.
 */
function originAllowed($rpId, $origin) {
    $wa = new WebAuthn('Test', $rpId, ['none']);
    $ref = new ReflectionMethod(WebAuthn::class, '_checkOrigin');
    $ref->setAccessible(true);
    return $ref->invoke($wa, $origin);
}

// ---------------------------------------------------------------------------
echo "\n[1] Origin matcher (WebAuthn::_checkOrigin)\n";
// legitimate origins must still be accepted
check('exact host accepted',              originAllowed('example.com', 'https://example.com') === true);
check('subdomain accepted',               originAllowed('example.com', 'https://login.example.com') === true);
check('deep subdomain accepted',          originAllowed('example.com', 'https://a.b.example.com') === true);
check('case-insensitive host accepted',   originAllowed('example.com', 'https://EXAMPLE.com') === true);
check('localhost http accepted',          originAllowed('localhost', 'http://localhost') === true);
// the vulnerability: sibling / suffix-lookalike domains must be rejected
check('sibling suffix domain rejected',   originAllowed('example.com', 'https://evilexample.com') === false);
check('prefix-attack domain rejected',    originAllowed('example.com', 'https://example.com.attacker.com') === false);
check('unrelated domain rejected',        originAllowed('example.com', 'https://attacker.com') === false);
check('http (non-localhost) rejected',    originAllowed('example.com', 'http://example.com') === false);
check('empty/garbage origin rejected',    originAllowed('example.com', 'not a url') === false);

// ---------------------------------------------------------------------------
echo "\n[2] CBOR recursion depth limit (CborDecoder)\n";
// A valid, shallow map still decodes.
// CBOR: 0xA1 (map, 1 pair) 0x00 (key 0) 0x01 (val 1)
$shallow = "\xA1\x00\x01";
$ok = false;
try {
    $decoded = CborDecoder::decode($shallow);
    $ok = is_array($decoded) && ($decoded[0] ?? null) === 1;
} catch (Throwable $e) {
    $ok = false;
}
check('shallow CBOR still decodes', $ok);

// Deeply nested tag chain (major type 6 = 0xC0) must throw, not crash.
// Build well past MAX_DEPTH (32) so it trips the guard; terminate with a uint.
$deep = str_repeat("\xC0", 200) . "\x00";
$threw = false;
try {
    CborDecoder::decode($deep);
} catch (WebAuthnException $e) {
    $threw = ($e->getCode() === WebAuthnException::CBOR);
}
check('deeply nested CBOR throws WebAuthnException (no crash)', $threw);

// Deeply nested arrays (0x81 = array of 1) must also throw.
$deepArr = str_repeat("\x81", 200) . "\x00";
$threwArr = false;
try {
    CborDecoder::decode($deepArr);
} catch (WebAuthnException $e) {
    $threwArr = true;
}
check('deeply nested arrays throw', $threwArr);

// ---------------------------------------------------------------------------
echo "\n[3] ByteBuffer serialization is not an object-injection gadget\n";
$buf = new ByteBuffer("hello\x00world");
$roundTrip = unserialize(serialize($buf));
check('ByteBuffer round-trips', $roundTrip instanceof ByteBuffer && $roundTrip->getBinaryString() === "hello\x00world");

// Craft a __serialize-style payload whose inner 'data' encodes another object.
// With allowed_classes=false the inner object must NOT be instantiated.
class _SecTestGadget { public static $touched = false; public function __wakeup() { self::$touched = true; } }
$maliciousInner = serialize(new _SecTestGadget());
$ref = new ReflectionMethod(ByteBuffer::class, '__unserialize');
$ref->setAccessible(true);
$victim = (new ReflectionClass(ByteBuffer::class))->newInstanceWithoutConstructor();
$ref->invoke($victim, ['data' => $maliciousInner]);
check('inner object NOT instantiated during unserialize', _SecTestGadget::$touched === false);
check('blocked gadget payload coerced to empty string', $victim->getBinaryString() === '');

// ---------------------------------------------------------------------------
echo "\n[4] FIDO MDS JWS signature verification\n";
// Generate a throwaway RSA key + self-signed cert, build a valid RS256 JWS,
// and confirm the verifier accepts it and rejects a tampered payload.
$rsa = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
if ($rsa === false) {
    check('openssl RSA keygen available', false);
} else {
    $csr = openssl_csr_new(['commonName' => 'mds-test'], $rsa, ['digest_alg' => 'sha256']);
    $x509 = openssl_csr_sign($csr, null, $rsa, 1, ['digest_alg' => 'sha256']);
    openssl_x509_export($x509, $certPem);
    // strip PEM armor to DER-base64 for the x5c entry
    $x5c = preg_replace('/-----[^-]+-----|\s+/', '', $certPem);

    $b64url = function ($bin) { return rtrim(strtr(base64_encode($bin), '+/', '-_'), '='); };
    $header64 = $b64url(json_encode(['alg' => 'RS256', 'x5c' => [$x5c]]));
    $payload64 = $b64url(json_encode(['entries' => []]));
    $signingInput = $header64 . '.' . $payload64;
    openssl_sign($signingInput, $sig, $rsa, OPENSSL_ALGO_SHA256);
    $sig64 = $b64url($sig);

    $wa = new WebAuthn('Test', 'example.com', ['none']);
    $verify = new ReflectionMethod(WebAuthn::class, '_verifyMetadataBlobSignature');
    $verify->setAccessible(true);

    // valid signature: must NOT throw (no root pinning -> signature-only check)
    $validOk = false;
    try {
        $verify->invoke($wa, $header64, $payload64, $sig64, null);
        $validOk = true;
    } catch (Throwable $e) {
        $validOk = false;
    }
    check('valid RS256 MDS JWS passes signature check', $validOk);

    // tampered payload: must throw INVALID_SIGNATURE
    $tampered64 = $b64url(json_encode(['entries' => [['evil' => true]]]));
    $tamperCaught = false;
    try {
        $verify->invoke($wa, $header64, $tampered64, $sig64, null);
    } catch (WebAuthnException $e) {
        $tamperCaught = ($e->getCode() === WebAuthnException::INVALID_SIGNATURE);
    }
    check('tampered MDS payload rejected', $tamperCaught);

    // chain pinned to an unrelated root: must throw CERTIFICATE_NOT_TRUSTED
    $otherKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    $otherCsr = openssl_csr_new(['commonName' => 'other-root'], $otherKey, ['digest_alg' => 'sha256']);
    $otherX509 = openssl_csr_sign($otherCsr, null, $otherKey, 1, ['digest_alg' => 'sha256']);
    openssl_x509_export($otherX509, $otherRootPem);
    $pinCaught = false;
    try {
        $verify->invoke($wa, $header64, $payload64, $sig64, $otherRootPem);
    } catch (WebAuthnException $e) {
        $pinCaught = ($e->getCode() === WebAuthnException::CERTIFICATE_NOT_TRUSTED);
    }
    check('MDS chain not matching pinned root rejected', $pinCaught);
}

// ---------------------------------------------------------------------------
echo "\n[5] ES256 raw->DER signature conversion\n";
$ec = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
if ($ec === false) {
    check('openssl EC keygen available', false);
} else {
    $csr = openssl_csr_new(['commonName' => 'es256-test'], $ec, ['digest_alg' => 'sha256']);
    $x509 = openssl_csr_sign($csr, null, $ec, 1, ['digest_alg' => 'sha256']);
    openssl_x509_export($x509, $certPem);
    $x5c = preg_replace('/-----[^-]+-----|\s+/', '', $certPem);

    $b64url = function ($bin) { return rtrim(strtr(base64_encode($bin), '+/', '-_'), '='); };
    $header64 = $b64url(json_encode(['alg' => 'ES256', 'x5c' => [$x5c]]));
    $payload64 = $b64url(json_encode(['entries' => []]));
    $signingInput = $header64 . '.' . $payload64;

    // openssl_sign yields DER ECDSA; convert to raw R||S the way JWS carries it.
    openssl_sign($signingInput, $derSig, $ec, OPENSSL_ALGO_SHA256);
    // parse DER SEQUENCE { INTEGER r, INTEGER s } -> fixed 32-byte r||s
    $off = 2; // skip SEQ tag+len (short form for P-256)
    $rLen = ord($derSig[$off + 1]); $r = substr($derSig, $off + 2, $rLen);
    $off = $off + 2 + $rLen;
    $sLen = ord($derSig[$off + 1]); $s = substr($derSig, $off + 2, $sLen);
    $r = ltrim($r, "\x00"); $s = ltrim($s, "\x00");
    $rawSig = str_pad($r, 32, "\x00", STR_PAD_LEFT) . str_pad($s, 32, "\x00", STR_PAD_LEFT);
    $sig64 = $b64url($rawSig);

    $wa = new WebAuthn('Test', 'example.com', ['none']);
    $verify = new ReflectionMethod(WebAuthn::class, '_verifyMetadataBlobSignature');
    $verify->setAccessible(true);
    $es256Ok = false;
    try {
        $verify->invoke($wa, $header64, $payload64, $sig64, null);
        $es256Ok = true;
    } catch (Throwable $e) {
        $es256Ok = false;
    }
    check('valid ES256 (raw R||S) MDS JWS passes after DER conversion', $es256Ok);
}

// ---------------------------------------------------------------------------
echo "\n----------------------------------------\n";
echo "Passed: $passes   Failed: $failures\n";
exit($failures === 0 ? 0 : 1);
