#!/usr/bin/env php
<?php

/**
 * DIVE PoC — Sign helper
 *
 * Computes the DIVE signature for one or more files and prints the
 * base64-encoded signature ready to be pasted into signatures.json.
 *
 * Requirements:
 *   - PHP >= 8.1 with the sodium extension (ext-sodium)
 *
 * Usage:
 *   # Generate a new Ed25519 key pair (one-time setup)
 *   php sign.php --keygen
 *
 *   # Sign a file with an existing private key
 *   php sign.php --sign <file> --key <private-key-b64> \
 *                [--algo sha256|sha384|sha512] \
 *                [--key-id <id>] [--fqdn <fqdn>]
 *
 * The private key accepted by --key is either:
 *   - 32-byte seed (produced by --keygen, recommended)
 *   - 64-byte sodium secret key in seed||pubkey format (e.g. from the Python library)
 *     In this format the public key is the LAST 32 bytes (bytes 32–63).
 *     Never use substr($key, 0, 32) to extract it — that returns the seed.
 *     Use sodium_crypto_sign_publickey() or the equivalent in your library.
 * The matching 32-byte public key is what you publish in DNS.
 *
 * Signature input follows RFC 9421 (HTTP Message Signatures) over the
 * RFC 9530 Content-Digest header.
 */

declare(strict_types=1);

if (!extension_loaded('sodium')) {
    fwrite(STDERR, "Error: ext-sodium is required.\n");
    exit(1);
}

// ── Argument parsing ──────────────────────────────────────────────────────────

$args = array_slice($argv, 1);

function usage(): void
{
    echo <<<USAGE
    Usage:
      php sign.php --keygen
      php sign.php --sign <file> --key <private-key-b64> \
                   [--algo sha256|sha384|sha512] \
                   [--key-id <id>] [--fqdn <fqdn>]

    Options:
      --keygen          Generate a new Ed25519 key pair and print both
                        the private key (for this script) and the public
                        key (for DNS publication).
      --sign <file>     Path to the file to sign.
      --key  <b64>      Base64-encoded Ed25519 private key: 32-byte seed (current
                        --keygen output) or legacy 64-byte sodium secret key.
      --algo <algo>     Hash algorithm: sha256 (default), sha384, sha512.
      --key-id <id>     Key identifier to embed in Signature-Input (default: keyABC).
      --fqdn <fqdn>     FQDN qualifier; when present keyid becomes key-id@fqdn.

    USAGE;
}

if (in_array('--keygen', $args, true)) {
    doKeygen();
    exit(0);
}

$signIndex  = array_search('--sign',   $args);
$keyIndex   = array_search('--key',    $args);
$algoIndex  = array_search('--algo',   $args);
$keyIdIndex = array_search('--key-id', $args);
$fqdnIndex  = array_search('--fqdn',   $args);

if ($signIndex === false || $keyIndex === false) {
    usage();
    exit(1);
}

$filePath = $args[$signIndex + 1] ?? null;
$keyB64   = $args[$keyIndex  + 1] ?? null;
$hashAlgo = ($algoIndex  !== false) ? ($args[$algoIndex  + 1] ?? 'sha256') : 'sha256';
$keyId    = ($keyIdIndex !== false) ? ($args[$keyIdIndex + 1] ?? 'keyABC') : 'keyABC';
$fqdn     = ($fqdnIndex  !== false) ? ($args[$fqdnIndex  + 1] ?? null)     : null;

if ($filePath === null || $keyB64 === null) {
    usage();
    exit(1);
}

doSign($filePath, $keyB64, $hashAlgo, $keyId, $fqdn);
exit(0);

// ── Actions ───────────────────────────────────────────────────────────────────

function doKeygen(): void
{
    $keypair = sodium_crypto_sign_keypair();
    $secret  = sodium_crypto_sign_secretkey($keypair); // 64 bytes: seed (0–31) || pubkey (32–63)
    $seed    = substr($secret, 0, SODIUM_CRYPTO_SIGN_SEEDBYTES); // 32-byte seed — the private key
    $public  = sodium_crypto_sign_publickey($keypair);            // 32-byte public key

    echo "=== New Ed25519 key pair ===\n\n";
    echo "Private key / seed (keep secret — use with --key):\n";
    echo base64_encode($seed) . "\n\n";
    echo "Public key (publish in DNS key record, `key` parameter, wrapped in colons):\n";
    echo ':' . base64_encode($public) . ":\n\n";
    echo "DNS TXT record example:\n";
    echo sprintf(
        'keyABC._divekey.example.com.  900  IN  TXT  "sig=\"ed25519\", key=:%s:, cache=900"',
        base64_encode($public)
    ) . "\n";
}

function doSign(string $filePath, string $keyB64, string $hashAlgo, string $keyId, ?string $fqdn): void
{
    // ── Validate hash algorithm ───────────────────────────────────────────────
    $allowed = ['sha256', 'sha384', 'sha512'];
    if (!in_array($hashAlgo, $allowed, true)) {
        fwrite(STDERR, "Error: unsupported hash algorithm \"$hashAlgo\". Allowed: " . implode(', ', $allowed) . "\n");
        exit(1);
    }

    // ── Read the file ─────────────────────────────────────────────────────────
    if (!file_exists($filePath) || !is_readable($filePath)) {
        fwrite(STDERR, "Error: file \"$filePath\" not found or not readable.\n");
        exit(1);
    }

    $fileContent = file_get_contents($filePath);
    if ($fileContent === false) {
        fwrite(STDERR, "Error: could not read file \"$filePath\".\n");
        exit(1);
    }

    // ── Decode the private key and derive the 64-byte signing key ────────────────
    $keyDecoded = base64_decode($keyB64, strict: true);
    if ($keyDecoded === false) {
        fwrite(STDERR, "Error: --key is not valid base64.\n");
        exit(1);
    }
    if (strlen($keyDecoded) === SODIUM_CRYPTO_SIGN_SEEDBYTES) {
        // 32-byte seed — current format produced by --keygen
        $keypair = sodium_crypto_sign_seed_keypair($keyDecoded);
        $keyRaw  = sodium_crypto_sign_secretkey($keypair);
    } elseif (strlen($keyDecoded) === SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
        // 64-byte sodium secret key (seed||pubkey) — legacy format from old --keygen
        $keyRaw = $keyDecoded;
    } else {
        fwrite(STDERR, sprintf(
            "Error: --key must be a base64-encoded %d-byte seed or %d-byte Ed25519 secret key.\n",
            SODIUM_CRYPTO_SIGN_SEEDBYTES,
            SODIUM_CRYPTO_SIGN_SECRETKEYBYTES
        ));
        exit(1);
    }

    // ── Compute the RFC 9530 Content-Digest ──────────────────────────────────
    $digestRaw     = hash($hashAlgo, $fileContent, binary: true);
    $digestB64     = base64_encode($digestRaw);
    // RFC 9530 digest algorithm names use hyphens: sha256 → sha-256
    $rfcAlgo       = 'sha-' . substr($hashAlgo, 3);   // 'sha256' → 'sha-256'
    $contentDigest = sprintf('%s=:%s:', $rfcAlgo, $digestB64);

    // ── Build the RFC 9421 signature base ────────────────────────────────────
    // Signature-Input value for this single entry (label "sig1"):
    $keyPart       = $fqdn !== null ? sprintf('%s@%s', $keyId, $fqdn) : $keyId;
    $sigInputValue = sprintf('("content-digest");keyid="%s";alg="ed25519"', $keyPart);

    // RFC 9421 §2.5 signature base format:
    //   "<component-id>": <value>\n"@signature-params": <sig-input-value>
    $sigBase = sprintf(
        '"content-digest": %s' . "\n" . '"@signature-params": %s',
        $contentDigest,
        $sigInputValue
    );

    // ── Sign ──────────────────────────────────────────────────────────────────
    $signature = sodium_crypto_sign_detached($sigBase, $keyRaw);
    $sigB64    = base64_encode($signature);
    $basename  = basename($filePath);

    echo "=== DIVE signature for: $basename ===\n\n";
    echo "Hash algorithm  : $hashAlgo\n";
    echo "Content-Digest  : $contentDigest\n";
    echo "Signature (b64) : $sigB64\n\n";
    echo "signatures.json entry:\n";
    $entry = ['key_id' => $keyId, 'content_digest' => $contentDigest, 'signature_b64' => $sigB64];
    if ($fqdn !== null) {
        // Insert fqdn after key_id
        $entry = ['key_id' => $keyId, 'fqdn' => $fqdn, 'content_digest' => $contentDigest, 'signature_b64' => $sigB64];
    }
    echo json_encode($entry, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n\n";
    echo "Response headers (RFC 9421 / RFC 9530):\n";
    echo "Content-Digest: $contentDigest\n";
    echo "Signature-Input: sig1=$sigInputValue\n";
    echo "Signature: sig1=:$sigB64:\n";
}
