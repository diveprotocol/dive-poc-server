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
 *   php sign.php --sign <file> --key <private-key-b64> [--algo sha256|sha384|sha512]
 *
 * The private key is expected as a raw base64-encoded 64-byte Ed25519
 * seed+public-key pair as produced by sodium_crypto_sign_keypair().
 * The public key (first 32 bytes) is what you publish in DNS.
 *
 * Signature input follows the DIVE spec (§ Signature Input Construction):
 *   input = hash_algorithm_name || ":" || hash_bytes_raw
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
      php sign.php --sign <file> --key <private-key-b64> [--algo sha256|sha384|sha512]

    Options:
      --keygen          Generate a new Ed25519 key pair and print both
                        the private key (for this script) and the public
                        key (for DNS publication).
      --sign <file>     Path to the file to sign.
      --key  <b64>      Base64-encoded 64-byte Ed25519 private key (seed||pub).
      --algo <algo>     Hash algorithm: sha256 (default), sha384, sha512.

    USAGE;
}

if (in_array('--keygen', $args, true)) {
    doKeygen();
    exit(0);
}

$signIndex = array_search('--sign', $args);
$keyIndex  = array_search('--key',  $args);
$algoIndex = array_search('--algo', $args);

if ($signIndex === false || $keyIndex === false) {
    usage();
    exit(1);
}

$filePath   = $args[$signIndex + 1] ?? null;
$keyB64     = $args[$keyIndex  + 1] ?? null;
$hashAlgo   = ($algoIndex !== false) ? ($args[$algoIndex + 1] ?? 'sha256') : 'sha256';

if ($filePath === null || $keyB64 === null) {
    usage();
    exit(1);
}

doSign($filePath, $keyB64, $hashAlgo);
exit(0);

// ── Actions ───────────────────────────────────────────────────────────────────

function doKeygen(): void
{
    $keypair = sodium_crypto_sign_keypair();
    $secret  = sodium_crypto_sign_secretkey($keypair); // 64 bytes: seed || pub
    $public  = sodium_crypto_sign_publickey($keypair); // 32 bytes

    echo "=== New Ed25519 key pair ===\n\n";
    echo "Private key (keep secret — use with --key):\n";
    echo base64_encode($secret) . "\n\n";
    echo "Public key (publish in DNS key record, `key` parameter, wrapped in colons):\n";
    echo ':' . base64_encode($public) . ":\n\n";
    echo "DNS TXT record example:\n";
    echo sprintf(
        'keyABC._divekey.example.com.  900  IN  TXT  "sig=\"ed25519\", key=:%s:, allowed-hash=(\"sha256\" \"sha384\"), cache=900"',
        base64_encode($public)
    ) . "\n";
}

function doSign(string $filePath, string $keyB64, string $hashAlgo): void
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

    // ── Decode the private key ────────────────────────────────────────────────
    $keyRaw = base64_decode($keyB64, strict: true);
    if ($keyRaw === false || strlen($keyRaw) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
        fwrite(STDERR, sprintf(
            "Error: private key must be a base64-encoded %d-byte Ed25519 secret key.\n",
            SODIUM_CRYPTO_SIGN_SECRETKEYBYTES
        ));
        exit(1);
    }

    // ── Compute the digest ────────────────────────────────────────────────────
    $phpAlgo    = str_replace('sha', 'sha', $hashAlgo); // sha256 → sha256 (php hash() name)
    $digestRaw  = hash($phpAlgo, $fileContent, binary: true);

    // ── Build the signature input per the DIVE spec ───────────────────────────
    //   input = hash_algorithm_name || ":" || hash_bytes_raw
    $sigInput = $hashAlgo . ':' . $digestRaw;

    // ── Sign ──────────────────────────────────────────────────────────────────
    $signature = sodium_crypto_sign_detached($sigInput, $keyRaw);

    $sigB64      = base64_encode($signature);
    $digestB64   = base64_encode($digestRaw);
    $basename    = basename($filePath);

    echo "=== DIVE signature for: $basename ===\n\n";
    echo "Hash algorithm : $hashAlgo\n";
    echo "Digest (base64): $digestB64\n";
    echo "Signature (b64): $sigB64\n\n";
    echo "signatures.json entry:\n";
    echo json_encode([
        'key_id'          => 'keyABC',
        'fqdn'            => 'example.com',
        'hash_algorithm'  => $hashAlgo,
        'signature_b64'   => $sigB64,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n\n";
    echo "DIVE-Sig header value (no @fqdn qualifier):\n";
    echo "keyABC:$hashAlgo:$sigB64\n";
}
