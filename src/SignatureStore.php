<?php

/**
 * DIVE PoC — SignatureStore
 *
 * Reads signatures.json and exposes per-file signature data.
 *
 * Expected JSON structure
 * ───────────────────────
 * {
 *   "filename.ext": {
 *     "signatures": [
 *       {
 *         "key_id":        "keyABC",
 *         "fqdn":          "example.com",        // optional; omit for no @fqdn qualifier
 *         "hash_algorithm": "sha256",             // sha256 | sha384 | sha512
 *         "signature_b64": "<base64-encoded raw signature bytes>"
 *       }
 *     ]
 *   }
 * }
 *
 * The "fqdn" field is optional.  When present the DIVE-Sig entry will be
 * emitted as `keyID@fqdn:hash-algorithm:BASE64SIG`.
 *
 * Multiple entries in "signatures" map to multiple comma-separated entries
 * in the DIVE-Sig header (as required by the spec for multi-key scenarios).
 */

declare(strict_types=1);

class SignatureStore
{
    /** @var array<string, array{signatures: list<array{key_id: string, fqdn?: string, hash_algorithm: string, signature_b64: string}>}> */
    private array $data;

    public function __construct(private readonly string $storePath)
    {
        $this->data = $this->load();
    }

    // ── Public API ─────────────────────────────────────────────────────────────

    /**
     * Returns true when at least one signature entry exists for $filename.
     */
    public function has(string $filename): bool
    {
        return isset($this->data[$filename]);
    }

    /**
     * Builds the value of the DIVE-Sig HTTP response header for $filename.
     *
     * Returns null when no signature data is registered for the file.
     *
     * @throws \RuntimeException on data integrity problems
     */
    public function buildDiveSigHeader(string $filename): ?string
    {
        if (!$this->has($filename)) {
            return null;
        }

        $entries    = $this->data[$filename]['signatures'] ?? [];
        $parts      = [];
        $seenKeyIds = [];

        foreach ($entries as $index => $entry) {
            $keyId     = $entry['key_id']        ?? null;
            $hashAlgo  = $entry['hash_algorithm'] ?? null;
            $sigB64    = $entry['signature_b64']  ?? null;
            $fqdn      = $entry['fqdn']            ?? null;  // optional

            if ($keyId === null || $hashAlgo === null || $sigB64 === null) {
                throw new \RuntimeException(
                    sprintf(
                        'signatures.json: entry #%d for file "%s" is missing required field(s).',
                        $index,
                        $filename
                    )
                );
            }

            // Validate key_id character set: A-Z a-z 0-9 _
            if (!preg_match('/^[A-Za-z0-9_]+$/', $keyId)) {
                throw new \RuntimeException(
                    sprintf(
                        'signatures.json: key_id "%s" contains invalid characters.',
                        $keyId
                    )
                );
            }

            // Enforce uniqueness per the spec (§ HTTP Response Headers)
            if (isset($seenKeyIds[$keyId])) {
                throw new \RuntimeException(
                    sprintf(
                        'signatures.json: duplicate key_id "%s" for file "%s".',
                        $keyId,
                        $filename
                    )
                );
            }
            $seenKeyIds[$keyId] = true;

            // Validate hash algorithm
            if (!in_array($hashAlgo, ['sha256', 'sha384', 'sha512'], true)) {
                throw new \RuntimeException(
                    sprintf(
                        'signatures.json: unsupported hash_algorithm "%s". Allowed: sha256, sha384, sha512.',
                        $hashAlgo
                    )
                );
            }

            // Validate fqdn if present (basic label-dot-label sanity check)
            if ($fqdn !== null) {
                if (!$this->isValidFqdn($fqdn)) {
                    throw new \RuntimeException(
                        sprintf(
                            'signatures.json: invalid fqdn "%s" for key_id "%s".',
                            $fqdn,
                            $keyId
                        )
                    );
                }
            }

            // Build the entry token: `keyID[@fqdn]:hash-algo:BASE64SIG`
            $keyPart = $fqdn !== null
                ? sprintf('%s@%s', $keyId, $fqdn)
                : $keyId;

            $parts[] = sprintf('%s:%s:%s', $keyPart, $hashAlgo, $sigB64);
        }

        if (empty($parts)) {
            return null;
        }

        // Spec recommends ≤ 3 entries; emit a warning to the error log but
        // do not truncate — the operator is responsible for their own config.
        if (count($parts) > 3) {
            error_log(sprintf(
                'DIVE PoC: file "%s" has %d DIVE-Sig entries; '
                . 'the spec recommends no more than 3.',
                $filename,
                count($parts)
            ));
        }

        return implode(',', $parts);
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    /**
     * Loads and parses the JSON store from disk.
     *
     * @return array<string, mixed>
     */
    private function load(): array
    {
        if (!file_exists($this->storePath)) {
            error_log(sprintf(
                'DIVE PoC: signatures file not found at "%s"; treating as empty.',
                $this->storePath
            ));
            return [];
        }

        $raw = file_get_contents($this->storePath);
        if ($raw === false) {
            error_log(sprintf(
                'DIVE PoC: could not read signatures file at "%s".',
                $this->storePath
            ));
            return [];
        }

        $decoded = json_decode($raw, associative: true, flags: JSON_THROW_ON_ERROR);

        if (!is_array($decoded)) {
            throw new \RuntimeException(
                'signatures.json: root element must be a JSON object.'
            );
        }

        return $decoded;
    }

    /**
     * Very basic FQDN sanity check (no leading/trailing dots, no empty labels,
     * only valid hostname characters).  Not a full RFC 1123 validator.
     */
    private function isValidFqdn(string $fqdn): bool
    {
        // Strip trailing dot (root label) if present
        $fqdn = rtrim($fqdn, '.');

        if ($fqdn === '') {
            return false;
        }

        $labels = explode('.', $fqdn);
        foreach ($labels as $label) {
            if ($label === '' || !preg_match('/^[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?$/', $label)) {
                return false;
            }
        }

        return true;
    }
}
