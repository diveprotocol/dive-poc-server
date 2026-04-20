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
 *         "key_id":         "keyABC",
 *         "fqdn":           "example.com",              // optional; omit for no @fqdn qualifier
 *         "content_digest": "sha-256=:BASE64DIGEST:",   // RFC 9530 Content-Digest value
 *         "signature_b64":  "<base64-encoded raw Ed25519 signature bytes>"
 *       }
 *     ]
 *   }
 * }
 *
 * The "fqdn" field is optional.  When present the keyid in Signature-Input
 * will be emitted as `keyID@fqdn`.
 *
 * Multiple entries in "signatures" map to multiple labeled entries in
 * Signature-Input / Signature (RFC 9421 §4.2, for key rotation overlap).
 */

declare(strict_types=1);

class SignatureStore
{
    /** @var array<string, array{signatures: list<array{key_id: string, fqdn?: string, content_digest: string, signature_b64: string}>}> */
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
     * Builds the RFC 9421 HTTP signature headers for $filename.
     *
     * Returns an array with keys 'content-digest', 'signature-input', 'signature',
     * or null when no signature data is registered for the file.
     *
     * @return array{content-digest: string, signature-input: string, signature: string}|null
     * @throws \RuntimeException on data integrity problems
     */
    public function buildSignatureHeaders(string $filename): ?array
    {
        if (!$this->has($filename)) {
            return null;
        }

        $entries         = $this->data[$filename]['signatures'] ?? [];
        $sigInputParts   = [];
        $sigParts        = [];
        $seenKeyIds      = [];
        $contentDigest   = null;

        foreach ($entries as $index => $entry) {
            $keyId            = $entry['key_id']         ?? null;
            $contentDigestVal = $entry['content_digest'] ?? null;
            $sigB64           = $entry['signature_b64']  ?? null;
            $fqdn             = $entry['fqdn']            ?? null;  // optional

            if ($keyId === null || $contentDigestVal === null || $sigB64 === null) {
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

            // Enforce uniqueness per the spec
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

            // Validate content_digest format per RFC 9530: sha-256=:BASE64: etc.
            if (!preg_match('/^(sha-256|sha-384|sha-512)=:[A-Za-z0-9+\/]+=*:$/', $contentDigestVal)) {
                throw new \RuntimeException(
                    sprintf(
                        'signatures.json: invalid content_digest "%s" for key_id "%s". '
                        . 'Expected format: sha-256=:BASE64: (RFC 9530).',
                        $contentDigestVal,
                        $keyId
                    )
                );
            }

            // All entries must agree on the content digest (same file content)
            if ($contentDigest === null) {
                $contentDigest = $contentDigestVal;
            } elseif ($contentDigest !== $contentDigestVal) {
                throw new \RuntimeException(
                    sprintf(
                        'signatures.json: conflicting content_digest values for file "%s".',
                        $filename
                    )
                );
            }

            // Validate fqdn if present (basic label-dot-label sanity check)
            if ($fqdn !== null && !$this->isValidFqdn($fqdn)) {
                throw new \RuntimeException(
                    sprintf(
                        'signatures.json: invalid fqdn "%s" for key_id "%s".',
                        $fqdn,
                        $keyId
                    )
                );
            }

            // Structured Fields dict key: "sig" + 1-based index (valid SF key: lowercase + digits)
            $label   = 'sig' . ($index + 1);
            $keyPart = $fqdn !== null ? sprintf('%s@%s', $keyId, $fqdn) : $keyId;

            $sigInputParts[] = sprintf(
                '%s=("content-digest");keyid="%s";alg="ed25519"',
                $label,
                $keyPart
            );
            $sigParts[] = sprintf('%s=:%s:', $label, $sigB64);
        }

        if (empty($sigInputParts) || $contentDigest === null) {
            return null;
        }

        // Spec recommends ≤ 3 entries; emit a warning but do not truncate.
        if (count($sigInputParts) > 3) {
            error_log(sprintf(
                'DIVE PoC: file "%s" has %d signature entries; '
                . 'the spec recommends no more than 3.',
                $filename,
                count($sigInputParts)
            ));
        }

        return [
            'content-digest'  => $contentDigest,
            'signature-input' => implode(', ', $sigInputParts),
            'signature'       => implode(', ', $sigParts),
        ];
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
