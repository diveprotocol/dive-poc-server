# DIVE PoC — PHP server

Proof of concept for the **Domain-based Integrity Verification Enforcement**
(DIVE) draft RFC. Serves files from a configurable directory with RFC 9421
HTTP Message Signature headers attached.

---

## Directory layout

```
.
├── Dockerfile
├── docker-compose.yml
├── entrypoint.sh             ← startup checks, then launches Apache
├── container-data/           ← mounted as /data inside the container
│   ├── resources/            ← put your downloadable files here
│   └── signatures.json       ← signature metadata (see below)
├── src/                      ← PHP source (copied into the image)
│   ├── index.php             ← router / entry point
│   ├── config.php            ← path constants
│   ├── SignatureStore.php    ← reads signatures.json, builds RFC 9421 headers
│   └── DownloadHandler.php   ← path-safe file serving
└── tools/
    └── sign.php              ← CLI helper: key generation + signing (offline)
```

---

## Quick start

```bash
# 1. Place files to serve
cp myfile.zip container-data/resources/

# 2. Generate a key pair (offline, never inside the container)
php tools/sign.php --keygen
#    → prints a private key (keep it!) and a public key for DNS

# 3. Sign the file
php tools/sign.php --sign container-data/resources/myfile.zip \
                   --key    <private-key-b64> \
                   --algo   sha256 \
                   --key-id keyABC \
                   --fqdn   example.com
#    → prints a signatures.json snippet; paste it in

# 4. Edit container-data/signatures.json with the output above

# 5. Start the server
docker compose up --build
#    On startup the entrypoint will:
#      - verify /data is mounted
#      - create resources/ and signatures.json if absent
#      - validate signatures.json as well-formed JSON
#      - log the number of files found in resources/
#      - hand off to Apache

# 6. Download the file
curl -I http://localhost/downloads/myfile.zip
#    HTTP/1.1 200 OK
#    Content-Digest: sha-256=:<BASE64DIGEST>:
#    Signature-Input: sig1=("content-digest");keyid="keyABC@example.com";alg="ed25519"
#    Signature: sig1=:<BASE64SIG>:
#    Content-Disposition: attachment; filename="myfile.zip"
```

---

## signatures.json format

```json
{
  "<filename>": {
    "signatures": [
      {
        "key_id": "keyABC",
        "fqdn": "example.com",
        "content_digest": "sha-256=:<base64-sha256-of-file>:",
        "signature_b64": "<base64-encoded raw Ed25519 signature>"
      }
    ]
  }
}
```

| Field            | Required | Notes                                                    |
| ---------------- | -------- | -------------------------------------------------------- |
| `key_id`         | ✓        | `[A-Za-z0-9_]+` — matches the DNS label prefix          |
| `content_digest` | ✓        | RFC 9530 value: `sha-256=:BASE64:` / `sha-384=:BASE64:` |
| `signature_b64`  | ✓        | Base64 of the raw 64-byte Ed25519 signature              |
| `fqdn`           | —        | When present, keyid in Signature-Input becomes `key@fqdn`|

Multiple entries in `"signatures"` produce multiple labeled entries in
`Signature-Input` / `Signature` (multi-key scenario, key rotation overlap, etc.).

---

## Signature input (RFC 9421 §2.5)

The signature is computed over the RFC 9421 **signature base**, which for DIVE is:

```
"content-digest": <Content-Digest header value>
"@signature-params": ("content-digest");keyid="<keyid>";alg="ed25519"
```

Example for SHA-256 with `keyABC@example.com`:

```
"content-digest": sha-256=:<base64-digest>:
"@signature-params": ("content-digest");keyid="keyABC@example.com";alg="ed25519"
```

The `tools/sign.php` helper does this automatically.

---

## DNS records to publish (for a real deployment)

**Policy record** (`_dive.example.com TXT`):

```
v="dive-draft-01", scopes=("download"), directives=("https-required"), cache=1800
```

**Key record** (`keyABC._divekey.example.com TXT`):

```
sig="ed25519", key=:<base64-public-key>:, cache=900
```

Both zones **must** be signed with DNSSEC.

---

## Security notes

- **No private key on the server.** Signatures are pre-computed offline with
  `tools/sign.php` and stored in `signatures.json`. The serving process never sees
  a private key, and `tools/` is never copied into the Docker image.
- **Path traversal is blocked** at two levels: character rejection (`/`, `\`,
  null bytes) and `realpath()` containment check.
- Files with no entry in `signatures.json` are served **without** DIVE signature
  headers. A DIVE-enforcing client in `download` scope will refuse them.
