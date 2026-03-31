# DIVE PoC — PHP server

Proof of concept for the **Domain-based Integrity Verification Enforcement**
(DIVE) draft RFC. Serves files from a configurable directory with the
`DIVE-Sig` HTTP response header attached.

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
│   ├── SignatureStore.php    ← reads signatures.json, builds DIVE-Sig value
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
                   --key  <private-key-b64> \
                   --algo sha256
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
#    DIVE-Sig: keyABC@example.com:sha256:<BASE64SIG>
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
        "hash_algorithm": "sha256",
        "signature_b64": "<base64-encoded raw Ed25519 signature>"
      }
    ]
  }
}
```

| Field            | Required | Notes                                          |
| ---------------- | -------- | ---------------------------------------------- |
| `key_id`         | ✓        | `[A-Za-z0-9_]+` — matches the DNS label prefix |
| `hash_algorithm` | ✓        | `sha256` \| `sha384` \| `sha512`               |
| `signature_b64`  | ✓        | Base64 of the raw 64-byte Ed25519 signature    |
| `fqdn`           | —        | When present emits `keyID@fqdn` in the header  |

Multiple entries in `"signatures"` produce multiple comma-separated tokens in
`DIVE-Sig` (multi-key scenario, key rotation overlap, etc.).

---

## Signature input (per DIVE spec §5 Step 5)

```
input = hash_algorithm_name || ":" || raw_hash_bytes
```

Example for SHA-256:

```
"sha256:" + <32 raw bytes of SHA-256(file)>
```

The `tools/sign.php` helper does this automatically.

---

## DNS records to publish (for a real deployment)

**Policy record** (`_dive.example.com TXT`):

```
v="dive-draft-00", scopes=("download"), directives=("https-required"), cache=1800
```

**Key record** (`keyABC._divekey.example.com TXT`):

```
sig="ed25519", key=:<base64-public-key>:, allowed-hash=("sha256" "sha384"), cache=900
```

Both zones **must** be signed with DNSSEC.

---

## Security notes

- **No private key on the server.** Signatures are pre-computed offline with
  `tools/sign.php` and stored in `signatures.json`. The serving process never sees
  a private key, and `tools/` is never copied into the Docker image.
- **Path traversal is blocked** at two levels: character rejection (`/`, `\`,
  null bytes) and `realpath()` containment check.
- Files with no entry in `signatures.json` are served **without** `DIVE-Sig`.
  A DIVE-enforcing client in `download` scope will refuse them.
