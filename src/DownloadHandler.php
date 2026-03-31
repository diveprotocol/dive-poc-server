<?php

/**
 * DIVE PoC — DownloadHandler
 *
 * Validates the requested filename, attaches the DIVE-Sig header, and
 * streams the file to the client.
 *
 * Security measures implemented
 * ──────────────────────────────
 *  1. Path traversal prevention
 *       - The raw filename from the URL is sanitised: any path separator
 *         (/ or \) and any null byte are rejected outright.
 *       - The resolved absolute path is verified to sit inside RESOURCES_DIR
 *         using realpath() comparison.  This defeats symlink escapes and any
 *         OS-level path normalisation tricks.
 *  2. No shell execution — file content is read and streamed with plain PHP
 *     file I/O; no exec/system/passthru is used.
 *  3. Signature injection — DIVE-Sig is taken from the pre-computed
 *     signatures.json; the server never signs on-the-fly, keeping the
 *     private key off the serving host (in line with §Operational Security).
 */

declare(strict_types=1);

class DownloadHandler
{
    // Chunk size for streaming (bytes)
    private const STREAM_CHUNK = 524288; // 512 KiB

    public function __construct(
        private readonly SignatureStore $store,
        private readonly string        $resourcesDir
    ) {}

    // ── Public entry-point ─────────────────────────────────────────────────────

    /**
     * Handles a download request for the given raw filename segment.
     *
     * Calls exit() after sending the response (or after an error response).
     */
    public function handle(string $rawFilename): void
    {
        // ── 1. Sanitise the filename ───────────────────────────────────────────

        // Reject empty filename
        if ($rawFilename === '') {
            $this->sendError(400, 'Bad Request', 'Filename must not be empty.');
            return;
        }

        // Reject any path separator or null byte immediately — no ambiguity
        if (preg_match('#[/\\\\\x00]#', $rawFilename)) {
            $this->sendError(400, 'Bad Request', 'Filename contains invalid characters.');
            return;
        }

        // Reject filenames that are purely dot-sequences (".", "..", "...")
        if (preg_match('/^\.+$/', $rawFilename)) {
            $this->sendError(400, 'Bad Request', 'Invalid filename.');
            return;
        }

        // Decode percent-encoded characters so that %2F etc. cannot sneak through
        $decodedFilename = rawurldecode($rawFilename);
        if (preg_match('#[/\\\\\x00]#', $decodedFilename)) {
            $this->sendError(400, 'Bad Request', 'Filename contains invalid characters after decoding.');
            return;
        }

        // At this point use the decoded form for everything
        $filename = $decodedFilename;

        // ── 2. Build and verify the absolute path ─────────────────────────────

        // Canonicalise the resources directory itself (once per request is fine)
        $canonicalResourcesDir = realpath($this->resourcesDir);
        if ($canonicalResourcesDir === false) {
            error_log(sprintf(
                'DIVE PoC: resources directory "%s" cannot be resolved.',
                $this->resourcesDir
            ));
            $this->sendError(500, 'Internal Server Error', 'Server misconfiguration.');
            return;
        }

        // Construct the candidate path WITHOUT calling realpath() yet, then
        // resolve — realpath() returns false if the file doesn't exist, which
        // we want to distinguish from an actual traversal attempt.
        $candidatePath = $canonicalResourcesDir . DIRECTORY_SEPARATOR . $filename;
        $resolvedPath  = realpath($candidatePath);

        if ($resolvedPath === false) {
            // File does not exist (or is a broken symlink)
            $this->sendError(404, 'Not Found', 'The requested resource was not found.');
            return;
        }

        // Enforce containment: resolved path must begin with resources dir + separator
        // We append DIRECTORY_SEPARATOR to both sides to prevent a prefix attack
        // (e.g., /data/resources-evil matching /data/resources).
        $prefix = $canonicalResourcesDir . DIRECTORY_SEPARATOR;
        if (!str_starts_with($resolvedPath, $prefix) && $resolvedPath !== $canonicalResourcesDir) {
            error_log(sprintf(
                'DIVE PoC: path traversal attempt detected. Raw: "%s", Resolved: "%s".',
                $rawFilename,
                $resolvedPath
            ));
            $this->sendError(403, 'Forbidden', 'Access denied.');
            return;
        }

        // ── 3. Reject directories ─────────────────────────────────────────────

        if (is_dir($resolvedPath)) {
            $this->sendError(403, 'Forbidden', 'Directory listing is not permitted.');
            return;
        }

        // ── 4. Ensure it is a regular, readable file ──────────────────────────

        if (!is_file($resolvedPath) || !is_readable($resolvedPath)) {
            $this->sendError(403, 'Forbidden', 'Resource is not accessible.');
            return;
        }

        // ── 5. Look up the DIVE-Sig header value ──────────────────────────────

        // Use the basename of the resolved path as the store key so that any
        // remaining symlink indirection (inside the directory) is stripped.
        $storeKey = basename($resolvedPath);

        try {
            $diveSigValue = $this->store->buildDiveSigHeader($storeKey);
        } catch (\RuntimeException $e) {
            error_log('DIVE PoC: SignatureStore error: ' . $e->getMessage());
            $this->sendError(500, 'Internal Server Error', 'Signature data error.');
            return;
        }

        // ── 6. Send response headers ──────────────────────────────────────────

        $fileSize = filesize($resolvedPath);
        $mimeType = $this->detectMimeType($resolvedPath, $filename);

        header('Content-Type: ' . $mimeType);
        header('Content-Length: ' . $fileSize);

        // Force download behaviour so that DIVE `download` scope applies
        // (Content-Disposition: attachment triggers the scope per the spec)
        $safeDispositionName = $this->sanitiseDispositionFilename($filename);
        header(sprintf(
            'Content-Disposition: attachment; filename="%s"',
            $safeDispositionName
        ));

        header('X-Content-Type-Options: nosniff');
        header('Cache-Control: no-store');

        // DIVE-Sig — only added when signature data is available
        if ($diveSigValue !== null) {
            header('DIVE-Sig: ' . $diveSigValue);
        } else {
            // Log the omission; a DIVE-compliant client will refuse this resource
            // once it determines it falls within an enforced scope.
            error_log(sprintf(
                'DIVE PoC: no signature data found for "%s"; DIVE-Sig header omitted.',
                $filename
            ));
        }

        http_response_code(200);

        // ── 7. Stream the file body ───────────────────────────────────────────

        if ($_SERVER['REQUEST_METHOD'] === 'HEAD') {
            // HEAD request: headers only, no body
            return;
        }

        $fh = fopen($resolvedPath, 'rb');
        if ($fh === false) {
            // Headers already sent; best we can do is log
            error_log(sprintf('DIVE PoC: failed to open "%s" for reading.', $resolvedPath));
            return;
        }

        while (!feof($fh)) {
            $chunk = fread($fh, self::STREAM_CHUNK);
            if ($chunk === false) {
                break;
            }
            echo $chunk;
            flush();
        }

        fclose($fh);
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    /**
     * Sends a JSON error response and terminates.
     */
    private function sendError(int $code, string $status, string $detail): void
    {
        http_response_code($code);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            'error'  => $status,
            'detail' => $detail,
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * Returns a best-effort MIME type for the given file.
     *
     * Prefers the fileinfo extension; falls back to a small built-in map;
     * defaults to application/octet-stream for unknown types.
     */
    private function detectMimeType(string $resolvedPath, string $filename): string
    {
        if (extension_loaded('fileinfo')) {
            $finfo = new \finfo(FILEINFO_MIME_TYPE);
            $type  = $finfo->file($resolvedPath);
            if ($type !== false && $type !== '') {
                return $type;
            }
        }

        // Fallback map keyed on lowercase extension
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        $map = [
            'txt'  => 'text/plain',
            'html' => 'text/html',
            'css'  => 'text/css',
            'js'   => 'application/javascript',
            'json' => 'application/json',
            'xml'  => 'application/xml',
            'pdf'  => 'application/pdf',
            'zip'  => 'application/zip',
            'gz'   => 'application/gzip',
            'tar'  => 'application/x-tar',
            'png'  => 'image/png',
            'jpg'  => 'image/jpeg',
            'jpeg' => 'image/jpeg',
            'gif'  => 'image/gif',
            'svg'  => 'image/svg+xml',
            'wasm' => 'application/wasm',
        ];

        return $map[$ext] ?? 'application/octet-stream';
    }

    /**
     * Strips characters that could break the Content-Disposition header value.
     *
     * Keeps only printable ASCII minus double-quote, backslash, and CR/LF.
     */
    private function sanitiseDispositionFilename(string $filename): string
    {
        // Remove control characters and the characters that break the quoted-string
        return preg_replace('/[\x00-\x1F\x7F"\\\\]/', '_', $filename);
    }
}
