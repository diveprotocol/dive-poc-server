<?php

/**
 * DIVE PoC — Entry point / router
 *
 * Routes:
 *   GET  /downloads/{filename}   Serve a resource with RFC 9421 signature headers
 *   POST /report                 Handle DIVE verification failure reports
 *   GET  /                       Health-check / info page
 */

declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/SignatureStore.php';
require_once __DIR__ . '/DownloadHandler.php';
require_once __DIR__ . '/ReportHandler.php';

// ── Minimal router ────────────────────────────────────────────────────────────

$requestUri  = $_SERVER['REQUEST_URI'] ?? '/';
$requestPath = parse_url($requestUri, PHP_URL_PATH);
$requestMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';

// Normalize: collapse duplicate slashes, resolve dot segments safely
$requestPath = '/' . ltrim($requestPath, '/');

if (str_starts_with($requestPath, '/downloads/')) {
    // Extract the raw filename segment (everything after /downloads/)
    $rawFilename = substr($requestPath, strlen('/downloads/'));
    $handler     = new DownloadHandler(
        new SignatureStore(SIGNATURES_FILE),
        RESOURCES_DIR
    );
    $handler->handle($rawFilename);
    exit;
}

if ($requestPath === '/report' && $requestMethod === 'POST') {
    $handler = new ReportHandler();
    $content = file_get_contents('php://input');
    $result = $handler->handle($content);

    http_response_code($result['status']);
    header('Content-Type: application/json');
    echo json_encode(['message' => $result['message']]);
    exit;
}

if ($requestPath === '/' || $requestPath === '') {
    http_response_code(200);
    header('Content-Type: text/plain; charset=utf-8');
    echo "DIVE PoC server — operational\n";
    echo "Serve files via: GET /downloads/{filename}\n";
    echo "Submit reports via: POST /report\n";
    exit;
}

http_response_code(404);
header('Content-Type: text/plain; charset=utf-8');
echo "Not found.\n";
