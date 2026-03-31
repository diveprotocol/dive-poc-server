<?php

/**
 * DIVE PoC — Configuration
 *
 * All paths are resolved at runtime so the container mount point
 * (/data) is respected regardless of where PHP is invoked from.
 */

declare(strict_types=1);

// Root of the persistent data volume (mounted from ./container-data)
define('DATA_DIR',        '/data');

// Directory that holds the downloadable resources
define('RESOURCES_DIR',   DATA_DIR . '/resources');

// JSON file that maps filenames → signature metadata
define('SIGNATURES_FILE', DATA_DIR . '/signatures.json');

// Path to the reports log file
define('REPORTS_LOG', DATA_DIR . '/reports.log');

// Maximum report size in bytes (10KB)
define('MAX_REPORT_SIZE', 10240);

// Allowed report versions
define('ALLOWED_REPORT_VERSIONS', ['0.1']);
