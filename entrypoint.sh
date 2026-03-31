#!/bin/sh
# DIVE PoC — container entrypoint
#
# Performs startup checks on the /data volume, then transfers control to the
# official Apache entrypoint supplied by the php:8.3-apache base image.
#
# Exit codes:
#   0  all checks passed; Apache is about to start
#   1  fatal configuration error; container will not start

set -e

DATA_DIR="/data"
RESOURCES_DIR="${DATA_DIR}/resources"
SIGNATURES_FILE="${DATA_DIR}/signatures.json"

log()  { printf '[DIVE entrypoint] %s\n' "$*"; }
warn() { printf '[DIVE entrypoint] WARNING: %s\n' "$*" >&2; }
die()  { printf '[DIVE entrypoint] FATAL: %s\n' "$*" >&2; exit 1; }

# ── 1. Volume presence ────────────────────────────────────────────────────────

log "Checking data volume at ${DATA_DIR} ..."

if [ ! -d "${DATA_DIR}" ]; then
    die "${DATA_DIR} does not exist. Mount the data volume with: -v ./container-data:/data"
fi

# ── 2. Resources directory ────────────────────────────────────────────────────

if [ ! -d "${RESOURCES_DIR}" ]; then
    warn "${RESOURCES_DIR} not found — creating it."
    mkdir -p "${RESOURCES_DIR}" || die "Could not create ${RESOURCES_DIR}."
fi

if [ ! -r "${RESOURCES_DIR}" ] || [ ! -x "${RESOURCES_DIR}" ]; then
    die "${RESOURCES_DIR} is not readable by the container user."
fi

# ── 3. signatures.json ────────────────────────────────────────────────────────

if [ ! -f "${SIGNATURES_FILE}" ]; then
    warn "${SIGNATURES_FILE} not found — creating an empty store."
    printf '{}' > "${SIGNATURES_FILE}" \
        || die "Could not create ${SIGNATURES_FILE}."
fi

if [ ! -r "${SIGNATURES_FILE}" ]; then
    die "${SIGNATURES_FILE} exists but is not readable by the container user."
fi

# Basic JSON validity check (php is available in the image)
php -r "
    \$raw = file_get_contents('${SIGNATURES_FILE}');
    \$decoded = json_decode(\$raw, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        fwrite(STDERR, json_last_error_msg() . PHP_EOL);
        exit(1);
    }
    if (!is_array(\$decoded)) {
        fwrite(STDERR, 'Root element must be a JSON object.' . PHP_EOL);
        exit(1);
    }
    exit(0);
" || die "${SIGNATURES_FILE} is not valid JSON. Fix it before starting the container."

log "signatures.json OK."

# ── 4. Resource count (informational) ─────────────────────────────────────────

FILE_COUNT=$(find "${RESOURCES_DIR}" -maxdepth 1 -type f | wc -l)
log "Resources directory contains ${FILE_COUNT} file(s)."

if [ "${FILE_COUNT}" -eq 0 ]; then
    warn "No files found in ${RESOURCES_DIR}. Place files there before serving."
fi

# ── 5. Hand off to the base image's Apache entrypoint ─────────────────────────

log "All checks passed. Starting Apache ..."
exec docker-php-entrypoint apache2-foreground "$@"
