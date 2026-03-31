<?php

/**
 * DIVE PoC — ReportHandler
 *
 * Handles incoming DIVE verification failure reports as specified in the RFC.
 */

declare(strict_types=1);

class ReportHandler
{
    public function __construct(
        private readonly string $logPath = REPORTS_LOG,
        private readonly int $maxSize = MAX_REPORT_SIZE
    ) {}

    /**
     * Handles an incoming report request.
     *
     * @param string $content The raw JSON report body
     * @return array{status: int, message: string}
     */
    public function handle(string $content): array
    {
        // Validate content length
        if (strlen($content) > $this->maxSize) {
            return [
                'status' => 413,
                'message' => 'Report too large. Maximum size is ' . $this->maxSize . ' bytes.'
            ];
        }

        // Parse JSON
        try {
            $report = json_decode($content, associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            return [
                'status' => 400,
                'message' => 'Invalid JSON: ' . $e->getMessage()
            ];
        }

        // Validate required fields
        $validation = $this->validateReport($report);
        if ($validation !== true) {
            return [
                'status' => 400,
                'message' => $validation
            ];
        }

        // Log the report
        $this->logReport($report);

        return [
            'status' => 202,
            'message' => 'Report accepted'
        ];
    }

    /**
     * Validates the report structure and content.
     *
     * @param array $report The decoded report
     * @return true|string Returns true if valid, or an error message if invalid
     */
    private function validateReport(array $report): true|string
    {
        // Check report version
        if (!isset($report['report-version']) || !in_array($report['report-version'], ALLOWED_REPORT_VERSIONS, true)) {
            return 'Invalid or missing report-version. Must be one of: ' . implode(', ', ALLOWED_REPORT_VERSIONS);
        }

        // Check required top-level fields
        $requiredFields = [
            'timestamp',
            'client',
            'policy',
            'resource',
            'validation'
        ];

        foreach ($requiredFields as $field) {
            if (!isset($report[$field])) {
                return "Missing required field: $field";
            }
        }

        // Validate timestamp is reasonable (not in the future and not too old)
        if (!is_int($report['timestamp']) ||
            $report['timestamp'] > time() + 300 || // 5 minutes in the future
            $report['timestamp'] < time() - 86400) { // 24 hours in the past
            return 'Invalid timestamp';
        }

        // Validate client structure
        if (!isset($report['client']['user-agent']) || !is_string($report['client']['user-agent'])) {
            return 'Invalid client.user-agent';
        }

        // Validate policy structure
        $requiredPolicyFields = ['domain', 'fqdn', 'dnssec-validated'];
        foreach ($requiredPolicyFields as $field) {
            if (!isset($report['policy'][$field])) {
                return "Missing required policy field: $field";
            }
        }

        if (!is_bool($report['policy']['dnssec-validated'])) {
            return 'policy.dnssec-validated must be a boolean';
        }

        // Validate resource structure
        $requiredResourceFields = ['url', 'method', 'status-code', 'scope'];
        foreach ($requiredResourceFields as $field) {
            if (!isset($report['resource'][$field])) {
                return "Missing required resource field: $field";
            }
        }

        // Validate validation structure
        $requiredValidationFields = [
            'hash-algorithm',
            'hash-computed',
            'signature-valid',
            'failure-reason',
            'final-decision'
        ];

        foreach ($requiredValidationFields as $field) {
            if (!isset($report['validation'][$field])) {
                return "Missing required validation field: $field";
            }
        }

        if (!is_bool($report['validation']['signature-valid'])) {
            return 'validation.signature-valid must be a boolean';
        }

        return true;
    }

    /**
     * Logs the report to the reports log file.
     *
     * @param array $report The validated report
     */
    private function logReport(array $report): void
    {
        // Prepare log entry
        $logEntry = [
            'timestamp' => time(),
            'report' => $report
        ];

        $json = json_encode($logEntry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";

        // Append to log file
        file_put_contents($this->logPath, $json, FILE_APPEND | LOCK_EX);
    }
}
