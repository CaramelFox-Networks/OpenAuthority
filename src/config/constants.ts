/*
 * OpenAuthority
 * Copyright (C) 2026 CaramelFox Networks LLC
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

// ============================================================
// CONFIGURATION CONSTANTS
// ============================================================

export const PROBATIONARY_PERIOD_DAYS = 7;
export const PROBATIONARY_CHECK_HOURS = 6;
export const ACTIVE_CHECK_HOURS = 24;
export const VERIFICATION_MARGIN_MINUTES = 5;
export const DEFAULT_PAGE_SIZE = 10;
export const MAX_CERT_SIZE = 64 * 1024;
export const RATE_LIMIT_WINDOW_SECONDS = 3600;
export const RATE_LIMIT_MAX_REQUESTS = 5;
export const MAX_CONSECUTIVE_FAILURES = 3;
export const VALID_EXPORT_FORMATS = ["pem", "bundle", "zip", "mobileconfig", "json"] as const;

// Security constants for eligibility verification
export const MIN_SUCCESSFUL_VERIFICATIONS = 28;
export const VERIFICATION_STALENESS_HOURS = 48;

// Merkle Tree Checkpoint Configuration
export const CHECKPOINT_INTERVAL_ENTRIES = 100;
export const CHECKPOINT_INTERVAL_HOURS = 1;
export const MERKLE_TREE_VERSION = "1.0.0";

// ============================================================
// RESOURCE EXHAUSTION LIMITS
// ============================================================

export const MAX_MERKLE_TREE_SIZE = 10_000_000;
export const MAX_AUDIT_LOG_ENTRY_SIZE = 10_000;
export const MAX_PROOF_SIBLINGS = 40;
export const MAX_EXPORT_CERTIFICATES = 10_000;
export const MAX_SNAPSHOT_SIZE = 100_000_000;
export const MAX_RECURSION_DEPTH = 100;

// ============================================================
// DNS VALIDATION CONSTANTS (RFC 1035)
// ============================================================

export const DNS_MAX_LABEL_LENGTH = 63;
export const DNS_MAX_NAME_LENGTH = 253;