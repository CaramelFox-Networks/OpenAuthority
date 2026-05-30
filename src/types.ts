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

import { D1Database, KVNamespace } from "@cloudflare/workers-types/experimental";

export interface Env {
  DB: D1Database;
  RATE_LIMIT_KV?: KVNamespace;
  DISCORD_WEBHOOK_URL?: string;
  SIGNING_PRIVATE_KEY?: string;
  SIGNING_PUBLIC_KEY?: string;
  SIGNING_PUBLIC_KEY_PEM?: string; 
  TIMESTAMP_SERVICE_URL?: string;
  REKOR_URL?: string;
}

export interface NameConstraints {
  permittedDNS: string[];
  permittedIP: string[];
  excludedDNS: string[];
  excludedIP: string[];
}

// Properly typed Basic Constraints
export interface BasicConstraints {
  isCA: boolean;
  pathLenConstraint?: number;
}

export interface ParsedCertificate {
  fingerprint_sha512: string;
  fingerprint_sha256: string;
  subject: string;
  issuer: string;
  serialNumber: string;
  notBefore: Date;
  notAfter: Date;
  pemData: string;
  nameConstraints: NameConstraints;
  basicConstraints: BasicConstraints;
  isCA: boolean;
}

export interface CertificateAuthority {
  id: number;
  fingerprint_sha512: string;
  fingerprint_sha256: string;
  subject: string;
  issuer: string;
  serial_number: string;
  not_before: string;
  not_after: string;
  pem_data: string;
  name_constraints_dns: string;
  name_constraints_ip: string;
  verified_at: string;
  last_check_at: string;
  status: 'active' | 'probationary' | 'revoked' | 'expired';
  created_at: string;
  consecutive_failures?: number;
  successful_verification_count?: number;
}

export interface VerificationResult {
  success: boolean;
  domain?: string;
  ip?: string;
  expectedHash: string;
  foundHash?: string;
  error?: string;
  resolverResults?: ResolverResult[];
}

// Multi-resolver DNS validation 
export interface ResolverResult {
  resolver: string;
  success: boolean;
  records?: string[];
  error?: string;
  responseTime?: number;
}

// RDAP proof structure
export interface RDAPProof {
  ip: string;
  rdapServer: string;
  queryTimestamp: string;
  responseHash: string;
  matchLocation: 'remarks' | 'description' | 'notices' | 'not_found';
  matchedText?: string;
  fullResponse?: any;
}

export type AuditEventType = 
  | 'certificate_added'
  | 'dns'
  | 'whois'
  | 'certificate_promoted'
  | 'certificate_revoked'
  | 'certificate_expired'
  | 'external_anchor'; 

export interface CertificateDetails extends CertificateAuthority {
  audit_log: AuditLogEntry[];
  first_seen: string;
  last_verified: string | null;
  next_verification: string;
  total_successful_verifications: number;
  total_failed_verifications: number;
  eligibility_status: {
    eligible_for_export: boolean;
    reason?: string;
  };
}

export interface AuditLogEntry {
  id: number;
  ca_id: number;
  check_type: AuditEventType;
  target: string;
  success: boolean;
  details: string;
  checked_at: string;
  nonce?: string;
  previous_hash?: string;
  entry_hash?: string;
  external_anchor?: ExternalAnchor;
}

// External audit checkpoint
export interface ExternalAnchor {
  type: 'rfc3161' | 'blockchain' | 'transparency_log' | 'rekor';
  timestamp: string;
  proof: string;
  serviceUrl?: string;
  transactionId?: string;
  submitted_body?: string;
}

// Signed export manifest
export interface ExportManifest {
  version: string;
  generatedAt: string;
  certificateCount: number;
  certificates: Array<{
    fingerprint_sha256: string;
    subject: string;
    addedAt: string;
    lastVerified: string;
  }>;
  contentHash: string;
  canonicalization?: string;
  signature?: string;
  signatureAlgorithm?: string;
}

// ============================================================
// EXPLICIT THREAT MODEL
// ============================================================
/**
 * THREAT MODEL DOCUMENTATION
 * 
 * OpenAuthority - Security Assumptions and Threat Analysis
 * 
 * === WHAT WE PROTECT AGAINST ===
 * 
 * 1. UNAUTHORIZED CERTIFICATE ISSUANCE
 *    - Threat: Attacker creates CA and issues certs for domains they don't control
 *    - Mitigation: DNS TXT verification proves domain ownership
 *    - Mitigation: Name Constraints limit CA scope to declared domains only
 * 
 * 2. ROGUE CA INJECTION
 *    - Threat: Attacker directly inserts CA into database bypassing verification
 *    - Mitigation: Audit log cross-verification (verifyCertificateEligibility)
 *    - Mitigation: Hash chain integrity prevents log tampering
 *    - Mitigation: External anchoring provides tamper-evident timestamps
 * 
 * 3. DOMAIN TAKEOVER ATTACKS
 *    - Threat: Attacker gains temporary DNS control, adds malicious CA
 *    - Mitigation: 7-day probationary period with repeated verification
 *    - Mitigation: Continuous re-verification (6h probationary, 24h active)
 *    - Mitigation: Multi-resolver DNS validation prevents single-resolver poisoning
 * 
 * 4. AUDIT LOG TAMPERING
 *    - Threat: Operator or attacker modifies historical audit entries
 *    - Mitigation: Cryptographic hash chain (each entry references previous)
 *    - Mitigation: External RFC 3161 timestamps anchor chain to external time
 *    - Mitigation: Public audit log export allows independent verification
 * 
 * 5. STALE/ABANDONED CAs
 *    - Threat: CA owner loses control of domain, CA remains trusted
 *    - Mitigation: Continuous verification revokes CAs that fail checks
 *    - Mitigation: MAX_CONSECUTIVE_FAILURES (3) triggers automatic revocation
 * 
 * === WHAT WE DO NOT PROTECT AGAINST ===
 * 
 * 1. MALICIOUS OPERATOR (see OPERATOR_TRUST_ASSUMPTIONS)
 *    - A malicious operator with database access could theoretically:
 *      - Modify the database directly (mitigated by audit log verification)
 *      - Suppress verification failures (mitigated by external anchoring)
 *      - Issue false audit entries (mitigated by hash chain + external anchors)
 * 
 * 2. COMPROMISED DNS INFRASTRUCTURE
 *    - If ALL queried DNS resolvers are compromised, verification can be bypassed
 *    - Mitigation: Multi-resolver validation reduces this risk
 * 
 * 3. COMPROMISED RDAP/WHOIS INFRASTRUCTURE
 *    - If RIR RDAP servers are compromised, IP verification can be bypassed
 *    - This is considered out of scope (RIR compromise is catastrophic)
 * 
 * 4. CERTIFICATE PRIVATE KEY COMPROMISE
 *    - We verify domain ownership, not key security
 *    - CA operators are responsible for their own key management
 * 
 * 5. CLIENT-SIDE TRUST STORE TAMPERING
 *    - Once exported, trust store integrity is user's responsibility
 *    - Mitigation: Signed manifests allow verification of export integrity
 */
export const THREAT_MODEL_VERSION = "1.0.0";

// ============================================================
// OPERATOR TRUST ASSUMPTIONS
// ============================================================
/**
 * OPERATOR TRUST ASSUMPTIONS
 * 
 * This documents what trust users place in the OpenAuthority operator.
 * 
 * === TRUST ASSUMPTIONS ===
 * 
 * 1. CODE INTEGRITY
 *    - Users trust that the deployed code matches the published source
 *    - Verification: Code is open source, deployments can be audited
 * 
 * 2. VERIFICATION EXECUTION
 *    - Users trust that DNS/RDAP verification actually runs as documented
 *    - Verification: Audit log with external anchors provides evidence
 *    - Verification: Multi-resolver results are logged for transparency
 * 
 * 3. NO SELECTIVE SUPPRESSION
 *    - Users trust operator doesn't selectively hide verification failures
 *    - Verification: External timestamps make gaps in audit log detectable
 *    - Verification: Public audit export allows community monitoring
 * 
 * 4. INFRASTRUCTURE SECURITY
 *    - Users trust operator maintains secure infrastructure
 *    - This includes: database security, API security, key management
 * 
 * === TRUST MINIMIZATION MEASURES ===
 * 
 * 1. CRYPTOGRAPHIC AUDIT LOG
 *    - Hash chain prevents undetected modification of historical entries
 *    - External anchoring provides independent timestamp verification
 * 
 * 2. ELIGIBILITY CROSS-VERIFICATION
 *    - Export doesn't trust database status field alone
 *    - Verifies against audit log to detect direct database manipulation
 * 
 * 3. PUBLIC TRANSPARENCY
 *    - Full audit log is exportable and verifiable by anyone
 *    - Signed manifests allow verification of export integrity
 * 
 * 4. REPRODUCIBLE EXPORTS
 *    - Trust store generation is deterministic
 *    - Same inputs produce same outputs, enabling independent verification
 * 
 * === WHAT OPERATOR CANNOT DO (with mitigations working) ===
 * 
 * - Add CA without DNS verification (audit log would lack dns events)
 * - Backdate CA addition (external timestamps prevent this)
 * - Silently remove verification failures (hash chain would break)
 * - Claim more verifications than occurred (external anchors bound count)
 * 
 * === WHAT OPERATOR COULD THEORETICALLY DO ===
 * 
 * - Delay publishing verification failures (bounded by anchor frequency)
 * - Choose which external anchor service to use
 * - Decide operational parameters (probation period, check frequency)
 * 
 * Users who require zero operator trust should run their own instance.
 */
export const OPERATOR_TRUST_VERSION = "1.0.0";
