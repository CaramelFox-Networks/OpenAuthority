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

import { Env } from "../types";
import { PROBATIONARY_PERIOD_DAYS, MIN_SUCCESSFUL_VERIFICATIONS, VERIFICATION_STALENESS_HOURS } from "../config";
import { canonicalizeJSON } from "../utils";
import { computeLeafHash } from "../merkle";

// ============================================================
// CERTIFICATE ELIGIBILITY VERIFICATION
// ============================================================

export async function verifyCertificateEligibility(
  env: Env, 
  cert: { 
    id: number; 
    created_at: string; 
    status: string; 
    successful_verification_count?: number;
    fingerprint_sha256: string;
  }
): Promise<{ eligible: boolean; reason?: string }> {

  if (cert.status !== 'active') {
    return { eligible: false, reason: 'Status is not active' };
  }

  const createdAt = new Date(cert.created_at);
  const minAge = PROBATIONARY_PERIOD_DAYS * 24 * 60 * 60 * 1000;
  if (Date.now() - createdAt.getTime() < minAge) {
    return { eligible: false, reason: 'Certificate has not completed probationary period' };
  }

  const addedEvent = await env.DB.prepare(`
    SELECT id FROM verification_log 
    WHERE ca_id = ? AND check_type = 'certificate_added'
    LIMIT 1
  `).bind(cert.id).first<{ id: number }>();

  if (!addedEvent) {
    return { 
      eligible: false, 
      reason: 'No certificate_added event found in audit log - possible injection' 
    };
  }

  const auditCount = await env.DB.prepare(`
    SELECT COUNT(*) as count 
    FROM verification_log 
    WHERE ca_id = ? AND check_type IN ('dns', 'whois') AND success = 1
  `).bind(cert.id).first<{ count: number }>();

  const verifiedCount = auditCount?.count || 0;

  if (verifiedCount < MIN_SUCCESSFUL_VERIFICATIONS) {
    return { 
      eligible: false, 
      reason: `Insufficient verifications: ${verifiedCount}/${MIN_SUCCESSFUL_VERIFICATIONS}` 
    };
  }

  const promotedEvent = await env.DB.prepare(`
    SELECT id FROM verification_log 
    WHERE ca_id = ? AND check_type = 'certificate_promoted'
    LIMIT 1
  `).bind(cert.id).first<{ id: number }>();

  if (!promotedEvent) {
    return { 
      eligible: false, 
      reason: 'No certificate_promoted event found - status may have been manually set' 
    };
  }

  const recentCheck = await env.DB.prepare(`
    SELECT checked_at 
    FROM verification_log 
    WHERE ca_id = ? AND check_type IN ('dns', 'whois') AND success = 1 
    ORDER BY id DESC 
    LIMIT 1
  `).bind(cert.id).first<{ checked_at: string }>();

  if (!recentCheck) {
    return { eligible: false, reason: 'No successful verifications found in audit log' };
  }

  const lastVerified = new Date(recentCheck.checked_at);
  const stalenessLimit = VERIFICATION_STALENESS_HOURS * 60 * 60 * 1000;

  if (Date.now() - lastVerified.getTime() > stalenessLimit) {
    return { 
      eligible: false, 
      reason: `Last verification too old: ${recentCheck.checked_at}` 
    };
  }

  const criticalEntries = await env.DB.prepare(`
    SELECT * FROM verification_log 
    WHERE ca_id = ? AND check_type IN ('certificate_added', 'certificate_promoted')
    ORDER BY id ASC
  `).bind(cert.id).all<any>();

  for (const entry of criticalEntries.results) {
    if (!entry.leaf_hash || !entry.nonce) continue;

    const entryDataObj = {
      ca_id: entry.ca_id,
      check_type: entry.check_type,
      target: entry.target,
      success: entry.success === 1,
      details: entry.details,
      checked_at: entry.checked_at,
      nonce: entry.nonce,
      tree_position: entry.tree_position
    };
    const entryData = canonicalizeJSON(entryDataObj);
    const computedHash = await computeLeafHash(entryData);

    if (computedHash !== entry.leaf_hash) {
      return { 
        eligible: false, 
        reason: `Audit log integrity failure at entry ${entry.id}` 
      };
    }
  }

  return { eligible: true };
}