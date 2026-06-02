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

import { Env, CertificateAuthority } from "../types";
import { PROBATIONARY_CHECK_HOURS, VERIFICATION_MARGIN_MINUTES, ACTIVE_CHECK_HOURS, MAX_CONSECUTIVE_FAILURES } from "../config";
import { createAuditLogEntry } from "../services";
import { safeDNSLookup } from "../utils";
import { verifyDNSTXT, extractBaseDomain, extractIPAddress, verifyWHOIS } from "../verification"

export async function runValidator(env: Env): Promise<void> {
  console.log("Starting periodic verification...");

  const certificates = await env.DB.prepare(`
    SELECT * FROM certificate_authorities 
    WHERE (
      (status = 'probationary' AND datetime(last_check_at, ? || ' hours', ? || ' minutes') <= datetime('now'))
      OR
      (status = 'active' AND datetime(last_check_at, ? || ' hours', ? || ' minutes') <= datetime('now'))
    )
    ORDER BY last_check_at ASC
    LIMIT 20
  `).bind(
    `${PROBATIONARY_CHECK_HOURS}`,
    `-${VERIFICATION_MARGIN_MINUTES}`,
    `${ACTIVE_CHECK_HOURS}`,
    `-${VERIFICATION_MARGIN_MINUTES}`
  ).all<CertificateAuthority>();

  if (certificates.results.length === 0) {
    console.log("No certificates due for verification");

    return;
  }

  console.log(`Verifying ${certificates.results.length} certificate(s)...`);

  for (const cert of certificates.results) {
    const now = new Date().toISOString();

    if (new Date(cert.not_after) < new Date()) {
      await env.DB.prepare(`
        UPDATE certificate_authorities 
        SET status = 'expired', last_check_at = ?
        WHERE id = ? AND status != 'expired'
      `).bind(now, cert.id).run();

      await createAuditLogEntry(
        env, 
        cert.id, 
        'certificate_expired', 
        cert.subject, 
        false, 
        `Certificate expired. Not After: ${cert.not_after}`
      );

      console.log(`Certificate ${cert.fingerprint_sha256.substring(0, 16)}... EXPIRED`);
      continue;
    }

    let allValid = true;
    let verificationError = "";
    const dnsConstraints = JSON.parse(cert.name_constraints_dns) as string[];
    const ipConstraints = JSON.parse(cert.name_constraints_ip) as string[];

    const uniqueDNS = [...new Set(dnsConstraints.map(dns => extractBaseDomain(dns)))];

    for (const baseDomain of uniqueDNS) {
      // Use safeDNSLookup wrapper for all DNS operations
      const result = await safeDNSLookup(baseDomain, cert.fingerprint_sha512, verifyDNSTXT);

      if (!result.normalizedDomain) {
        console.warn(`Skipping invalid domain ${baseDomain}: ${result.error}`);
        continue;
      }

      await createAuditLogEntry(env, cert.id, 'dns', result.normalizedDomain, result.success, result.error || 'Verified');

      if (!result.success) {
        allValid = false;
        verificationError = result.error || "DNS verification failed";
      }
    }

    for (const ipRange of ipConstraints) {
      const ip = extractIPAddress(ipRange);
      const result = await verifyWHOIS(ip, cert.fingerprint_sha512);
      await createAuditLogEntry(env, cert.id, 'whois', ip, result.success, result.error || 'Verified');

      if (!result.success) {
        allValid = false;
        verificationError = result.error || "WHOIS verification failed";
      }
    }

    if (!allValid) {
      const currentFailures = (cert.consecutive_failures || 0) + 1;

      if (currentFailures >= MAX_CONSECUTIVE_FAILURES) {
        await env.DB.prepare(`
          UPDATE certificate_authorities 
          SET status = 'revoked', last_check_at = ?, consecutive_failures = ?
          WHERE id = ?
        `).bind(now, currentFailures, cert.id).run();

        await createAuditLogEntry(
          env, 
          cert.id, 
          'certificate_revoked', 
          cert.subject, 
          false, 
          `Certificate revoked after ${currentFailures} consecutive verification failures. Last error: ${verificationError}`
        );

        console.log(`Certificate ${cert.fingerprint_sha256.substring(0, 16)}... REVOKED after ${currentFailures} consecutive failures`);
      } else {
        await env.DB.prepare(`
          UPDATE certificate_authorities 
          SET last_check_at = ?, consecutive_failures = ?
          WHERE id = ?
        `).bind(now, currentFailures, cert.id).run();
        console.log(`Certificate ${cert.fingerprint_sha256.substring(0, 16)}... verification failed (${currentFailures}/${MAX_CONSECUTIVE_FAILURES}): ${verificationError}`);
      }
    } else {
        const newVerificationCount = (cert.successful_verification_count || 0) + 1;

        // Update Verification Count
        await env.DB.prepare(`
          UPDATE certificate_authorities
          SET last_check_at = ?,
              consecutive_failures = 0,
              successful_verification_count = ?
          WHERE id = ?
          `).bind(now, newVerificationCount, cert.id).run();
        }
      }

  console.log("Periodic verification complete");
}