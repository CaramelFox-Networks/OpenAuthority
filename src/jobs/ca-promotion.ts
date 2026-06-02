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
import { PROBATIONARY_PERIOD_DAYS, MIN_SUCCESSFUL_VERIFICATIONS } from "../config";
import { createAuditLogEntry } from "../services";

export async function promoteEligibleCertificates(env: Env): Promise<void> {
  const now = new Date();

  const candidates = await env.DB.prepare(`
    SELECT *
    FROM certificate_authorities
    WHERE status = 'probationary'
      AND successful_verification_count >= ?
  `)
  .bind(MIN_SUCCESSFUL_VERIFICATIONS)
  .all<CertificateAuthority>();

  for (const cert of candidates.results) {
    const probationEndDate = new Date(
      new Date(cert.created_at).getTime() +
      PROBATIONARY_PERIOD_DAYS * 24 * 60 * 60 * 1000
    );

    if (now >= probationEndDate) {
      await env.DB.prepare(`
        UPDATE certificate_authorities
        SET status = 'active'
        WHERE id = ?
      `)
      .bind(cert.id)
      .run();

      await createAuditLogEntry(
        env,
        cert.id,
        'certificate_promoted',
        cert.subject,
        true,
        `Certificate promoted from probationary to active after ${cert.successful_verification_count} successful verifications over ${PROBATIONARY_PERIOD_DAYS} days`
      );
    }
  }
}