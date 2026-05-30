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

import { handleTransparencyVerify } from './transparency';
import { buildMerkleTree } from '../merkle'
import { Env } from '../types';
import { normalizeHeaders } from '../utils';

export async function handleAuditLog(
  env: Env, 
  corsHeaders: Record<string, string>,
  page: number,
  limit: number,
  caId?: string | null
): Promise<Response> {
  const session = env.DB.withSession();

  const offset = (page - 1) * limit;
  const safeLimit = Math.min(Math.max(1, limit), 100);

  let whereClause = "";
  const params: any[] = [];

  if (caId && /^\d+$/.test(caId)) {
    whereClause = "WHERE vl.ca_id = ?";
    params.push(parseInt(caId));
  }

  const countQuery = caId && /^\d+$/.test(caId)
    ? `SELECT COUNT(*) as total FROM verification_log vl WHERE vl.ca_id = ?`
    : `SELECT COUNT(*) as total FROM verification_log`;

  const countResult = await session.prepare(countQuery)
    .bind(...(caId && /^\d+$/.test(caId) ? [parseInt(caId)] : []))
    .first<{ total: number }>();

  const total = countResult?.total || 0;

  const results = await session.prepare(`
    SELECT vl.*, ca.subject, ca.fingerprint_sha256
    FROM verification_log vl
    JOIN certificate_authorities ca ON vl.ca_id = ca.id
    ${whereClause}
    ORDER BY vl.id DESC
    LIMIT ? OFFSET ?
  `).bind(...params, safeLimit, offset).all();

  return new Response(
    JSON.stringify({ 
      logs: results.results.map((log: any) => ({
        ...log,
        success: log.success === 1
      })),
      pagination: {
        page,
        limit: safeLimit,
        total,
        totalPages: Math.ceil(total / safeLimit)
      }
    }),
    { headers: { ...corsHeaders, "Content-Type": "application/json" } }
  );
}

async function handleCertificateAuditLog(
  env: Env,
  id: string,
  corsHeaders: Record<string, string>
): Promise<Response> {
  if (!id || !/^\d+$/.test(id)) {
    return new Response(
      JSON.stringify({ error: "Invalid certificate ID." }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  const results = await env.DB.prepare(`
    SELECT * FROM verification_log 
    WHERE ca_id = ? 
    ORDER BY id DESC
  `).bind(id).all<any>();

  return new Response(
    JSON.stringify({
      ca_id: parseInt(id),
      logs: results.results.map((log: any) => ({
        ...log,
        success: log.success === 1
      })),
      total: results.results.length
    }),
    { headers: { ...corsHeaders, "Content-Type": "application/json" } }
  );
}

export async function handleAuditExport(env: Env, format: string, corsHeaders: Record<string, string>): Promise<Response> {
  const results = await env.DB.prepare(`
    SELECT vl.*, ca.subject, ca.fingerprint_sha256
    FROM verification_log vl
    JOIN certificate_authorities ca ON vl.ca_id = ca.id
    ORDER BY vl.id ASC
  `).all();

  const entries = await env.DB.prepare(`
    SELECT leaf_hash FROM verification_log WHERE leaf_hash IS NOT NULL ORDER BY tree_position ASC
  `).all<{ leaf_hash: string }>();
  const leafHashes = entries.results.map(e => e.leaf_hash);
  const { root } = await buildMerkleTree(leafHashes);

  if (format === "csv") {
    const headers = "id,ca_id,subject,fingerprint_sha256,check_type,target,success,details,checked_at,nonce,leaf_hash,tree_position\n";
    const rows = results.results.map((log: any) => 
      `${log.id},${log.ca_id},"${log.subject}","${log.fingerprint_sha256}",${log.check_type},"${log.target}",${log.success},"${log.details}",${log.checked_at},${log.nonce || ''},${log.leaf_hash || ''},${log.tree_position || ''}`
    ).join('\n');

    return new Response(headers + rows, {
      headers: {
        ...corsHeaders,
        "Content-Type": "text/csv",
        "Content-Disposition": "attachment; filename=openauthority-audit-log.csv"
      }
    });
  }

  return new Response(
    JSON.stringify({
      logs: results.results.map((log: any) => ({
        ...log,
        success: log.success === 1
      })),
      total: results.results.length,
      exported_at: new Date().toISOString(),
      merkle_tree: {
        root: root,
        size: leafHashes.length
      },
      verification_info: {
        description: "Each log entry has a leaf_hash computed as SHA256(0x00 || canonical_entry_data). The Merkle tree root can be recomputed from all leaf hashes.",
        algorithm: "RFC 6962 Merkle Tree",
        canonicalization: "RFC8785-JCS",
        leaf_prefix: "0x00",
        node_prefix: "0x01"
      }
    }, null, 2),
    { 
      headers: { 
        ...corsHeaders,
        "Content-Type": "application/json",
        "Content-Disposition": "attachment; filename=openauthority-audit-log.json"
      } 
    }
  );
}

export async function handleAuditVerify(env: Env, corsHeaders: Record<string, string>): Promise<Response> {
  return handleTransparencyVerify(env, corsHeaders);
}

// ============================================
// ROUTE DISPATCHER
// ============================================

export async function handleAuditRoutes(
  request: Request,
  env: Env,
  corsHeaders: HeadersInit
): Promise<Response | null> {
  const url = new URL(request.url);
  const headers = normalizeHeaders(corsHeaders);

  if (
    request.method === 'GET' &&
    (
      url.pathname === '/api/audit-log' ||
      url.pathname === '/api/audit'
    )
  ){
    const page = Math.max(
      1,
      parseInt(url.searchParams.get('page') ?? '1', 10)
    );

    const limit = Math.max(
      1,
      parseInt(url.searchParams.get('limit') ?? '50', 10)
    );

    const caId = url.searchParams.get('ca_id');

    return handleAuditLog(
      env,
      headers,
      page,
      limit,
      caId
    );
  }

  if (
    request.method === 'GET' &&
    url.pathname.startsWith('/api/certificate/') &&
    url.pathname.endsWith('/audit')
  ) {
    const id = url.pathname.split('/')[3];

    return handleCertificateAuditLog(
      env,
      id,
      headers
    );
  }

  if (
    request.method === 'GET' &&
    (
      url.pathname === '/api/audit-export' ||
      url.pathname === '/api/audit/export'
    )
  ){
    const format =
      url.searchParams.get('format') ?? 'json';

    return handleAuditExport(
      env,
      format,
      headers
    );
  }

  if (
    request.method === 'GET' &&
    (
      url.pathname === '/api/audit-verify' ||
      url.pathname === '/api/audit/verify'
    )
  ){
    return handleAuditVerify(
      env,
      headers
    );
  }

  return null;
}