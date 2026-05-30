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

import { Env, ParsedCertificate, CertificateAuthority, CertificateDetails } from "../types";
import { RATE_LIMIT_WINDOW_SECONDS, MAX_CERT_SIZE, PROBATIONARY_PERIOD_DAYS, PROBATIONARY_CHECK_HOURS, ACTIVE_CHECK_HOURS } from "../config";
import { checkRateLimit, safeDNSLookup, validateDomainStrict, normalizeHeaders } from "../utils";
import { parseCertificate } from "../certificate";
import { extractBaseDomain, verifyDNSTXT, extractIPAddress, verifyWHOIS } from "../verification";
import { createAuditLogEntry } from "../services";
import { MerkleProof, getInclusionProofForEntry } from "../merkle";
import { verifyCertificateEligibility } from '../trust';

export async function handleUpload(request: Request, env: Env, corsHeaders: Record<string, string>): Promise<Response> {
  const responseHeaders = { ...corsHeaders, "Content-Type": "application/json" };

  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rateLimit = await checkRateLimit(env, clientIP);

  if (!rateLimit.allowed) {
    return new Response(
      JSON.stringify({ error: "Rate limit exceeded. Please try again later." }),
      { 
        status: 429, 
        headers: { 
          ...responseHeaders, 
          "Retry-After": String(RATE_LIMIT_WINDOW_SECONDS),
          "X-RateLimit-Remaining": "0"
        } 
      }
    );
  }

  const formData = await request.formData();
  const certFile = formData.get("certificate");

  if (!certFile || !(certFile instanceof File)) {
    return new Response(
      JSON.stringify({ error: "No certificate file provided" }),
      { status: 400, headers: responseHeaders }
    );
  }

  if (certFile.size > MAX_CERT_SIZE) {
    return new Response(
      JSON.stringify({ error: `Certificate file too large. Maximum size is ${MAX_CERT_SIZE / 1024}KB.` }),
      { status: 400, headers: responseHeaders }
    );
  }

  const arrayBuffer = await certFile.arrayBuffer();
  const uint8Array = new Uint8Array(arrayBuffer);
  const isPEM = uint8Array[0] === 45 && uint8Array[1] === 45 && uint8Array[2] === 45;

  let certData: string | Uint8Array<ArrayBuffer>;
  if (isPEM) {
    certData = new TextDecoder().decode(uint8Array);
  } else {
    certData = uint8Array;
  }

  let parsed: ParsedCertificate;
  try {
    parsed = await parseCertificate(certData);
  } catch (e: unknown) {
    return new Response(
      JSON.stringify({ error: `Certificate parsing failed: ${e instanceof Error ? e.message : String(e)}` }),
      { status: 400, headers: responseHeaders }
    );
  }

  const existing = await env.DB.prepare(
    "SELECT id FROM certificate_authorities WHERE fingerprint_sha512 = ?"
  ).bind(parsed.fingerprint_sha512).first();

  if (existing) {
    return new Response(
      JSON.stringify({ error: "Certificate already exists in the trust store" }),
      { status: 409, headers: responseHeaders }
    );
  }

  const uniqueDomains = [...new Set(
    parsed.nameConstraints.permittedDNS.map(dns => extractBaseDomain(dns))
  )];

  // Validate all domains using strict RFC 1035 validation
  for (const domain of uniqueDomains) {
    const validation = validateDomainStrict(domain);
    if (!validation.isValid) {
      return new Response(
        JSON.stringify({ error: `Invalid domain in certificate: ${validation.error}` }),
        { status: 400, headers: responseHeaders }
      );
    }
  }

  const dnsVerifications: Array<{ domain: string; success: boolean; error?: string }> = [];
  for (const baseDomain of uniqueDomains) {
    // Use safeDNSLookup wrapper for all DNS operations
    const result = await safeDNSLookup(baseDomain, parsed.fingerprint_sha512, verifyDNSTXT);
    dnsVerifications.push({
      domain: result.normalizedDomain || baseDomain,
      success: result.success,
      error: result.error
    });

    if (!result.success) {
      return new Response(
        JSON.stringify({ 
          error: `DNS verification failed for ${result.normalizedDomain || baseDomain}: ${result.error}`,
          verifications: dnsVerifications
        }),
        { status: 400, headers: responseHeaders }
      );
    }
  }

  const ipVerifications: Array<{ ip: string; success: boolean; error?: string }> = [];
  for (const ipRange of parsed.nameConstraints.permittedIP) {
    const ip = extractIPAddress(ipRange);
    const result = await verifyWHOIS(ip, parsed.fingerprint_sha512);
    ipVerifications.push({
      ip,
      success: result.success,
      error: result.error
    });

    if (!result.success) {
      return new Response(
        JSON.stringify({ 
          error: `WHOIS verification failed for ${ip}: ${result.error}`,
          verifications: { dns: dnsVerifications, ip: ipVerifications }
        }),
        { status: 400, headers: responseHeaders }
      );
    }
  }

  const now = new Date().toISOString();

  const statements = [
    env.DB.prepare(`
      INSERT INTO certificate_authorities (
        fingerprint_sha512, fingerprint_sha256, subject, issuer, serial_number,
        not_before, not_after, pem_data, name_constraints_dns, name_constraints_ip,
        verified_at, last_check_at, created_at, status, consecutive_failures, successful_verification_count
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'probationary', 0, 0)
    `).bind(
      parsed.fingerprint_sha512,
      parsed.fingerprint_sha256,
      parsed.subject,
      parsed.issuer,
      parsed.serialNumber,
      parsed.notBefore.toISOString(),
      parsed.notAfter.toISOString(),
      parsed.pemData,
      JSON.stringify(parsed.nameConstraints.permittedDNS),
      JSON.stringify(parsed.nameConstraints.permittedIP),
      now,
      now,
      now
    )
  ];

  await env.DB.batch(statements);

  const ca = await env.DB.prepare(
    "SELECT id FROM certificate_authorities WHERE fingerprint_sha512 = ?"
  ).bind(parsed.fingerprint_sha512).first<{ id: number }>();

  if (ca) {
    await createAuditLogEntry(
      env, 
      ca.id, 
      'certificate_added', 
      parsed.subject, 
      true, 
      `Certificate added to trust store. Subject: ${parsed.subject}, Fingerprint: ${parsed.fingerprint_sha256.substring(0, 16)}...`
    );

    for (const v of dnsVerifications) {
      await createAuditLogEntry(env, ca.id, 'dns', v.domain, v.success, v.error || 'Initial verification passed');
    }

    for (const v of ipVerifications) {
      await createAuditLogEntry(env, ca.id, 'whois', v.ip, v.success, v.error || 'Initial verification passed');
    }
  }

  return new Response(
    JSON.stringify({ 
      success: true, 
      message: `Certificate verified and added to trust store (probationary for ${PROBATIONARY_PERIOD_DAYS} days)`,
      fingerprint: parsed.fingerprint_sha512,
      subject: parsed.subject,
      verifications: { dns: dnsVerifications, ip: ipVerifications }
    }),
    { 
      status: 201, 
      headers: { 
        ...responseHeaders,
        "X-RateLimit-Remaining": String(rateLimit.remaining)
      } 
    }
  );
}

export async function handleListCertificates(
  env: Env, 
  corsHeaders: Record<string, string>,
  page: number,
  limit: number,
  search: string
): Promise<Response> {
  const session = env.DB.withSession();
  const offset = (page - 1) * limit;
  const safeLimit = Math.min(Math.max(1, limit), 100);

  let whereClause = "WHERE status IN ('active', 'probationary')";
  const params: any[] = [];

  if (search) {
    whereClause += ` AND (
      subject LIKE ? OR 
      fingerprint_sha256 LIKE ? OR 
      fingerprint_sha512 LIKE ? OR
      name_constraints_dns LIKE ?
    )`;
    const searchPattern = `%${search}%`;
    params.push(searchPattern, searchPattern, searchPattern, searchPattern);
  }

  const countResult = await session.prepare(
    `SELECT COUNT(*) as total FROM certificate_authorities ${whereClause}`
  ).bind(...params).first<{ total: number }>();

  const total = countResult?.total || 0;

  const results = await session.prepare(`
    SELECT id, fingerprint_sha512, fingerprint_sha256, subject, issuer, 
           serial_number, not_before, not_after, name_constraints_dns, 
           name_constraints_ip, verified_at, last_check_at, status, created_at,
           successful_verification_count
    FROM certificate_authorities
    ${whereClause}
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  `).bind(...params, safeLimit, offset).all<CertificateAuthority>();

  const certificates = results.results.map(cert => ({
    ...cert,
    name_constraints_dns: JSON.parse(cert.name_constraints_dns),
    name_constraints_ip: JSON.parse(cert.name_constraints_ip)
  }));

  return new Response(
    JSON.stringify({ 
      certificates,
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

export async function handleGetCertificateDetails(
  env: Env, 
  id: string, 
  corsHeaders: Record<string, string>
): Promise<Response> {
  const session = env.DB.withSession();

  if (!id || !/^\d+$/.test(id)) {
    return new Response(
      JSON.stringify({ error: "Invalid certificate ID. Must be a positive integer." }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  const cert = await session.prepare(`
    SELECT * FROM certificate_authorities WHERE id = ?
  `).bind(id).first<CertificateAuthority>();

  if (!cert) {
    return new Response(
      JSON.stringify({ error: "Certificate not found" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  const auditResults = await session.prepare(`
    SELECT * FROM verification_log 
    WHERE ca_id = ? 
    ORDER BY id DESC
  `).bind(id).all<any>();

  const successfulVerifications = auditResults.results.filter(
    (log: any) => ['dns', 'whois'].includes(log.check_type) && log.success === 1
  ).length;

  const failedVerifications = auditResults.results.filter(
    (log: any) => ['dns', 'whois'].includes(log.check_type) && log.success === 0
  ).length;

  const firstSeenEntry = auditResults.results.find(
    (log: any) => log.check_type === 'certificate_added'
  ) || auditResults.results[auditResults.results.length - 1];

  const lastVerifiedEntry = auditResults.results.find(
    (log: any) => ['dns', 'whois'].includes(log.check_type) && log.success === 1
  );

  const lastCheckAt = new Date(cert.last_check_at);
  const checkIntervalHours = cert.status === 'probationary' ? PROBATIONARY_CHECK_HOURS : ACTIVE_CHECK_HOURS;
  const nextVerification = new Date(lastCheckAt.getTime() + checkIntervalHours * 60 * 60 * 1000);

  const eligibility = await verifyCertificateEligibility(env, cert);

  const addedEntry = auditResults.results.find((log: any) => log.check_type === 'certificate_added');
  let inclusionProof: MerkleProof | null = null;
  if (addedEntry) {
    inclusionProof = await getInclusionProofForEntry(env, addedEntry.id);
  }

  const response: CertificateDetails & { inclusion_proof?: MerkleProof | null } = {
    ...cert,
    name_constraints_dns: JSON.parse(cert.name_constraints_dns) as any,
    name_constraints_ip: JSON.parse(cert.name_constraints_ip) as any,
    audit_log: auditResults.results.map((log: any) => ({
      id: log.id,
      ca_id: log.ca_id,
      check_type: log.check_type,
      target: log.target,
      success: log.success === 1,
      details: log.details,
      checked_at: log.checked_at,
      nonce: log.nonce,
      leaf_hash: log.leaf_hash,
      tree_position: log.tree_position
    })),
    first_seen: firstSeenEntry?.checked_at || cert.created_at,
    last_verified: lastVerifiedEntry?.checked_at || null,
    next_verification: nextVerification.toISOString(),
    total_successful_verifications: successfulVerifications,
    total_failed_verifications: failedVerifications,
    eligibility_status: {
      eligible_for_export: eligibility.eligible,
      reason: eligibility.reason
    },
    inclusion_proof: inclusionProof
  };

  return new Response(
    JSON.stringify(response, null, 2),
    { headers: { ...corsHeaders, "Content-Type": "application/json" } }
  );
}

export async function handleCertificateAuditLog(
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

// ============================================
// ROUTE DISPATCHER
// ============================================

export async function handleCertificateRoutes(
  request: Request,
  env: Env,
  corsHeaders: HeadersInit
): Promise<Response | null> {
  const url = new URL(request.url);
  const headers = normalizeHeaders(corsHeaders);

  if (
    request.method === 'POST' &&
    url.pathname === '/api/upload'
  ) {
    return handleUpload(
      request,
      env,
      headers
    );
  }

  if (
    request.method === 'GET' &&
    url.pathname === '/api/certificates'
  ) {
    const page = Math.max(
      1,
      parseInt(url.searchParams.get('page') ?? '1', 10)
    );

    const limit = Math.max(
      1,
      parseInt(url.searchParams.get('limit') ?? '50', 10)
    );

    const search =
      url.searchParams.get('search') ?? '';

    return handleListCertificates(
      env,
      headers,
      page,
      limit,
      search
    );
  }

  if (
    request.method === 'GET' &&
    /^\/api\/certificate\/\d+$/.test(url.pathname)
  ) {
    const id = url.pathname.split('/')[3];

    return handleGetCertificateDetails(
      env,
      id,
      headers
    );
  }

  return null;
}