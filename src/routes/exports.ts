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

import { Env, THREAT_MODEL_VERSION, OPERATOR_TRUST_VERSION } from '../types';
import { VALID_EXPORT_FORMATS, MAX_EXPORT_CERTIFICATES, MERKLE_TREE_VERSION } from '../config'
import { canonicalizeJSON, generateZip, generateReproducibleExport, computeContentHash, signManifest, normalizeHeaders } from '../utils';
import { extractCN, generateMobileConfig } from '../certificates';
import { buildMerkleTree, TrustStoreSnapshot } from '../merkle';
import { verifyCertificateEligibility, generateTrustStoreSnapshot, verifyTrustStoreSnapshot } from '../trust';


export async function handleExport(env: Env, format: string, corsHeaders: Record<string, string>): Promise<Response> {
  if (!VALID_EXPORT_FORMATS.includes(format as any)) {
    return new Response(
      JSON.stringify({ 
        error: `Invalid format '${format}'. Supported formats: ${VALID_EXPORT_FORMATS.join(", ")}` 
      }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  const results = await env.DB.prepare(`
    SELECT id, pem_data, subject, fingerprint_sha256, created_at, status, 
           successful_verification_count, last_check_at
    FROM certificate_authorities 
    WHERE status = 'active'
    LIMIT ?
  `).bind(MAX_EXPORT_CERTIFICATES).all<{ 
    id: number; 
    pem_data: string; 
    subject: string; 
    fingerprint_sha256: string;
    created_at: string;
    status: string;
    successful_verification_count?: number;
    last_check_at: string;
  }>();

  const eligibleCertificates: Array<{ 
    pem_data: string; 
    subject: string; 
    fingerprint_sha256: string;
    created_at: string;
    last_check_at: string;
  }> = [];
  const rejectedCertificates: Array<{ fingerprint_sha256: string; reason: string }> = [];

  for (const cert of results.results) {
    const eligibility = await verifyCertificateEligibility(env, cert);

    if (eligibility.eligible) {
      eligibleCertificates.push({
        pem_data: cert.pem_data,
        subject: cert.subject,
        fingerprint_sha256: cert.fingerprint_sha256,
        created_at: cert.created_at,
        last_check_at: cert.last_check_at
      });
    } else {
      console.warn(
        `Certificate ${cert.fingerprint_sha256.substring(0, 16)}... rejected from export: ${eligibility.reason}`
      );
      rejectedCertificates.push({
        fingerprint_sha256: cert.fingerprint_sha256,
        reason: eligibility.reason!
      });
    }
  }

  const { content, manifest } = generateReproducibleExport(eligibleCertificates);
  manifest.contentHash = await computeContentHash(content);

  const signedManifest = await signManifest(env, manifest);

  const entries = await env.DB.prepare(`
    SELECT leaf_hash FROM verification_log WHERE leaf_hash IS NOT NULL ORDER BY tree_position ASC
  `).all<{ leaf_hash: string }>();
  const leafHashes = entries.results.map(e => e.leaf_hash);
  const { root } = await buildMerkleTree(leafHashes);

  if (format === "pem" || format === "bundle") {
    return new Response(content, {
      headers: {
        ...corsHeaders,
        "Content-Type": "application/x-pem-file",
        "Content-Disposition": "attachment; filename=openauthority-trust-store.pem",
        "X-Content-Hash": manifest.contentHash,
        "X-Manifest-Signature": signedManifest.signature || "unsigned",
        "X-Tree-Root": root,
        "X-Tree-Size": String(leafHashes.length),
        "X-Canonicalization": "RFC8785-JCS"
      }
    });
  }

  if (format === "zip") {
    const encoder = new TextEncoder();
    const files: Array<{ name: string; data: Uint8Array<ArrayBuffer> }> = [];

    const readme = `OpenAuthority Trust Store
========================

This ZIP contains ${eligibleCertificates.length} CA certificate(s).

Content Hash: ${manifest.contentHash}
Generated At: ${manifest.generatedAt}
Merkle Tree Root: ${root}
Merkle Tree Size: ${leafHashes.length}
Canonicalization: RFC 8785 JCS

Verification:
- Download the full snapshot from /api/transparency/snapshot
- Use the verifyTrustStoreSnapshot() function to verify independently
- Check Rekor entries at https://search.sigstore.dev
- Verify signatures using the public key from /api/transparency/public-key

Signature Verification Procedure:
1. Parse manifest.json
2. Remove 'signature', 'signatureAlgorithm', and 'canonicalization' fields
3. Canonicalize using RFC 8785 JCS (recursive key sort by UTF-16, no whitespace)
4. Encode as UTF-8
5. Verify ECDSA-P256-SHA256 signature over the canonical bytes

Installation:
- Windows: Double-click each .crt → Install Certificate → Local Machine → Trusted Root CAs
- macOS: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain <file>.crt
- Linux: Copy to /usr/local/share/ca-certificates/ and run update-ca-certificates
- Android: Settings → Security → Install certificates → CA certificate

For more information: https://openauthority.dev
`;
    files.push({ name: 'README.txt', data: encoder.encode(readme) });

    // Include both canonical and human-readable manifest
    const canonicalManifest = canonicalizeJSON(signedManifest);
    files.push({ name: 'manifest.canonical.json', data: encoder.encode(canonicalManifest) });
    files.push({ name: 'manifest.json', data: encoder.encode(JSON.stringify(signedManifest, null, 2)) });

    for (const cert of eligibleCertificates) {
      const cn = extractCN(cert.subject);
      const safeName = cn.replace(/[^a-zA-Z0-9.-]/g, '_').substring(0, 50);
      const filename = `${safeName}-${cert.fingerprint_sha256.substring(0, 8)}.crt`;
      files.push({ name: filename, data: encoder.encode(cert.pem_data) });
    }

    const zipData = generateZip(files);

    return new Response(zipData, {
      headers: {
        ...corsHeaders,
        "Content-Type": "application/zip",
        "Content-Disposition": "attachment; filename=openauthority-trust-store.zip"
      }
    });
  }

  if (format === "mobileconfig") {
    const mobileconfig = generateMobileConfig(eligibleCertificates);
    return new Response(mobileconfig, {
      headers: {
        ...corsHeaders,
        "Content-Type": "application/x-apple-aspen-config",
        "Content-Disposition": "attachment; filename=openauthority-trust-store.mobileconfig"
      }
    });
  }

  // format === "json"
  return new Response(
    JSON.stringify({ 
      manifest: signedManifest,
      certificates: eligibleCertificates.map(c => ({
        subject: c.subject,
        fingerprint_sha256: c.fingerprint_sha256,
        pem_data: c.pem_data
      })),
      transparency: {
        treeRoot: root,
        treeSize: leafHashes.length,
        snapshotUrl: "/api/transparency/snapshot",
        publicKeyUrl: "/api/transparency/public-key"
      },
      _meta: {
        total_active_in_db: results.results.length,
        passed_eligibility_check: eligibleCertificates.length,
        rejected: rejectedCertificates.length > 0 ? rejectedCertificates : undefined,
        threatModelVersion: THREAT_MODEL_VERSION,
        operatorTrustVersion: OPERATOR_TRUST_VERSION,
        merkleTreeVersion: MERKLE_TREE_VERSION,
        canonicalization: "RFC8785-JCS",
        reproducible: true
      },
      _verification: {
        signatureAlgorithm: "ECDSA-P256-SHA256",
        canonicalization: "RFC8785-JCS",
        procedure: [
          "1. Parse the manifest JSON",
          "2. Remove 'signature', 'signatureAlgorithm', and 'canonicalization' fields",
          "3. Canonicalize using RFC 8785 JCS (recursive key sort by UTF-16, no whitespace)",
          "4. Encode as UTF-8",
          "5. Verify ECDSA-P256-SHA256 signature over the canonical bytes"
        ],
        publicKeyUrl: "/api/transparency/public-key"
      }
    }, null, 2),
    { headers: { ...corsHeaders, "Content-Type": "application/json" } }
  );
}

export async function handleGetSnapshot(
  env: Env, 
  corsHeaders: Record<string, string>
): Promise<Response> {
  try {
    const snapshot = await generateTrustStoreSnapshot(env);

    return new Response(JSON.stringify(snapshot, null, 2), {
      headers: {
        ...corsHeaders,
        "Content-Type": "application/json",
        "Content-Disposition": "attachment; filename=openauthority-snapshot.json",
        "X-Content-Hash": snapshot.contentHash,
        "X-Tree-Size": String(snapshot.treeHead.treeSize),
        "X-Root-Hash": snapshot.treeHead.rootHash,
        "X-Canonicalization": "RFC8785-JCS"
      }
    });
  } catch (e) {
    return new Response(
      JSON.stringify({ error: e instanceof Error ? e.message : "Snapshot generation failed" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
}

export async function handleVerifySnapshot(
  request: Request, 
  corsHeaders: Record<string, string>
): Promise<Response> {
  try {
    const body = await request.json() as { 
      snapshot: TrustStoreSnapshot; 
      publicKey?: string 
    };

    if (!body.snapshot) {
      return new Response(
        JSON.stringify({ error: "Missing snapshot in request body" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const result = await verifyTrustStoreSnapshot(body.snapshot, body.publicKey);

    return new Response(JSON.stringify({
      ...result,
      verifiedAt: new Date().toISOString(),
      canonicalization: "RFC8785-JCS"
    }, null, 2), {
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  } catch (e) {
    return new Response(
      JSON.stringify({ error: `Invalid request: ${e}` }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
}

// ============================================
// ROUTE DISPATCHER
// ============================================

export async function handleExportRoutes(
  request: Request,
  env: Env,
  corsHeaders: HeadersInit
): Promise<Response | null> {
  const url = new URL(request.url);
  const headers = normalizeHeaders(corsHeaders);

  if (
    request.method === 'GET' &&
    url.pathname === '/api/export'
  ) {
    const format =
      url.searchParams.get('format') ?? 'json';

    return handleExport(
      env,
      format,
      headers
    );
  }

  if (
    request.method === 'GET' &&
    (
      url.pathname === '/api/snapshot' ||
      url.pathname === '/api/transparency/snapshot'
    )
  ){
    return handleGetSnapshot(
      env,
      headers
    );
  }

  if (
    request.method === 'POST' &&
    (
      url.pathname === '/api/verify-snapshot' ||
      url.pathname === '/api/transparency/verify-snapshot'
    )
  ){
    return handleVerifySnapshot(
      request,
      headers
    );
  }

  return null;
}