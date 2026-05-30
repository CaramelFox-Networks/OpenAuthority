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
import { createIncrementalMerkleTree, createSignedTreeHead } from "../merkle";
import { normalizeHeaders, validateDomainStrict } from "../utils";

export async function handleGetPublicKey(env: Env, corsHeaders: Record<string, string>): Promise<Response> {
  return new Response(JSON.stringify({
    algorithm: "ECDSA-P256",
    format: "SPKI-Base64",
    publicKey: env.SIGNING_PUBLIC_KEY || null,
    canonicalization: "RFC8785-JCS",
    signatureAlgorithm: "ECDSA-P256-SHA256",
    usage: "Verify signatures on tree heads, checkpoints, manifests, and snapshots"
  }, null, 2), {
    headers: { ...corsHeaders, "Content-Type": "application/json" }
  });
}

export async function handleGetTreeHead(env: Env, corsHeaders: Record<string, string>): Promise<Response> {
  const tree = createIncrementalMerkleTree(env);
  const treeSize = await tree.getTreeSize();
  const root = await tree.getRoot();

  const latestCheckpoint = await env.DB.prepare(`
    SELECT checkpoint_hash FROM transparency_checkpoints ORDER BY id DESC LIMIT 1
  `).first<{ checkpoint_hash: string }>();

  const sth = await createSignedTreeHead(
    env, 
    treeSize, 
    root, 
    latestCheckpoint?.checkpoint_hash
  );

  return new Response(JSON.stringify(sth, null, 2), {
    headers: { ...corsHeaders, "Content-Type": "application/json" }
  });
}

// ============================================
// ROUTE DISPATCHER
// ============================================

export async function handlePublicRoutes(
  request: Request,
  env: Env,
  corsHeaders: HeadersInit
): Promise<Response | null> {
  const url = new URL(request.url);
  const responseHeaders = normalizeHeaders(corsHeaders)

  // Public key
  if (
    request.method === 'GET' &&
    (
      url.pathname === '/api/public-key' ||
      url.pathname === '/api/transparency/public-key'
    ) 
  ){
    return handleGetPublicKey(env, responseHeaders);
  }

// ============================================
// DOMAIN VALIDATION
// ============================================

  if (
    url.pathname === '/api/validate-domain' &&
    request.method === 'GET'
  ) {
    const domain = url.searchParams.get('domain') || '';
    const result = validateDomainStrict(domain);

    return new Response(
      JSON.stringify(result),
      {
        headers: {
          ...corsHeaders,
          'Content-Type': 'application/json',
        },
      }
    );
  }
  return null;
}
