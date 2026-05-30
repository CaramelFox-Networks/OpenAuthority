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

import { Env } from '../types';
import { MAX_MERKLE_TREE_SIZE } from '../config';
import { verifyRekorEntry } from '../rekor'
import { getInclusionProofForEntry, generateConsistencyProof, computeLeafHash, TransparencyCheckpoint, createIncrementalMerkleTree } from '../merkle';
import { canonicalizeJSON, sha256, normalizeHeaders } from '../utils';
import { buildVerificationSummary } from '../services';
import { handleGetTreeHead } from './public';

export async function handleGetInclusionProof(
  env: Env, 
  entryId: string, 
  corsHeaders: Record<string, string>
): Promise<Response> {
  if (!/^\d+$/.test(entryId)) {
    return new Response(
      JSON.stringify({ error: "Invalid entry ID" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  const proof = await getInclusionProofForEntry(env, parseInt(entryId));

  if (!proof) {
    return new Response(
      JSON.stringify({ error: "Entry not found or has no leaf hash" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  return new Response(JSON.stringify({
    entryId: parseInt(entryId),
    proof,
    verificationInstructions: {
      description: "To verify this proof, compute the leaf hash from entry data using RFC 8785 canonical JSON, then walk up the tree using siblings",
      algorithm: "RFC 6962 Merkle Tree with domain separation (0x00 for leaves, 0x01 for nodes)",
      canonicalization: "RFC 8785 JSON Canonicalization Scheme (JCS)"
    }
  }, null, 2), {
    headers: { ...corsHeaders, "Content-Type": "application/json" }
  });
}

export async function handleGetConsistencyProof(
  env: Env,
  oldSize: number,
  newSize: number,
  corsHeaders: Record<string, string>
): Promise<Response> {
  if (oldSize <= 0 || newSize <= 0 || newSize < oldSize) {
    return new Response(
      JSON.stringify({ error: "Invalid tree sizes. old_size must be >= 0 and <= new_size" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  if (newSize > MAX_MERKLE_TREE_SIZE) {
    return new Response(
      JSON.stringify({ error: `new_size exceeds maximum of ${MAX_MERKLE_TREE_SIZE}` }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  const entries = await env.DB.prepare(`
    SELECT leaf_hash FROM verification_log 
    WHERE leaf_hash IS NOT NULL 
    ORDER BY tree_position ASC
  `).all<{ leaf_hash: string }>();

  const leafHashes = entries.results.map(e => e.leaf_hash);

  if (newSize > leafHashes.length) {
    return new Response(
      JSON.stringify({ error: `new_size ${newSize} exceeds current tree size ${leafHashes.length}` }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  if (oldSize === newSize) {
    return new Response(JSON.stringify({
      proof: [],
      verificationInstructions: {
        description: "Trees are identical; empty consistency proof",
        algorithm: "RFC 6962 consistency proof"
      }
    }, null, 2), {
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }

  const proof = await generateConsistencyProof(leafHashes, oldSize, newSize);

  return new Response(JSON.stringify({
    proof,
    verificationInstructions: {
      description: "This proof demonstrates that the tree of old_size is a prefix of the tree of new_size",
      algorithm: "RFC 6962 consistency proof"
    }
  }, null, 2), {
    headers: { ...corsHeaders, "Content-Type": "application/json" }
  });
}

export async function handleTransparencyVerify(
  env: Env,
  corsHeaders: Record<string, string>
): Promise<Response> {
  const entries = await env.DB.prepare(`
    SELECT * FROM verification_log 
    WHERE leaf_hash IS NOT NULL 
    ORDER BY tree_position ASC
  `).all<any>();

  let localValid = true;
  let localErrorMessage = "";
  let entriesVerified = 0;

  // Verify each entry's leaf hash (data integrity check)
  for (const entry of entries.results) {
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
      localValid = false;
      localErrorMessage = `Leaf hash mismatch at entry ${entry.id}: computed ${computedHash.substring(0, 16)}..., stored ${entry.leaf_hash.substring(0, 16)}...`;
      break;
    }

    entriesVerified++;
  }

  // Use incremental tree for root verification
  const tree = createIncrementalMerkleTree(env);
  const computedRoot = await tree.getRoot();
  const treeSize = await tree.getTreeSize();

  let checkpointValid = true;
  let checkpointError = "";
  let expectedRoot = "";
  let latestCheckpoint: TransparencyCheckpoint | null = null;

  if (localValid) {
    latestCheckpoint = await env.DB.prepare(`
      SELECT * FROM transparency_checkpoints ORDER BY id DESC LIMIT 1
    `).first<TransparencyCheckpoint>();

    if (latestCheckpoint) {
      expectedRoot = latestCheckpoint.root_hash;

      // Verify the stored root matches what we compute
      // If tree has grown since checkpoint, we verify the checkpoint was valid at that size
      if (treeSize === latestCheckpoint.tree_size) {
        // Tree hasn't grown - roots should match exactly
        if (computedRoot !== latestCheckpoint.root_hash) {
          checkpointValid = false;
          checkpointError = `Root mismatch: computed ${computedRoot.substring(0, 16)}..., stored ${latestCheckpoint.root_hash.substring(0, 16)}...`;
        }
      } else if (treeSize > latestCheckpoint.tree_size) {
        // Tree has grown since checkpoint - verify checkpoint data hash
        const checkpointDataObj = {
          tree_size: latestCheckpoint.tree_size,
          root_hash: latestCheckpoint.root_hash,
          timestamp: latestCheckpoint.timestamp,
          previous_checkpoint_hash: latestCheckpoint.previous_checkpoint_hash
        };
        const checkpointData = canonicalizeJSON(checkpointDataObj);
        const computedCheckpointHash = await sha256(checkpointData);

        if (computedCheckpointHash !== latestCheckpoint.checkpoint_hash) {
          checkpointValid = false;
          checkpointError = `Checkpoint hash mismatch: computed ${computedCheckpointHash.substring(0, 16)}..., stored ${latestCheckpoint.checkpoint_hash.substring(0, 16)}...`;
        }
      }
    }
  }

  // Verify external Rekor anchors
  const externalVerifications: Array<{ type: string; valid: boolean; error?: string; uuid?: string }> = [];

  const checkpointsWithRekor = await env.DB.prepare(`
    SELECT rekor_entry_uuid, checkpoint_hash FROM transparency_checkpoints 
    WHERE rekor_entry_uuid IS NOT NULL
    ORDER BY id DESC LIMIT 5
  `).all<{ rekor_entry_uuid: string; checkpoint_hash: string }>();

  for (const cp of checkpointsWithRekor.results) {
    const rekorResult = await verifyRekorEntry(cp.rekor_entry_uuid, cp.checkpoint_hash);
    externalVerifications.push({
      type: 'rekor',
      valid: rekorResult.valid,
      error: rekorResult.error,
      uuid: cp.rekor_entry_uuid
    });
  }

  const overallValid = localValid && checkpointValid;
  const summary = buildVerificationSummary(
    localValid,
    checkpointValid,
    entriesVerified,
    entries.results.length,
    externalVerifications
  );

  return new Response(JSON.stringify({
    // Overall status
    valid: overallValid,
    summary,

    // Local integrity verification
    localIntegrity: {
      valid: localValid,
      entriesVerified,
      totalEntries: entries.results.length,
      error: localErrorMessage || null
    },

    // Merkle tree verification
    merkleTree: {
      valid: checkpointValid,
      computedRoot: computedRoot || null,
      expectedRoot: expectedRoot || null,
      currentTreeSize: treeSize,
      checkpointTreeSize: latestCheckpoint?.tree_size || 0,
      error: checkpointError || null
    },

    // External anchor verification
    externalAnchors: {
      rekor: {
        verified: externalVerifications.filter(v => v.type === 'rekor' && v.valid).length,
        total: externalVerifications.filter(v => v.type === 'rekor').length,
        results: externalVerifications.filter(v => v.type === 'rekor').map(v => ({
          uuid: v.uuid,
          valid: v.valid,
          error: v.error || null,
          searchUrl: v.uuid ? `https://search.sigstore.dev/?uuid=${v.uuid}` : null
        }))
      }
    },

    // Metadata
    verifiedAt: new Date().toISOString(),
    canonicalization: "RFC8785-JCS",

    // Verification instructions for independent verification
    verificationInstructions: {
      description: "To independently verify this audit log:",
      steps: [
        "1. Fetch all entries from /api/audit/export",
        "2. For each entry, canonicalize using RFC 8785 JCS and compute SHA256(0x00 || canonical_json)",
        "3. Compare computed leaf hashes against stored leaf_hash values",
        "4. Build Merkle tree from leaf hashes using RFC 6962 (node_hash = SHA256(0x01 || left || right))",
        "5. Compare computed root against checkpoint root_hash",
        "6. Verify Rekor entries at search.sigstore.dev using the UUIDs provided"
      ],
      publicKeyUrl: "/api/transparency/public-key"
    }
  }, null, 2), {
    headers: { ...corsHeaders, "Content-Type": "application/json" }
  });
}

export async function handleVerifyRekor(
  uuid: string | null,
  hash: string | null,
  corsHeaders: Record<string, string>
): Promise<Response> {
  if (!uuid || !hash) {
    return new Response(
      JSON.stringify({ error: "Missing uuid or hash parameter" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  const result = await verifyRekorEntry(uuid, hash);

  return new Response(JSON.stringify({
    uuid,
    expectedHash: hash,
    ...result,
    verifiedAt: new Date().toISOString(),
    rekorUrl: `https://search.sigstore.dev/?uuid=${uuid}`
  }, null, 2), {
    headers: { ...corsHeaders, "Content-Type": "application/json" }
  });
}

export async function handleListCheckpoints(
  env: Env, 
  corsHeaders: Record<string, string>,
  page: number,
  limit: number
): Promise<Response> {
  const offset = (page - 1) * limit;
  const safeLimit = Math.min(Math.max(1, limit), 100);

  const countResult = await env.DB.prepare(
    "SELECT COUNT(*) as total FROM transparency_checkpoints"
  ).first<{ total: number }>();

  const total = countResult?.total || 0;

  const results = await env.DB.prepare(`
    SELECT * FROM transparency_checkpoints
    ORDER BY id DESC
    LIMIT ? OFFSET ?
  `).bind(safeLimit, offset).all<TransparencyCheckpoint>();

  const checkpoints = results.results.map(cp => ({
    ...cp,
    consistency_proof: cp.consistency_proof ? JSON.parse(cp.consistency_proof) : null,
    external_anchors: cp.external_anchors ? JSON.parse(cp.external_anchors) : []
  }));

  return new Response(JSON.stringify({
    checkpoints,
    pagination: {
      page,
      limit: safeLimit,
      total,
      totalPages: Math.ceil(total / safeLimit)
    }
  }, null, 2), {
    headers: { ...corsHeaders, "Content-Type": "application/json" }
  });
}

export async function handleGetCheckpoint(
  env: Env, 
  id: string, 
  corsHeaders: Record<string, string>
): Promise<Response> {
  if (!/^\d+$/.test(id)) {
    return new Response(
      JSON.stringify({ error: "Invalid checkpoint ID" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  const checkpoint = await env.DB.prepare(`
    SELECT * FROM transparency_checkpoints WHERE id = ?
  `).bind(id).first<TransparencyCheckpoint>();

  if (!checkpoint) {
    return new Response(
      JSON.stringify({ error: "Checkpoint not found" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  return new Response(JSON.stringify({
    ...checkpoint,
    external_anchors: checkpoint.external_anchors ? JSON.parse(checkpoint.external_anchors) : []
  }, null, 2), {
    headers: { ...corsHeaders, "Content-Type": "application/json" }
  });
}

// ============================================
// ROUTE DISPATCHER
// ============================================

export async function handleTransparencyRoutes(
  request: Request,
  env: Env,
  corsHeaders: HeadersInit
): Promise<Response | null> {
  const url = new URL(request.url);
  const headers = normalizeHeaders(corsHeaders);

  if (
    request.method === 'GET' &&
    url.pathname === '/api/transparency/tree-head'
  ) {
    return handleGetTreeHead(
      env,
      headers
    );
  }

  if (
    request.method === 'GET' &&
    url.pathname.startsWith('/api/transparency/proof/')
  ) {
    const entryId = url.pathname.split('/').pop()!;

    return handleGetInclusionProof(
      env,
      entryId,
      headers
    );
  }

  if (
    request.method === 'GET' &&
    url.pathname === '/api/transparency/consistency'
  ) {
    const oldSize = parseInt(
      url.searchParams.get('oldSize') ?? '0',
      10
    );

    const newSize = parseInt(
      url.searchParams.get('newSize') ?? '0',
      10
    );

    return handleGetConsistencyProof(
      env,
      oldSize,
      newSize,
      headers
    );
  }

  if (
    request.method === 'GET' &&
    url.pathname === '/api/transparency/checkpoints'
  ) {
    const page = Math.max(
      1,
      parseInt(url.searchParams.get('page') ?? '1', 10)
    );

    const limit = Math.max(
      1,
      parseInt(url.searchParams.get('limit') ?? '50', 10)
    );

    return handleListCheckpoints(
      env,
      headers,
      page,
      limit
    );
  }

  if (
    request.method === 'GET' &&
    url.pathname.startsWith('/api/transparency/checkpoint/')
  ) {
    const id = url.pathname.split('/').pop()!;

    return handleGetCheckpoint(
      env,
      id,
      headers
    );
  }

  if (
    request.method === 'POST' &&
    url.pathname === '/api/transparency/verify'
  ) {
    return handleTransparencyVerify(
      env,
      headers
    );
  }

  if (
    request.method === 'POST' &&
    url.pathname === '/api/transparency/verify-rekor'
  ) {
    const body = await request.json() as {
      uuid?: string;
      hash?: string;
    };

    return handleVerifyRekor(
      body.uuid ?? null,
      body.hash ?? null,
      headers
    );
  }

  return null;
}