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

import { Env, ExternalAnchor } from "../types";
import { SignedTreeHead, TransparencyCheckpoint } from "./types";
import { MERKLE_TREE_VERSION, CHECKPOINT_INTERVAL_ENTRIES, CHECKPOINT_INTERVAL_HOURS } from "../config/";
import { createIncrementalMerkleTree } from "./incremental";
import { canonicalizeJSON, sha256 } from "../utils";
import { generateConsistencyProof } from "./consistency";
import { submitToRekor, createRFC3161Timestamp } from "../rekor";

// ============================================================
// SIGNED TREE HEAD MANAGEMENT
// ============================================================

export async function createSignedTreeHead(
  env: Env,
  treeSize: number,
  rootHash: string,
  previousSTHHash?: string
): Promise<SignedTreeHead> {
  const sth: SignedTreeHead = {
    version: MERKLE_TREE_VERSION,
    treeSize,
    rootHash,
    timestamp: new Date().toISOString(),
    previousSTH: previousSTHHash || 'GENESIS',
    canonicalization: 'RFC8785-JCS'
  };

  if (env.SIGNING_PRIVATE_KEY) {
    try {
      const keyData = Uint8Array.from(atob(env.SIGNING_PRIVATE_KEY), c => c.charCodeAt(0));
      const privateKey = await crypto.subtle.importKey(
        "pkcs8",
        keyData,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign"]
      );

      const sthForSigning = {
        version: sth.version,
        treeSize: sth.treeSize,
        rootHash: sth.rootHash,
        timestamp: sth.timestamp,
        previousSTH: sth.previousSTH
      };
      const sthData = canonicalizeJSON(sthForSigning);

      const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        privateKey,
        new TextEncoder().encode(sthData)
      );

      sth.signature = btoa(String.fromCharCode(...new Uint8Array(signature)));
      sth.signatureAlgorithm = "ECDSA-P256-SHA256";
    } catch (e) {
      console.error("Failed to sign STH:", e);
    }
  }

  return sth;
}

// ============================================================
// CHECKPOINT MANAGEMENT 
// ============================================================

export async function createCheckpoint(env: Env): Promise<TransparencyCheckpoint | null> {
  const tree = createIncrementalMerkleTree(env);
  const treeSize = await tree.getTreeSize();

  if (treeSize === 0) return null;

  const root = await tree.getRoot();

  const prevCheckpoint = await env.DB.prepare(`
    SELECT checkpoint_hash, tree_size
    FROM transparency_checkpoints
    ORDER BY id DESC LIMIT 1
  `).first<{ checkpoint_hash: string; tree_size: number; }>();

  const previousCheckpointHash = prevCheckpoint?.checkpoint_hash || 'GENESIS';

  const sth = await createSignedTreeHead(env, treeSize, root, previousCheckpointHash);

  const checkpointDataObj = {
    tree_size: treeSize,
    root_hash: root,
    timestamp: sth.timestamp,
    previous_checkpoint_hash: previousCheckpointHash
  };
  const checkpointData = canonicalizeJSON(checkpointDataObj);
  const checkpointHash = await sha256(checkpointData);

  let consistencyProof: string | null = null;

  if (prevCheckpoint) {
    const entries = await env.DB.prepare(`
      SELECT leaf_hash FROM verification_log
      WHERE leaf_hash IS NOT NULL
      ORDER BY tree_position ASC
    `).all<{ leaf_hash: string }>();

    const leafHashes = entries.results.map((e: {leaf_hash: string}) => e.leaf_hash);

    const proof = await generateConsistencyProof(
      leafHashes,
      prevCheckpoint.tree_size,
      treeSize
    );

    consistencyProof = JSON.stringify({
      from_tree_size: prevCheckpoint.tree_size,
      to_tree_size: treeSize,
      proof
    });
  }

  const externalAnchors: ExternalAnchor[] = [];

  const rekorEntry = await submitToRekor(env, checkpointHash, checkpointData);
  if (rekorEntry) {
    externalAnchors.push({
      type: 'rekor',
      timestamp: new Date(rekorEntry.integratedTime * 1000).toISOString(),
      proof: JSON.stringify({
        uuid: rekorEntry.uuid,
        logIndex: rekorEntry.logIndex,
        inclusionProof: rekorEntry.inclusionProof
      }),
      submitted_body: rekorEntry.submittedBody,
      serviceUrl: 'https://rekor.sigstore.dev'
    });
  }

  const rfc3161 = await createRFC3161Timestamp(env, checkpointHash);
  if (rfc3161) externalAnchors.push(rfc3161);

  await env.DB.prepare(`
    INSERT INTO transparency_checkpoints (
      tree_size, root_hash, timestamp, signature, 
      previous_checkpoint_hash, checkpoint_hash, external_anchors,
      consistency_proof, rekor_entry_uuid, rekor_log_index
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    treeSize, root, sth.timestamp, sth.signature || null,
    previousCheckpointHash, checkpointHash, JSON.stringify(externalAnchors),
    consistencyProof, rekorEntry?.uuid || null, rekorEntry?.logIndex || null
  ).run();

  console.log(`Checkpoint created: tree_size=${treeSize}, root=${root.substring(0, 16)}...`);

  return await env.DB.prepare(`
    SELECT * FROM transparency_checkpoints WHERE checkpoint_hash = ?
  `).bind(checkpointHash).first<TransparencyCheckpoint>();
}

export async function shouldCreateCheckpoint(env: Env): Promise<boolean> {
  const lastCheckpoint = await env.DB.prepare(`
    SELECT tree_size, timestamp FROM transparency_checkpoints 
    ORDER BY id DESC LIMIT 1
  `).first<{ tree_size: number; timestamp: string }>();

  const currentEntryCount = await env.DB.prepare(`
    SELECT COUNT(*) as count FROM verification_log WHERE leaf_hash IS NOT NULL
  `).first<{ count: number }>();

  const entryCount = currentEntryCount?.count || 0;

  if (!lastCheckpoint) return entryCount > 0;

  const entriesSinceCheckpoint = entryCount - lastCheckpoint.tree_size;
  if (entriesSinceCheckpoint >= CHECKPOINT_INTERVAL_ENTRIES) return true;

  const lastCheckpointTime = new Date(lastCheckpoint.timestamp);
  const hoursSinceCheckpoint = (Date.now() - lastCheckpointTime.getTime()) / (1000 * 60 * 60);
  if (hoursSinceCheckpoint >= CHECKPOINT_INTERVAL_HOURS && entriesSinceCheckpoint > 0) return true;

  return false;
}