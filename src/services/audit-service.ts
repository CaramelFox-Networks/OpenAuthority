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

import { Env, AuditEventType } from "../types";
import { MAX_AUDIT_LOG_ENTRY_SIZE } from "../config"
import { shouldCreateCheckpoint, computeLeafHash, createIncrementalMerkleTree, createCheckpoint } from "../merkle";
import { canonicalizeJSON, generateNonce } from "../utils";
import { sendDiscordNotification } from "../notifications"

// ============================================================
// AUDIT LOG ENTRY CREATION WITH MERKLE TREE
// ============================================================

export async function createAuditLogEntry(
  env: Env,
  caId: number,
  checkType: AuditEventType,
  target: string,
  success: boolean,
  details: string
): Promise<void> {
  const safeDetails = details.length > MAX_AUDIT_LOG_ENTRY_SIZE 
    ? details.substring(0, MAX_AUDIT_LOG_ENTRY_SIZE - 3) + '...'
    : details;

  const now = new Date().toISOString();
  const nonce = generateNonce();

  // Use incremental tree for position
  const tree = createIncrementalMerkleTree(env);
  const treePosition = await tree.getTreeSize();

  const entryDataObj = {
    ca_id: caId,
    check_type: checkType,
    target,
    success,
    details: safeDetails,
    checked_at: now,
    nonce,
    tree_position: treePosition
  };
  const entryData = canonicalizeJSON(entryDataObj);
  const leafHash = await computeLeafHash(entryData);

  // Insert log entry
  await env.DB.prepare(`
    INSERT INTO verification_log (
      ca_id, check_type, target, success, details, checked_at, 
      nonce, leaf_hash, tree_position
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(caId, checkType, target, success ? 1 : 0, safeDetails, now, nonce, leafHash, treePosition).run();

  // Incrementally update Merkle tree - O(log n) instead of O(n)
  await tree.appendLeaf(leafHash);

  if (await shouldCreateCheckpoint(env)) {
    await createCheckpoint(env);
  }

  await sendDiscordNotification(env, checkType, target, success, safeDetails);
}

export function buildVerificationSummary(
  localValid: boolean,
  checkpointValid: boolean,
  entriesVerified: number,
  totalEntries: number,
  externalVerifications: Array<{ type: string; valid: boolean; error?: string }>
): string {
  const rekorResults = externalVerifications.filter(v => v.type === 'rekor');
  const rekorValid = rekorResults.filter(v => v.valid).length;
  const rekorTotal = rekorResults.length;

  if (!localValid) {
    return "FAILED: Local audit log integrity check failed. Entries may have been tampered with.";
  }
  if (!checkpointValid) {
    return "FAILED: Merkle tree root does not match latest checkpoint.";
  }
  if (rekorTotal > 0 && rekorValid === 0) {
    return `WARNING: ${entriesVerified} local entries verified, but Rekor anchors could not be validated.`;
  }
  if (rekorTotal === 0) {
    return `VERIFIED: ${entriesVerified}/${totalEntries} entries validated. Merkle root matches checkpoint. No external anchors to verify.`;
  }

  return `VERIFIED: ${entriesVerified}/${totalEntries} entries validated. Merkle root matches checkpoint. ${rekorValid}/${rekorTotal} Rekor anchors confirmed.`;
}