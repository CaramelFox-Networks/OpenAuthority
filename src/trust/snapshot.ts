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

import { Env, CertificateAuthority, ExternalAnchor, } from "../types";
import { MAX_EXPORT_CERTIFICATES, MERKLE_TREE_VERSION, MIN_SUCCESSFUL_VERIFICATIONS, PROBATIONARY_PERIOD_DAYS, VERIFICATION_STALENESS_HOURS, MAX_CONSECUTIVE_FAILURES, MAX_SNAPSHOT_SIZE, MAX_PROOF_SIBLINGS } from "../config";
import { MerkleProof, TransparencyCheckpoint, TrustStoreSnapshot, getInclusionProofForEntry, VerifiableLogEntry, buildMerkleTree, computeLeafHash, verifyInclusionProof, createSignedTreeHead } from "../merkle";
import { verifyCertificateEligibility } from "./eligibility";
import { sha256, canonicalizeJSON } from "../utils";

// ============================================================
// REPRODUCIBLE TRUST STORE SNAPSHOT
// ============================================================

export async function generateTrustStoreSnapshot(env: Env): Promise<TrustStoreSnapshot> {
  const latestCheckpoint = await env.DB.prepare(`
    SELECT * FROM transparency_checkpoints ORDER BY id DESC LIMIT 1
  `).first<TransparencyCheckpoint>();

  const certificates = await env.DB.prepare(`
    SELECT * FROM certificate_authorities WHERE status = 'active' LIMIT ?
  `).bind(MAX_EXPORT_CERTIFICATES).all<CertificateAuthority>();

  const eligibleCerts: TrustStoreSnapshot['certificates'] = [];

  for (const cert of certificates.results) {
    const eligibility = await verifyCertificateEligibility(env, cert);
    if (!eligibility.eligible) continue;

    const addedEntry = await env.DB.prepare(`
      SELECT id, tree_position FROM verification_log 
      WHERE ca_id = ? AND check_type = 'certificate_added' LIMIT 1
    `).first<{ id: number; tree_position: number }>(cert.id);

    let inclusionProof: MerkleProof | undefined;
    if (addedEntry && latestCheckpoint) {
      inclusionProof = await getInclusionProofForEntry(env, addedEntry.id) || undefined;
    }

    eligibleCerts.push({
      fingerprint_sha256: cert.fingerprint_sha256,
      subject: cert.subject,
      pem_data: cert.pem_data,
      addedAt: cert.created_at,
      lastVerified: cert.last_check_at,
      inclusionProof: inclusionProof!
    });
  }

  eligibleCerts.sort((a, b) => a.fingerprint_sha256.localeCompare(b.fingerprint_sha256));

  const auditEntries = await env.DB.prepare(`
    SELECT * FROM verification_log ORDER BY tree_position ASC
  `).all<any>();

  const auditLog: VerifiableLogEntry[] = auditEntries.results.map((e: any) => ({
    id: e.id,
    ca_id: e.ca_id,
    check_type: e.check_type,
    target: e.target,
    success: e.success === 1,
    details: e.details,
    checked_at: e.checked_at,
    nonce: e.nonce,
    leaf_hash: e.leaf_hash,
    tree_position: e.tree_position
  }));

  const checkpoints = await env.DB.prepare(`
    SELECT external_anchors FROM transparency_checkpoints WHERE external_anchors IS NOT NULL
  `).all<{ external_anchors: string }>();

  const allAnchors: ExternalAnchor[] = [];
  for (const cp of checkpoints.results) {
    try {
      allAnchors.push(...JSON.parse(cp.external_anchors));
    } catch {}
  }

  const leafHashes = auditLog.filter(e => e.leaf_hash).map(e => e.leaf_hash);
  const { root } = await buildMerkleTree(leafHashes);
  const treeHead = await createSignedTreeHead(env, leafHashes.length, root, latestCheckpoint?.checkpoint_hash);

  const snapshot: TrustStoreSnapshot = {
    version: MERKLE_TREE_VERSION,
    generatedAt: new Date().toISOString(),
    treeHead,
    certificates: eligibleCerts,
    auditLog,
    validationRules: {
      minSuccessfulVerifications: MIN_SUCCESSFUL_VERIFICATIONS,
      probationaryPeriodDays: PROBATIONARY_PERIOD_DAYS,
      verificationStalenessHours: VERIFICATION_STALENESS_HOURS,
      maxConsecutiveFailures: MAX_CONSECUTIVE_FAILURES
    },
    externalAnchors: allAnchors,
    contentHash: '',
    canonicalization: 'RFC8785-JCS'
  };

  const snapshotForHash = { ...snapshot };
  delete (snapshotForHash as any).contentHash;
  delete (snapshotForHash as any).signature;
  snapshot.contentHash = await sha256(canonicalizeJSON(snapshotForHash));

  const snapshotJson = JSON.stringify(snapshot);
  if (snapshotJson.length > MAX_SNAPSHOT_SIZE) {
    throw new Error(`Snapshot size ${snapshotJson.length} exceeds maximum of ${MAX_SNAPSHOT_SIZE}`);
  }

  if (env.SIGNING_PRIVATE_KEY) {
    try {
      const keyData = Uint8Array.from(atob(env.SIGNING_PRIVATE_KEY), c => c.charCodeAt(0));
      const privateKey = await crypto.subtle.importKey(
        "pkcs8", keyData, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]
      );
      const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        privateKey,
        new TextEncoder().encode(snapshot.contentHash)
      );
      snapshot.signature = btoa(String.fromCharCode(...new Uint8Array(signature)));
    } catch (e) {
      console.error("Failed to sign snapshot:", e);
    }
  }

  return snapshot;
}

export async function verifyTrustStoreSnapshot(
  snapshot: TrustStoreSnapshot,
  publicKeyBase64?: string
): Promise<{
  valid: boolean;
  errors: string[];
  certificatesVerified: number;
  auditEntriesVerified: number;
}> {
  const errors: string[] = [];
  let certificatesVerified = 0;
  let auditEntriesVerified = 0;

  const snapshotForHash = { ...snapshot };
  delete (snapshotForHash as any).contentHash;
  delete (snapshotForHash as any).signature;
  const computedContentHash = await sha256(canonicalizeJSON(snapshotForHash));

  if (computedContentHash !== snapshot.contentHash) {
    errors.push('Content hash mismatch - snapshot may have been tampered');
  }

  if (publicKeyBase64 && snapshot.signature) {
    try {
      const keyData = Uint8Array.from(atob(publicKeyBase64), c => c.charCodeAt(0));
      const publicKey = await crypto.subtle.importKey(
        "spki", keyData, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]
      );
      const signatureBytes = Uint8Array.from(atob(snapshot.signature), c => c.charCodeAt(0));
      const isValid = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        publicKey, signatureBytes,
        new TextEncoder().encode(snapshot.contentHash)
      );
      if (!isValid) errors.push('Snapshot signature verification failed');
    } catch (e) {
      errors.push(`Signature verification error: ${e}`);
    }
  }

  const leafHashes: string[] = [];
  for (const entry of snapshot.auditLog) {
    if (!entry.leaf_hash || !entry.nonce) continue;

    const entryDataObj = {
      ca_id: entry.ca_id,
      check_type: entry.check_type,
      target: entry.target,
      success: entry.success,
      details: entry.details,
      checked_at: entry.checked_at,
      nonce: entry.nonce,
      tree_position: entry.tree_position
    };
    const entryData = canonicalizeJSON(entryDataObj);
    const computedLeafHash = await computeLeafHash(entryData);

    if (computedLeafHash !== entry.leaf_hash) {
      errors.push(`Audit entry ${entry.id}: leaf hash mismatch`);
    } else {
      auditEntriesVerified++;
    }

    leafHashes.push(entry.leaf_hash);
  }

  const { root: computedRoot } = await buildMerkleTree(leafHashes);
  if (computedRoot !== snapshot.treeHead.rootHash) {
    errors.push(`Tree root mismatch: computed ${computedRoot}, expected ${snapshot.treeHead.rootHash}`);
  }

  for (const cert of snapshot.certificates) {
    if (!cert.inclusionProof) {
      errors.push(`Certificate ${cert.fingerprint_sha256.substring(0, 16)}...: missing inclusion proof`);
      continue;
    }

    if (cert.inclusionProof.siblings.length > MAX_PROOF_SIBLINGS) {
      errors.push(`Certificate ${cert.fingerprint_sha256.substring(0, 16)}...: proof too large`);
      continue;
    }

    const proofValid = await verifyInclusionProof(cert.inclusionProof);
    if (!proofValid) {
      errors.push(`Certificate ${cert.fingerprint_sha256.substring(0, 16)}...: inclusion proof invalid`);
    } else {
      certificatesVerified++;
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    certificatesVerified,
    auditEntriesVerified
  };
}