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

import { ExternalAnchor, AuditEventType } from "../types";

export interface IncrementalMerkleTree {
  getRoot(): Promise<string>;
  getTreeSize(): Promise<number>;
  appendLeaf(leafHash: string): Promise<{ root: string; leafIndex: number }>;
  getInclusionProof(leafIndex: number, treeSize?: number): Promise<MerkleProof | null>;
  getNode(level: number, idx: number): Promise<string | null>;
}

export interface MerkleProof {
  leafHash: string;
  leafIndex: number;
  siblings: Array<{
    hash: string;
    position: 'left' | 'right';
  }>;
  root: string;
  treeSize: number;
}

export interface ConsistencyProof {
  oldSize: number;
  newSize: number;
  oldRoot: string;
  newRoot: string;
  proof: string[];
}

export interface SignedTreeHead {
  version: string;
  treeSize: number;
  rootHash: string;
  timestamp: string;
  signature?: string;
  signatureAlgorithm?: string;
  canonicalization?: string;
  previousSTH?: string;
  externalAnchors?: ExternalAnchor[];
}

export interface TransparencyCheckpoint {
  id: number;
  tree_size: number;
  root_hash: string;
  timestamp: string;
  signature: string | null;
  previous_checkpoint_hash: string;
  checkpoint_hash: string;
  external_anchors: string | null;
  rekor_entry_uuid?: string;
  rekor_log_index?: number;
  consistency_proof?: string;
}

export interface VerifiableLogEntry {
  id: number;
  ca_id: number;
  check_type: AuditEventType;
  target: string;
  success: boolean;
  details: string;
  checked_at: string;
  nonce: string;
  leaf_hash: string;
  tree_position: number;
  inclusion_proof?: MerkleProof;
}

export interface RekorEntry {
  uuid: string;
  logIndex: number;
  integratedTime: number;
  body: string;
  submittedBody?: string;
  inclusionProof: {
    logIndex: number;
    rootHash: string;
    treeSize: number;
    hashes: string[];
  };
}

export interface TrustStoreSnapshot {
  version: string;
  generatedAt: string;
  treeHead: SignedTreeHead;
  certificates: Array<{
    fingerprint_sha256: string;
    subject: string;
    pem_data: string;
    addedAt: string;
    lastVerified: string;
    inclusionProof: MerkleProof;
  }>;
  auditLog: VerifiableLogEntry[];
  validationRules: {
    minSuccessfulVerifications: number;
    probationaryPeriodDays: number;
    verificationStalenessHours: number;
    maxConsecutiveFailures: number;
  };
  externalAnchors: ExternalAnchor[];
  contentHash: string;
  signature?: string;
  canonicalization?: string;
}

export interface ValidatedDomain {
  original: string;
  normalized: string;
  labels: string[];
  isValid: boolean;
  error?: string;
}