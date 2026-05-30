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
import { MAX_MERKLE_TREE_SIZE, MAX_PROOF_SIBLINGS } from "../config";
import { buildMerkleTree, computeNodeHash } from "./tree";
import { MerkleProof } from "./types";
import { createIncrementalMerkleTree } from "./incremental";

export async function generateInclusionProof(
  leafHashes: string[],
  leafIndex: number
): Promise<MerkleProof> {
  if (leafIndex < 0 || leafIndex >= leafHashes.length) {
    throw new Error(`Invalid leaf index: ${leafIndex}`);
  }

  if (leafHashes.length > MAX_MERKLE_TREE_SIZE) {
    throw new Error(`Tree size exceeds maximum of ${MAX_MERKLE_TREE_SIZE}`);
  }

  const { root, layers } = await buildMerkleTree(leafHashes);
  const siblings: Array<{ hash: string; position: 'left' | 'right' }> = [];

  let currentIndex = leafIndex;

  for (let layerIndex = 0; layerIndex < layers.length - 1; layerIndex++) {
    if (siblings.length >= MAX_PROOF_SIBLINGS) {
      throw new Error(`Proof exceeds maximum siblings of ${MAX_PROOF_SIBLINGS}`);
    }

    const layer = layers[layerIndex];
    const isLeftNode = currentIndex % 2 === 0;
    const siblingIndex = isLeftNode ? currentIndex + 1 : currentIndex - 1;

    if (siblingIndex < layer.length) {
      siblings.push({
        hash: layer[siblingIndex],
        position: isLeftNode ? 'right' : 'left'
      });
    }

    currentIndex = Math.floor(currentIndex / 2);
  }

  return {
    leafHash: leafHashes[leafIndex],
    leafIndex,
    siblings,
    root,
    treeSize: leafHashes.length
  };
}

export async function verifyInclusionProof(proof: MerkleProof): Promise<boolean> {
  if (proof.siblings.length > MAX_PROOF_SIBLINGS) {
    throw new Error(`Proof has too many siblings: ${proof.siblings.length}`);
  }

  let currentHash = proof.leafHash;

  for (const sibling of proof.siblings) {
    if (sibling.position === 'left') {
      currentHash = await computeNodeHash(sibling.hash, currentHash);
    } else {
      currentHash = await computeNodeHash(currentHash, sibling.hash);
    }
  }

  return currentHash === proof.root;
}

export async function getInclusionProofForEntry(
  env: Env,
  entryId: number
): Promise<MerkleProof | null> {
  const entry = await env.DB.prepare(`
    SELECT tree_position, leaf_hash FROM verification_log WHERE id = ?
  `).bind(entryId).first<{ tree_position: number; leaf_hash: string }>();

  if (!entry || !entry.leaf_hash) return null;

  const tree = createIncrementalMerkleTree(env);
  return tree.getInclusionProof(entry.tree_position);
}