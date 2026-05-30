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

import { Env} from "../types";

import { IncrementalMerkleTree, MerkleProof } from "./types";
import { computeNodeHash } from "./tree";

export function createIncrementalMerkleTree(env: Env): IncrementalMerkleTree {

  async function getTreeSize(): Promise<number> {
    const result = await env.DB.prepare(
      "SELECT COUNT(*) as count FROM merkle_nodes WHERE level = 0"
    ).first<{ count: number }>();
    return result?.count || 0;
  }

  async function getNode(level: number, idx: number): Promise<string | null> {
    const result = await env.DB.prepare(
      "SELECT hash FROM merkle_nodes WHERE level = ? AND idx = ?"
    ).bind(level, idx).first<{ hash: string }>();
    return result?.hash || null;
  }

  async function setNode(level: number, idx: number, hash: string): Promise<void> {
    await env.DB.prepare(`
      INSERT OR REPLACE INTO merkle_nodes (level, idx, hash, updated_at)
      VALUES (?, ?, ?, ?)
    `).bind(level, idx, hash, new Date().toISOString()).run();
  }

  async function getRoot(): Promise<string> {
    const size = await getTreeSize();
    if (size === 0) return '';

    // Find the highest level node
    const result = await env.DB.prepare(
      "SELECT hash FROM merkle_nodes ORDER BY level DESC, idx ASC LIMIT 1"
    ).first<{ hash: string }>();

    return result?.hash || '';
  }

  async function appendLeaf(leafHash: string): Promise<{ root: string; leafIndex: number }> {
    const leafIndex = await getTreeSize();

    // Insert leaf at level 0
    await setNode(0, leafIndex, leafHash);

    // Update path to root
    let currentLevel = 0;
    let currentIdx = leafIndex;
    let currentHash = leafHash;

    // Calculate max levels needed
    const maxLevels = Math.ceil(Math.log2(leafIndex + 2)) + 1;

    for (let i = 0; i < maxLevels; i++) {
      const isLeftChild = currentIdx % 2 === 0;
      const siblingIdx = isLeftChild ? currentIdx + 1 : currentIdx - 1;
      const parentIdx = Math.floor(currentIdx / 2);

      const siblingHash = siblingIdx >= 0 ? await getNode(currentLevel, siblingIdx) : null;

      let parentHash: string;
      if (siblingHash === null) {
        parentHash = currentHash;
      } else if (isLeftChild) {
        parentHash = await computeNodeHash(currentHash, siblingHash);
      } else {
        parentHash = await computeNodeHash(siblingHash, currentHash);
      }

      currentLevel++;
      currentIdx = parentIdx;
      currentHash = parentHash;

      await setNode(currentLevel, currentIdx, parentHash);

      // Stop if this node has no sibling at parent level
      if (parentIdx === 0 && (leafIndex + 1) <= Math.pow(2, currentLevel)) {
        break;
      }
    }

    return { root: currentHash, leafIndex };
  }

  async function getInclusionProof(leafIndex: number, treeSize?: number): Promise<MerkleProof | null> {
    const size = treeSize ?? await getTreeSize();
    if (leafIndex >= size || leafIndex < 0) return null;

    const leafHash = await getNode(0, leafIndex);
    if (!leafHash) return null;

    const siblings: Array<{ hash: string; position: 'left' | 'right' }> = [];
    let currentIdx = leafIndex;
    let currentLevel = 0;

    const maxLevel = Math.ceil(Math.log2(size));

    while (currentLevel < maxLevel) {
      const isLeftChild = currentIdx % 2 === 0;
      const siblingIdx = isLeftChild ? currentIdx + 1 : currentIdx - 1;

      if (siblingIdx >= 0) {
        const siblingHash = await getNode(currentLevel, siblingIdx);
        if (siblingHash !== null) {
          siblings.push({
            hash: siblingHash,
            position: isLeftChild ? 'right' : 'left'
          });
        }
      }

      currentIdx = Math.floor(currentIdx / 2);
      currentLevel++;
    }

    const root = await getRoot();

    return {
      leafHash,
      leafIndex,
      siblings,
      root,
      treeSize: size
    };
  }

  return { getRoot, getTreeSize, appendLeaf, getInclusionProof, getNode };
}