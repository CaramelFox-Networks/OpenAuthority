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

import { MAX_MERKLE_TREE_SIZE } from "../config";
import { buildMerkleTree, computeNodeHash } from "./tree";
import { ConsistencyProof } from "./types";

export async function generateConsistencyProof(
  leafHashes: string[],
  oldSize: number,
  newSize: number
): Promise<ConsistencyProof> {

  if (oldSize <= 0) {
    throw new Error('oldSize must be > 0');
  }

  if (oldSize > newSize) {
    throw new Error('oldSize cannot exceed newSize');
  }

  if (newSize > leafHashes.length) {
    throw new Error('newSize exceeds available leaves');
  }

  if (newSize > MAX_MERKLE_TREE_SIZE) {
    throw new Error(
      `Tree size ${newSize} exceeds maximum`
    );
  }

  const oldLeaves = leafHashes.slice(0, oldSize);
  const newLeaves = leafHashes.slice(0, newSize);

  const { root: oldRoot } = await buildMerkleTree(oldLeaves);
  const { root: newRoot } = await buildMerkleTree(newLeaves);

  const proof = await buildConsistencyProofRecursive(
    leafHashes,
    oldSize,
    newSize,
    0
  );

  return {
    oldSize,
    newSize,
    oldRoot,
    newRoot,
    proof
  };
}

async function buildConsistencyProofRecursive(
  leaves: string[],
  m: number,
  n: number,
  start: number
): Promise<string[]> {

  if (m === n) {
    return [];
  }

  const k = largestPowerOfTwoLessThan(n);

  // ----------------------------------------------------------
  // Entire old tree fits inside LEFT subtree
  // ----------------------------------------------------------

  if (m <= k) {

    const proof = await buildConsistencyProofRecursive(
      leaves,
      m,
      k,
      start
    );

    const rightHash = await hashFullSubtree(
      leaves,
      start + k,
      n - k
    );

    proof.push(rightHash);

    return proof;
  }

  // ----------------------------------------------------------
  // Old tree spans LEFT + RIGHT
  // ----------------------------------------------------------

  const proof = await buildConsistencyProofRecursive(
    leaves,
    m - k,
    n - k,
    start + k
  );

  const leftHash = await hashFullSubtree(
    leaves,
    start,
    k
  );

  proof.push(leftHash);

  return proof;
}

function largestPowerOfTwoLessThan(n: number): number {
  let k = 1;

  while ((k << 1) < n) {
    k <<= 1;
  }

  return k;
}

export async function hashFullSubtree(
  leaves: string[],
  start: number,
  size: number
): Promise<string> {
  if (size === 1) {
    return leaves[start];
  }

  const k = largestPowerOfTwoLessThan(size);

  const left = await hashFullSubtree(leaves, start, k);

  const right = await hashFullSubtree(
    leaves,
    start + k,
    size - k
  );

  return computeNodeHash(left, right);
}