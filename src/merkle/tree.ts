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

import { MAX_AUDIT_LOG_ENTRY_SIZE, MAX_MERKLE_TREE_SIZE } from "../config";
import { sha256 } from "../utils";

// ============================================================
// MERKLE TREE IMPLEMENTATION (RFC 6962 Compatible)
// ============================================================

export async function computeLeafHash(leafData: string): Promise<string> {
  if (leafData.length > MAX_AUDIT_LOG_ENTRY_SIZE) {
    throw new Error(`Leaf data exceeds maximum size of ${MAX_AUDIT_LOG_ENTRY_SIZE} bytes`);
  }
  const prefixedData = '\x00' + leafData;
  return sha256(prefixedData);
}

export async function computeNodeHash(left: string, right: string): Promise<string> {
  const prefixedData = '\x01' + left + right;
  return sha256(prefixedData);
}

export async function buildMerkleTree(leafHashes: string[]): Promise<{
  root: string;
  layers: string[][];
}> {
  if (leafHashes.length === 0) {
    return { root: '', layers: [] };
  }

  if (leafHashes.length > MAX_MERKLE_TREE_SIZE) {
    throw new Error(`Tree size ${leafHashes.length} exceeds maximum of ${MAX_MERKLE_TREE_SIZE}`);
  }

  const layers: string[][] = [leafHashes];
  let currentLayer = leafHashes;

  while (currentLayer.length > 1) {
    const nextLayer: string[] = [];

    for (let i = 0; i < currentLayer.length; i += 2) {
      if (i + 1 < currentLayer.length) {
        const hash = await computeNodeHash(currentLayer[i], currentLayer[i + 1]);
        nextLayer.push(hash);
      } else {
        nextLayer.push(currentLayer[i]);
      }
    }

    layers.push(nextLayer);
    currentLayer = nextLayer;
  }

  return {
    root: currentLayer[0],
    layers
  };
}