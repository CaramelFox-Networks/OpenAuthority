import { describe, it, expect } from 'vitest';
import crypto from 'crypto';

import {
  buildMerkleTree
} from '../../src/merkle';

import {
  hashFullSubtree
} from '../../src/merkle/consistency';

function randomHash(): string {
  return crypto.randomBytes(32).toString('hex');
}

describe('Merkle tree compatibility', () => {

  it('buildMerkleTree matches hashFullSubtree for sizes 1..1000', async () => {

    for (let size = 1; size <= 1000; size++) {

      const leaves = Array.from(
        { length: size },
        () => randomHash()
      );

      const { root } =
        await buildMerkleTree(leaves);

      const subtreeRoot =
        await hashFullSubtree(
          leaves,
          0,
          leaves.length
        );

      expect(
        subtreeRoot,
        `Mismatch at tree size ${size}`
      ).toBe(root);
    }

  },
120000
);

});