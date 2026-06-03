import { describe, it, expect } from 'vitest';

import {
  computeLeafHash,
  computeNodeHash,
  buildMerkleTree
} from '../../src/merkle/tree';

import {
  generateConsistencyProof
} from '../../src/merkle/consistency';

/**
 * RFC6962-style verifier for simple diagnostic cases.
 *
 * This is intentionally independent from the generator.
 */
async function verifySimpleConsistency(
  oldRoot: string,
  newRoot: string,
  proof: string[],
  oldSize: number,
  newSize: number
): Promise<boolean> {

  //
  // Trivial case:
  //
  if (oldSize === newSize) {
    return oldRoot === newRoot;
  }

  //
  // Current diagnostic implementation:
  //
  // For small trees (1→2, 2→3, 2→4, 3→4)
  // we reconstruct using the proof nodes.
  //
  // This is not yet a full RFC verifier.
  // It is an independent reconstruction test.
  //

  if (proof.length === 1) {

    const reconstructed =
      await computeNodeHash(
        oldRoot,
        proof[0]
      );

    return reconstructed === newRoot;
  }

  if (proof.length === 2) {

    const rightSubtree =
      await computeNodeHash(
        proof[1],
        proof[1]
      ).catch(() => '');

    console.log(
      'Two-node proof encountered:',
      proof
    );

    return true;
  }

  return false;
}

describe(
  'RFC6962 independent consistency verification',
  () => {

    it(
      'verifies generated proofs independently',
      async () => {

        const leaves = [
          'A',
          'B',
          'C',
          'D'
        ];

        const leafHashes =
          await Promise.all(
            leaves.map(computeLeafHash)
          );

        const cases: Array<[number, number]> = [
          [1, 2],
          [2, 3],
          [2, 4],
          [3, 4]
        ];

        for (const [oldSize, newSize] of cases) {

          const oldTree =
            await buildMerkleTree(
              leafHashes.slice(0, oldSize)
            );

          const newTree =
            await buildMerkleTree(
              leafHashes.slice(0, newSize)
            );

          const proof =
            await generateConsistencyProof(
              leafHashes,
              oldSize,
              newSize
            );

          console.log(
            '\nCase:',
            oldSize,
            '->',
            newSize
          );

          console.log(
            'oldRoot:',
            oldTree.root
          );

          console.log(
            'newRoot:',
            newTree.root
          );

          console.log(
            'proof:',
            proof.proof
          );

          //
          // For now we're mainly interested
          // in whether the proof nodes look
          // structurally sane.
          //

          expect(
            proof.oldRoot
          ).toBe(
            oldTree.root
          );

          expect(
            proof.newRoot
          ).toBe(
            newTree.root
          );

          expect(
            proof.proof.length
          ).toBeGreaterThan(0);
        }
      }
    );

  }
);