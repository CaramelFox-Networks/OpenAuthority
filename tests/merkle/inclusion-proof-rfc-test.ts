import { describe, it, expect } from 'vitest';

import {
  computeLeafHash,
  buildMerkleTree
} from '../../src/merkle/tree';

import {
  generateInclusionProof,
  verifyInclusionProof
} from '../../src/merkle/inclusion';

describe(
  'RFC6962 inclusion proof compatibility',
  () => {

    it(
      'verifies every leaf in a small tree',
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

        const tree =
          await buildMerkleTree(
            leafHashes
          );

        for (
          let leafIndex = 0;
          leafIndex < leafHashes.length;
          leafIndex++
        ) {

          const proof =
            await generateInclusionProof(
              leafHashes,
              leafIndex
            );

          console.log(
            '\nLeaf:',
            leafIndex
          );

          console.log(
            'leafHash:',
            proof.leafHash
          );

          console.log(
            'siblings:',
            JSON.stringify(
              proof.siblings,
              null,
              2
            )
          );

          console.log(
            'proofRoot:',
            proof.root
          );

          console.log(
            'treeRoot:',
            tree.root
          );

          expect(
            proof.root
          ).toBe(
            tree.root
          );

          expect(
            proof.leafHash
          ).toBe(
            leafHashes[leafIndex]
          );

          expect(
            await verifyInclusionProof(
              proof
            )
          ).toBe(true);
        }
      }
    );

    it(
      'verifies all leaves across multiple tree sizes',
      async () => {

        const leaves = [
          'A',
          'B',
          'C',
          'D',
          'E',
          'F',
          'G',
          'H'
        ];

        const leafHashes =
          await Promise.all(
            leaves.map(computeLeafHash)
          );

        for (
          let treeSize = 1;
          treeSize <= leaves.length;
          treeSize++
        ) {

          const currentLeaves =
            leafHashes.slice(
              0,
              treeSize
            );

          const tree =
            await buildMerkleTree(
              currentLeaves
            );

          for (
            let leafIndex = 0;
            leafIndex < treeSize;
            leafIndex++
          ) {

            const proof =
              await generateInclusionProof(
                currentLeaves,
                leafIndex
              );

            const valid =
              await verifyInclusionProof(
                proof
              );

            if (!valid) {

              console.log(
                '\nFAILED'
              );

              console.log(
                'treeSize:',
                treeSize
              );

              console.log(
                'leafIndex:',
                leafIndex
              );

              console.log(
                JSON.stringify(
                  proof,
                  null,
                  2
                )
              );
            }

            expect(
              proof.root
            ).toBe(
              tree.root
            );

            expect(
              valid
            ).toBe(true);
          }
        }
      }
    );

  }
);