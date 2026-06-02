import { describe, it, expect } from 'vitest';
import crypto from 'crypto';

import {
  generateConsistencyProof,
  hashFullSubtree
} from '../../src/merkle/consistency';

describe(
  'OpenAuthority consistency proof soundness',
  () => {

    it(
      'proof nodes are actual subtree roots',
      async () => {

        function randomHash(): string {
          return crypto.randomBytes(32).toString('hex');
        }

        for (let newSize = 2; newSize <= 100; newSize++) {

          const leaves =
            Array.from(
              { length: newSize },
              () => randomHash()
            );

          for (
            let oldSize = 1;
            oldSize < newSize;
            oldSize++
          ) {

            const cp =
              await generateConsistencyProof(
                leaves,
                oldSize,
                newSize
              );

            //
            // Every proof node should correspond
            // to some subtree root in the tree.
            //

            const subtreeRoots =
              new Set<string>();

            async function collect(
              start: number,
              size: number
            ): Promise<void> {

              const root =
                await hashFullSubtree(
                  leaves,
                  start,
                  size
                );

              subtreeRoots.add(root);

              if (size === 1) {
                return;
              }

              let k = 1;

              while ((k << 1) < size) {
                k <<= 1;
              }

              await collect(start, k);

              await collect(
                start + k,
                size - k
              );
            }

            await collect(0, newSize);

            for (const node of cp.proof) {

              expect(
                subtreeRoots.has(node),
                `old=${oldSize} new=${newSize}`
              ).toBe(true);
            }
          }
        }
      },
      120000
    );

  }
);