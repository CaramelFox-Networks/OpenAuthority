import { describe, it, expect } from 'vitest';
import crypto from 'crypto';

import {
  generateConsistencyProof
} from '../../src/merkle/consistency';

describe(
  'Consistency proof diagnostics',
  () => {

    it(
      'prints smallest proofs',
      async () => {

        function randomHash(): string {
          return crypto.randomBytes(32).toString('hex');
        }

        const leaves =
          Array.from(
            { length: 10 },
            () => randomHash()
          );

        const cases = [
          [1, 2],
          [1, 3],
          [1, 4],
          [2, 3],
          [2, 4],
          [3, 4],
          [4, 5],
          [4, 8]
        ];

        for (const [oldSize, newSize] of cases) {

          const proof =
            await generateConsistencyProof(
              leaves,
              oldSize,
              newSize
            );

          console.log(
            JSON.stringify(
              {
                oldSize,
                newSize,
                proofLength:
                  proof.proof.length,
                proof:
                  proof.proof
              },
              null,
              2
            )
          );
        }

        expect(true).toBe(true);
      }
    );

  }
);