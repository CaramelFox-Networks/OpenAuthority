import { describe, it, expect } from 'vitest';
import crypto from 'crypto';

import {
  generateConsistencyProof
} from '../../src/merkle/consistency';

import {
  hashFullSubtree
} from '../../src/merkle/';

function largestPowerOfTwoLessThan(
  n: number
): number {

  let k = 1;

  while ((k << 1) < n) {
    k <<= 1;
  }

  return k;
}

async function referenceRFC6962Proof(
  leaves: string[],
  m: number,
  n: number,
  start = 0
): Promise<string[]> {

  if (m === n) {
    return [];
  }

  const k =
    largestPowerOfTwoLessThan(n);

  //
  // Entire old tree is in left subtree
  //
  if (m <= k) {

    const proof =
      await referenceRFC6962Proof(
        leaves,
        m,
        k,
        start
      );

    proof.push(
      await hashFullSubtree(
        leaves,
        start + k,
        n - k
      )
    );

    return proof;
  }

  //
  // Old tree spans left + right
  //
  const proof =
    await referenceRFC6962Proof(
      leaves,
      m - k,
      n - k,
      start + k
    );

  proof.unshift(
    await hashFullSubtree(
      leaves,
      start,
      k
    )
  );

  return proof;
}

describe(
  'RFC6962 proof generator',
  () => {

    it(
      'matches reference implementation',
      async () => {

        function randomHash(): string {

          return crypto
            .randomBytes(32)
            .toString('hex');
        }

        for (
          let newSize = 2;
          newSize <= 30;
          newSize++
        ) {

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

            const generated =
              await generateConsistencyProof(
                leaves,
                oldSize,
                newSize
              );

            const expected =
              await referenceRFC6962Proof(
                leaves,
                oldSize,
                newSize
              );

            if (
              JSON.stringify(
                generated.proof
              ) !==
              JSON.stringify(
                expected
              )
            ) {

              console.log(
                'Mismatch',
                oldSize,
                newSize,
                'generated:', generated.proof,
                expected
              );

              console.log(
                JSON.stringify(
                  {
                    generated:
                      generated.proof,
                    expected
                  },
                  null,
                  2
                )
              );
            }

            expect(
              generated.proof
            ).toEqual(
              expected
            );
          }
        }
      },
      60000
    );

  }
);