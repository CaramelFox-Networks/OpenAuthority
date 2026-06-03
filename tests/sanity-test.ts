import { describe, it, expect } from 'vitest';

import {
  buildMerkleTree,
  computeLeafHash,
  computeNodeHash,
} from '../src/merkle/tree';
import { createHash } from 'crypto';
import { hashFullSubtree } from '../src/merkle/consistency';


import {
  generateConsistencyProof,
} from '../src/merkle/consistency';

describe('RFC6962 DIAGNOSTIC DUMP', () => {

  it('prints everything needed to diagnose compatibility', async () => {

    const leaves = ['A', 'B', 'C', 'D'];

    const leafHashes = await Promise.all(
      leaves.map(computeLeafHash)
    );

    console.log('\n========================================');
    console.log('LEAF HASHES');
    console.log('========================================');

    for (const leaf of leaves) {
      console.log(
        leaf,
        await computeLeafHash(leaf)
      );
    }

    console.log('\n========================================');
    console.log('HASH ENCODING TEST');
    console.log('========================================');

    const hA = await computeLeafHash('A');
    const hB = await computeLeafHash('B');

    const projectNode =
      await computeNodeHash(hA, hB);

    function sha256Hex(buf: Buffer): string {
      return createHash('sha256')
        .update(buf)
        .digest('hex');
    }

    const rfcNode = sha256Hex(
        Buffer.concat([
        Buffer.from([0x01]),
        Buffer.from(hA, 'hex'),
        Buffer.from(hB, 'hex'),
      ])
    );

    console.log('projectNode:', projectNode);
    console.log('rfcNode:', rfcNode);
    console.log(
      'matchesRFC:',
      projectNode === rfcNode
    );


    console.log('leafA:', hA);
    console.log('leafB:', hB);
    console.log('projectNode:', projectNode);

    console.log('\n========================================');
    console.log('CONSISTENCY PROOFS');
    console.log('========================================');

    const cases: Array<[number, number]> = [
      [1, 2],
      [2, 3],
      [3, 4],
      [2, 4],
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

      console.log('\n----------------------------------------');
      console.log(`${oldSize} -> ${newSize}`);
      console.log('oldRoot:', oldTree.root);
      console.log('newRoot:', newTree.root);

      console.log('proof object:');
      console.dir(proof, { depth: null });

      console.log('proof keys:', Object.keys(proof as any));
      console.log('proof json:', JSON.stringify(proof, null, 2));

      console.log(
        'CD subtrees:',
        await hashFullSubtree(
          leafHashes,
          2,
          2
        )
      )
    }

    expect(true).toBe(true);
  });

});