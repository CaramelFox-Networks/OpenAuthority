import { describe, it, expect, vi } from "vitest";
import {
  generateInclusionProof,
  verifyInclusionProof
} from "../../src/merkle/inclusion";
import type { MerkleProof } from "../../src/merkle";
import { computeLeafHash, computeNodeHash } from "../../src/merkle/tree";

describe("Inclusion proofs", () => {
  it("verifies valid proof", async () => {
    const leaves = [
      await computeLeafHash("a"),
      await computeLeafHash("b"),
      await computeLeafHash("c"),
      await computeLeafHash("d")
    ];

    const proof =
      await generateInclusionProof(leaves, 2);

    expect(
      await verifyInclusionProof(proof)
    ).toBe(true);
  });

  it("fails after tampering", async () => {
    const leaves = [
      await computeLeafHash("a"),
      await computeLeafHash("b")
    ];

    const proof =
      await generateInclusionProof(leaves, 0);

    proof.root = "evil";

    expect(
      await verifyInclusionProof(proof)
    ).toBe(false);
  });

  it("rejects invalid index", async () => {
    const leaves = [
      await computeLeafHash("a")
    ];

    await expect(
      generateInclusionProof(leaves, 99)
    ).rejects.toThrow();
  });
});


describe("generateInclusionProof", () => {
  it("rejects negative index", async () => {
    await expect(
      generateInclusionProof(["A"], -1)
    ).rejects.toThrow();
  });

  it("rejects out-of-range index", async () => {
    await expect(
      generateInclusionProof(["A"], 2)
    ).rejects.toThrow();
  });

  it("creates proof", async () => {
    const proof =
      await generateInclusionProof(
        ["A","B","C","D"],
        0
      );

    expect(proof.leafHash).toBe("A");
    expect(proof.root).toMatch(/^[a-f0-9]{64}$/);
  });
});

describe("verifyInclusionProof", () => {
  it("returns true when hashes match", async () => {
    const proof = {
      leafHash: "A",
      leafIndex: 0,
      siblings: [],
      root: "A",
      treeSize: 1
    };

    expect(
      await verifyInclusionProof(proof)
    ).toBe(true);
  });

  it("returns false for mismatch", async () => {
    const proof: MerkleProof = {
      leafHash: "A",
      leafIndex: 0,
      siblings: [],
      root: "B",
      treeSize: 1
    };

    expect(
      await verifyInclusionProof(proof)
    ).toBe(false);
  });

  it("handles left sibling branch", async () => {
    const left = await computeLeafHash("B");
    const right = await computeLeafHash("A");

    const root = await computeNodeHash(left, right);

    const proof: MerkleProof = {
      leafHash: right,
      leafIndex: 1,
      siblings: [
        {
          hash: left,
          position: "left"
        }
      ],
      root,
      treeSize: 2
    };

    expect(
      await verifyInclusionProof(proof)
    ).toBe(true);
  });

  it("handles right sibling branch", async () => {
    const left = await computeLeafHash("A");
    const right = await computeLeafHash("B");

    const root = await computeNodeHash(left, right);

    const proof: MerkleProof = {
      leafHash: left,
      leafIndex: 0,
      siblings: [
        {
          hash: right,
          position: "right"
        }
      ],
      root,
      treeSize: 2
    };

    expect(
      await verifyInclusionProof(proof)
    ).toBe(true);
  });
});