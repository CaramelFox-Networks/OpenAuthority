import { describe, it, expect } from "vitest";
import {
  generateConsistencyProof,
  hashFullSubtree
} from "../../src/merkle/consistency";
import { computeLeafHash } from "../../src/merkle/tree";

describe("Consistency proofs", () => {
  it("creates proof between tree versions", async () => {
    const leaves = [
      await computeLeafHash("a"),
      await computeLeafHash("b"),
      await computeLeafHash("c"),
      await computeLeafHash("d")
    ];

    const proof =
      await generateConsistencyProof(
        leaves,
        2,
        4
      );

    expect(proof.oldSize).toBe(2);
    expect(proof.newSize).toBe(4);

    expect(proof.proof.length)
      .toBeGreaterThan(0);
  });

  it("rejects oldSize > newSize", async () => {
    await expect(
      generateConsistencyProof([], 5, 4)
    ).rejects.toThrow();
  });

  it("hashes subtree", async () => {
    const leaves = [
      await computeLeafHash("a"),
      await computeLeafHash("b")
    ];

    const hash = await hashFullSubtree(
      leaves,
      0,
      2
    );

    expect(hash.length).toBeGreaterThan(0);
  });
});

describe("generateConsistencyProof", () => {
  const leaves = [
    "a",
    "b",
    "c",
    "d",
    "e",
    "f"
  ];

  it("rejects oldSize <= 0", async () => {
    await expect(
      generateConsistencyProof(leaves, 0, 5)
    ).rejects.toThrow();
  });

  it("rejects oldSize > newSize", async () => {
    await expect(
      generateConsistencyProof(leaves, 5, 4)
    ).rejects.toThrow();
  });

  it("rejects newSize beyond leaves", async () => {
    await expect(
      generateConsistencyProof(leaves, 2, 20)
    ).rejects.toThrow();
  });

  it("generates proof where old tree fits left", async () => {
    const proof =
      await generateConsistencyProof(
        leaves,
        2,
        6
      );

    expect(proof.oldSize).toBe(2);
    expect(proof.proof.length).toBeGreaterThan(0);
  });

  it("generates proof spanning both sides", async () => {
    const proof =
      await generateConsistencyProof(
        leaves,
        5,
        6
      );

    expect(proof.proof.length).toBeGreaterThan(0);
  });
});

describe("hashFullSubtree", () => {
  it("returns leaf for size=1", async () => {
    expect(
      await hashFullSubtree(["A"], 0, 1)
    ).toBe("A");
  });

  it("recursively hashes larger trees", async () => {
    const result =
      await hashFullSubtree(
        ["A", "B", "C", "D"],
        0,
        4
      );

    expect(result).toMatch(/^[a-f0-9]{64}$/);
  });
});