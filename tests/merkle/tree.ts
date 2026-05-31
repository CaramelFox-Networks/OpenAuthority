import { describe, it, expect } from "vitest";
import {
  computeLeafHash,
  computeNodeHash,
  buildMerkleTree
} from "../../src/merkle/tree";

describe("Merkle tree", () => {
  it("produces deterministic leaf hashes", async () => {
    const h1 = await computeLeafHash("abc");
    const h2 = await computeLeafHash("abc");

    expect(h1).toBe(h2);
  });

  it("different leaves hash differently", async () => {
    const h1 = await computeLeafHash("a");
    const h2 = await computeLeafHash("b");

    expect(h1).not.toBe(h2);
  });

  it("node hash is deterministic", async () => {
    const h1 = await computeNodeHash("x", "y");
    const h2 = await computeNodeHash("x", "y");

    expect(h1).toBe(h2);
  });

  it("builds single-leaf tree", async () => {
    const leaf = await computeLeafHash("a");

    const tree = await buildMerkleTree([leaf]);

    expect(tree.root).toBe(leaf);
  });

  it("builds multi-leaf tree", async () => {
    const leaves = [
      await computeLeafHash("a"),
      await computeLeafHash("b"),
      await computeLeafHash("c")
    ];

    const tree = await buildMerkleTree(leaves);

    expect(tree.root.length).toBeGreaterThan(0);
    expect(tree.layers.length).toBeGreaterThan(1);
  });

  it("empty tree returns empty root", async () => {
    const tree = await buildMerkleTree([]);

    expect(tree.root).toBe("");
  });
});

describe("computeLeafHash", () => {
  it("prefixes with 0x00", async () => {
    const hash1 = await computeLeafHash("abc");
    const hash2 = await computeLeafHash("\x00abc");

    expect(hash1).not.toBe(hash2);
    expect(hash1).toHaveLength(64);
  });

  it("rejects oversized entries", async () => {
    const large = "x".repeat(10_000_000);

    await expect(
      computeLeafHash(large)
    ).rejects.toThrow();
  });
});

describe("computeNodeHash", () => {
  it("prefixes with 0x01", async () => {
    const hash = await computeNodeHash("A", "B");

    expect(hash).toHaveLength(64);
    expect(hash).not.toBe(await computeLeafHash("AB"));
  });
});

describe("buildMerkleTree", () => {
  it("returns empty tree", async () => {
    expect(
      await buildMerkleTree([])
    ).toEqual({
      root: "",
      layers: []
    });
  });

  it("returns single leaf root", async () => {
    const result = await buildMerkleTree(["A"]);

    expect(result.root).toBe("A");
    expect(result.layers.length).toBe(1);
  });

  it("handles odd number of leaves", async () => {
    const result = await buildMerkleTree([
      "A",
      "B",
      "C"
    ]);

    expect(result.layers.length).toBeGreaterThan(1);
  });

  it("handles even number of leaves", async () => {
    const result = await buildMerkleTree([
      "A",
      "B",
      "C",
      "D"
    ]);

    expect(result.root).toBeDefined();
  });
});