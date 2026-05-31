import { describe, it, expect } from "vitest";
import { createIncrementalMerkleTree } from "../../src/merkle/incremental";

function createEnv() {
  const nodes = new Map<string,string>();

  return {
    DB: {
      prepare(sql: string) {
        return {
          bind(...args:any[]) {
            return {
              async first() {
                if (
                  sql.includes("COUNT(*)")
                ) {
                  const count =
                    [...nodes.keys()]
                      .filter(k => k.startsWith("0:"))
                      .length;

                  return { count };
                }

                if (
                  sql.includes(
                    "SELECT hash"
                  )
                ) {
                  const key =
                    `${args[0]}:${args[1]}`;

                  const hash =
                    nodes.get(key);

                  return hash
                    ? { hash }
                    : null;
                }

                return null;
              },

              async run() {
                nodes.set(
                  `${args[0]}:${args[1]}`,
                  args[2]
                );
              }
            };
          },
          async first() {
            return null;
          }
        };
      }
    }
  } as any;
}

describe("incremental merkle tree", () => {
  it("starts empty", async () => {
    const tree =
      createIncrementalMerkleTree(
        createEnv()
      );

    expect(
      await tree.getTreeSize()
    ).toBe(0);
  });

  it("adds first leaf", async () => {
    const tree =
      createIncrementalMerkleTree(
        createEnv()
      );

    const result =
      await tree.appendLeaf("A");

    expect(
      result.leafIndex
    ).toBe(0);
  });

  it("rejects invalid inclusion proof index", async () => {
    const tree =
      createIncrementalMerkleTree(
        createEnv()
      );

    expect(
      await tree.getInclusionProof(99)
    ).toBeNull();
  });
});