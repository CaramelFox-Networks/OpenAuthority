import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/rekor", () => ({
  verifyRekorEntry: vi.fn(async () => ({
    valid: true
  }))
}));

vi.mock("../../src/merkle", () => ({
  getInclusionProofForEntry: vi.fn(async (_env, id) =>
    id === 1
      ? { leafHash: "A", root: "ROOT" }
      : null
  ),

  generateConsistencyProof: vi.fn(async () => ({
    oldSize: 1,
    newSize: 2,
    proof: ["X"]
  })),

  computeLeafHash: vi.fn(async () => "HASH"),

  createIncrementalMerkleTree: vi.fn(() => ({
    getRoot: vi.fn().mockResolvedValue("ROOT"),
    getTreeSize: vi.fn().mockResolvedValue(1)
  }))
}));

vi.mock("../../src/utils", () => ({
  canonicalizeJSON: vi.fn(() => "{}"),
  sha256: vi.fn(async () => "CHECKPOINT_HASH"),
  normalizeHeaders: vi.fn(h => h)
}));

vi.mock("../../src/services", () => ({
  buildVerificationSummary: vi.fn(() => ({
    status: "ok"
  }))
}));

import {
  handleGetInclusionProof
} from "../../src/routes/transparency";

describe("handleGetInclusionProof", () => {
  it("rejects invalid id", async () => {
    const res =
      await handleGetInclusionProof(
        {} as any,
        "abc",
        {}
      );

    expect(res.status).toBe(400);
  });

  it("returns 404 when proof missing", async () => {
    const res =
      await handleGetInclusionProof(
        {} as any,
        "999",
        {}
      );

    expect(res.status).toBe(404);
  });

  it("returns proof", async () => {
    const res =
      await handleGetInclusionProof(
        {} as any,
        "1",
        {}
      );

    expect(res.status).toBe(200);

    const body = await res.json();

    expect(body.entryId).toBe(1);
  });
});

import {
  handleGetConsistencyProof
} from "../../src/routes/transparency";

describe("handleGetConsistencyProof", () => {
  const env = {
    DB: {
      prepare() {
        return {
          all: async () => ({
            results: [
              { leaf_hash: "A" },
              { leaf_hash: "B" }
            ]
          })
        };
      }
    }
  } as any;

  it("rejects invalid sizes", async () => {
    const res =
      await handleGetConsistencyProof(
        env,
        2,
        1,
        {}
      );

    expect(res.status).toBe(400);
  });

  it("returns empty proof when equal", async () => {
    const res =
      await handleGetConsistencyProof(
        env,
        1,
        1,
        {}
      );

    const body = await res.json();

    expect(body.proof).toEqual([]);
  });

  it("returns generated proof", async () => {
    const res =
      await handleGetConsistencyProof(
        env,
        1,
        2,
        {}
      );

    expect(res.status).toBe(200);
  });
});

import {
  handleVerifyRekor
} from "../../src/routes/transparency";

describe("handleVerifyRekor", () => {
  it("requires parameters", async () => {
    const res =
      await handleVerifyRekor(
        null,
        null,
        {}
      );

    expect(res.status).toBe(400);
  });

  it("verifies Rekor entry", async () => {
    const res =
      await handleVerifyRekor(
        "uuid",
        "hash",
        {}
      );

    const body = await res.json();

    expect(body.valid).toBe(true);
  });
});

import {
  handleListCheckpoints,
  handleGetCheckpoint
} from "../../src/routes/transparency";

describe("checkpoint handlers", () => {
  const env = {
    DB: {
      prepare() {
        return {
          bind() {
            return this;
          },

          async first() {
            return {
              total: 1,
              id: 1,
              external_anchors: "[]"
            };
          },

          async all() {
            return {
              results: [
                {
                  id: 1,
                  consistency_proof: '["A"]',
                  external_anchors: "[]"
                }
              ]
            };
          }
        };
      }
    }
  } as any;

  it("lists checkpoints", async () => {
    const res =
      await handleListCheckpoints(
        env,
        {},
        1,
        50
      );

    const body = await res.json();

    expect(body.checkpoints).toHaveLength(1);
  });

  it("rejects invalid checkpoint id", async () => {
    const res =
      await handleGetCheckpoint(
        env,
        "abc",
        {}
      );

    expect(res.status).toBe(400);
  });

  it("returns checkpoint", async () => {
    const res =
      await handleGetCheckpoint(
        env,
        "1",
        {}
      );

    expect(res.status).toBe(200);
  });
});