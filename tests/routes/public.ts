import { describe, it, expect, vi } from "vitest";

vi.mock("../../src/merkle", () => ({
  createIncrementalMerkleTree: vi.fn(() => ({
    getTreeSize: vi.fn().mockResolvedValue(10),
    getRoot: vi.fn().mockResolvedValue("ROOT"),
  })),
  createSignedTreeHead: vi.fn().mockResolvedValue({
    treeSize: 10,
    rootHash: "ROOT",
    signature: "SIG",
  }),
}));

vi.mock("../../src/utils", () => ({
  normalizeHeaders: vi.fn((h) => h),
  validateDomainStrict: vi.fn((domain) => ({
    isValid: domain === "example.com",
  })),
}));

import {
  handleGetPublicKey,
  handleGetTreeHead,
  handlePublicRoutes,
} from "../../src/routes/public";

function env() {
  return {
    SIGNING_PUBLIC_KEY: "PUBKEY",
    DB: {
      prepare: () => ({
        first: async () => ({
          checkpoint_hash: "CHECKPOINT",
        }),
      }),
    },
  } as any;
}

describe("handleGetPublicKey", () => {
  it("returns public key info", async () => {
    const res = await handleGetPublicKey(
      env(),
      {}
    );

    expect(res.status).toBe(200);

    const body = await res.json();

    expect(body.publicKey).toBe("PUBKEY");
    expect(body.algorithm).toBe("ECDSA-P256");
  });
});

describe("handleGetTreeHead", () => {
  it("returns signed tree head", async () => {
    const res = await handleGetTreeHead(
      env(),
      {}
    );

    const body = await res.json();

    expect(body.rootHash).toBe("ROOT");
    expect(body.signature).toBe("SIG");
  });
});

describe("handlePublicRoutes", () => {
  it("routes public key endpoint", async () => {
    const req = new Request(
      "https://test/api/public-key"
    );

    const res = await handlePublicRoutes(
      req,
      env(),
      {}
    );

    expect(res).not.toBeNull();
  });

  it("routes transparency public key endpoint", async () => {
    const req = new Request(
      "https://test/api/transparency/public-key"
    );

    const res = await handlePublicRoutes(
      req,
      env(),
      {}
    );

    expect(res).not.toBeNull();
  });

  it("routes validate-domain", async () => {
    const req = new Request(
      "https://test/api/validate-domain?domain=example.com"
    );

    const res = await handlePublicRoutes(
      req,
      env(),
      {}
    );

    expect(res).not.toBeNull();

    const body = await res!.json();

    expect(body.isValid).toBe(true);
  });

  it("returns null for unknown route", async () => {
    const req = new Request(
      "https://test/nope"
    );

    const res = await handlePublicRoutes(
      req,
      env(),
      {}
    );

    expect(res).toBeNull();
  });
});