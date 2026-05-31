import {
  describe,
  it,
  expect,
  vi,
  beforeEach,
} from "vitest";

vi.mock("../../src/utils", () => ({
  p1363ToDer: vi.fn(
    () => new Uint8Array([1, 2, 3])
  ),
}));

import { submitToRekor } from "../../src/rekor/client";

describe("submitToRekor", () => {
  beforeEach(() => {
    vi.restoreAllMocks();

    vi.stubGlobal("crypto", {
      subtle: {
        importKey: vi
          .fn()
          .mockResolvedValue("key"),

        sign: vi
          .fn()
          .mockResolvedValue(
            new Uint8Array(64).buffer
          ),
      },
    });
  });

  it("returns null without signing key", async () => {
    const result =
      await submitToRekor(
        {} as any,
        "hash",
        "data"
      );

    expect(result).toBeNull();
  });

  it("returns null without public key", async () => {
    const result =
      await submitToRekor(
        {
          SIGNING_PRIVATE_KEY:
            btoa("private"),
        } as any,
        "hash",
        "data"
      );

    expect(result).toBeNull();
  });

  it("reconstructs PEM from raw public key", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          uuid1: {
            logIndex: 1,
            integratedTime: 123,
            body: "body",
          },
        }),
      })
    );

    const result =
      await submitToRekor(
        {
          SIGNING_PRIVATE_KEY:
            btoa("private"),
          SIGNING_PUBLIC_KEY:
            "QUJDREVGRw==",
        } as any,
        "hash",
        "checkpoint"
      );

    expect(result?.uuid).toBe("uuid1");
  });

  it("returns null on Rekor failure", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        text: async () => "error",
      })
    );

    const result =
      await submitToRekor(
        {
          SIGNING_PRIVATE_KEY:
            btoa("private"),
          SIGNING_PUBLIC_KEY_PEM:
            "pem",
        } as any,
        "hash",
        "data"
      );

    expect(result).toBeNull();
  });

  it("uses provided inclusion proof", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          uuid1: {
            logIndex: 1,
            integratedTime: 1,
            body: "body",
            verification: {
              inclusionProof: {
                hashes: ["A"],
                rootHash: "ROOT",
                treeSize: 1,
                logIndex: 1,
              },
            },
          },
        }),
      })
    );

    const result =
      await submitToRekor(
        {
          SIGNING_PRIVATE_KEY:
            btoa("private"),
          SIGNING_PUBLIC_KEY_PEM:
            "pem",
        } as any,
        "hash",
        "data"
      );

    expect(
      result?.inclusionProof.hashes
    ).toEqual(["A"]);
  });

  it("creates fallback inclusion proof", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          uuid1: {
            logIndex: 9,
            integratedTime: 1,
            body: "body",
          },
        }),
      })
    );

    const result =
      await submitToRekor(
        {
          SIGNING_PRIVATE_KEY:
            btoa("private"),
          SIGNING_PUBLIC_KEY_PEM:
            "pem",
        } as any,
        "hash",
        "data"
      );

    expect(
      result?.inclusionProof.rootHash
    ).toBe("");
  });

  it("handles crypto exceptions", async () => {
    vi.stubGlobal("crypto", {
      subtle: {
        importKey: vi
          .fn()
          .mockRejectedValue(
            new Error("crypto")
          ),
      },
    });

    const result =
      await submitToRekor(
        {
          SIGNING_PRIVATE_KEY:
            btoa("private"),
          SIGNING_PUBLIC_KEY_PEM:
            "pem",
        } as any,
        "hash",
        "data"
      );

    expect(result).toBeNull();
  });
});