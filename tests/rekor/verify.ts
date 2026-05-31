import { describe, it, expect, vi } from "vitest";
import { verifyRekorEntry } from "../../src/rekor/verify";

describe("verifyRekorEntry", () => {
  it("verifies valid Rekor entry", async () => {
    const body = btoa(
      JSON.stringify({
        spec: {
          data: {
            hash: {
              value: "abc123",
            },
          },
        },
      })
    );

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          uuid1: { body },
        }),
      })
    );

    const result =
      await verifyRekorEntry(
        "uuid1",
        "abc123"
      );

    expect(result.valid).toBe(true);
  });

  it("detects hash mismatch", async () => {
    const body = btoa(
      JSON.stringify({
        spec: {
          data: {
            hash: {
              value: "wrong",
            },
          },
        },
      })
    );

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          uuid1: { body },
        }),
      })
    );

    const result =
      await verifyRekorEntry(
        "uuid1",
        "expected"
      );

    expect(result.valid).toBe(false);
    expect(result.error).toContain(
      "Hash mismatch"
    );
  });

  it("handles missing entry", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
      })
    );

    const result =
      await verifyRekorEntry(
        "missing",
        "hash"
      );

    expect(result.valid).toBe(false);
    expect(result.error).toContain(
      "404"
    );
  });

  it("handles malformed response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({}),
      })
    );

    const result =
      await verifyRekorEntry(
        "uuid",
        "hash"
      );

    expect(result.valid).toBe(false);
  });

  it("handles fetch exceptions", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(
        new Error("boom")
      )
    );

    const result =
      await verifyRekorEntry(
        "uuid",
        "hash"
      );

    expect(result.valid).toBe(false);
    expect(result.error).toContain(
      "Verification failed"
    );
  });
});