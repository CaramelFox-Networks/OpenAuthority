import { describe, it, expect, vi, beforeEach } from "vitest";
import { createRFC3161Timestamp } from "../../src/rekor/timestamp";

describe("createRFC3161Timestamp", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("creates timestamp with default TSA URL", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        arrayBuffer: async () =>
          new Uint8Array([1, 2, 3]).buffer,
      })
    );

    const result = await createRFC3161Timestamp(
      {} as any,
      "aabbccdd"
    );

    expect(result).not.toBeNull();
    expect(result?.type).toBe("rfc3161");
    expect(result?.proof).toBe("AQID");
    expect(result?.serviceUrl).toBe(
      "https://freetsa.org/tsr"
    );
  });

  it("uses custom TSA URL", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      arrayBuffer: async () =>
        new Uint8Array([1]).buffer,
    });

    vi.stubGlobal("fetch", fetchMock);

    await createRFC3161Timestamp(
      {
        TIMESTAMP_SERVICE_URL:
          "https://tsa.example.com",
      } as any,
      "aabb"
    );

    expect(fetchMock).toHaveBeenCalledWith(
      "https://tsa.example.com",
      expect.any(Object)
    );
  });

  it("returns null on failed response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
      })
    );

    const result =
      await createRFC3161Timestamp(
        {} as any,
        "aabb"
      );

    expect(result).toBeNull();
  });

  it("returns null when fetch throws", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(
        new Error("network")
      )
    );

    const result =
      await createRFC3161Timestamp(
        {} as any,
        "aabb"
      );

    expect(result).toBeNull();
  });

  it("builds timestamp request body", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      arrayBuffer: async () =>
        new Uint8Array([1]).buffer,
    });

    vi.stubGlobal("fetch", fetchMock);

    await createRFC3161Timestamp(
      {} as any,
      "aabbccdd"
    );

    const body =
      fetchMock.mock.calls[0][1].body;

    expect(body).toBeInstanceOf(Uint8Array);
    expect(body.length).toBeGreaterThan(0);
  });
});