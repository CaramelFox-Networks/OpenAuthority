import { describe, it, expect, vi } from "vitest";
import { safeDNSLookup } from "../../src/utils/dns";

describe("safeDNSLookup", () => {
  it("normalizes before lookup", async () => {
    const lookup = vi.fn().mockResolvedValue({
      success: true
    });

    const result = await safeDNSLookup(
      "EXAMPLE.COM",
      "fp",
      lookup
    );

    expect(lookup).toHaveBeenCalledWith(
      "example.com",
      "fp"
    );

    expect(result.success).toBe(true);
  });

  it("rejects invalid domains", async () => {
    const lookup = vi.fn();

    const result = await safeDNSLookup(
      "bad..domain",
      "fp",
      lookup
    );

    expect(result.success).toBe(false);
    expect(lookup).not.toHaveBeenCalled();
  });
});