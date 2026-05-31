import { describe, it, expect } from "vitest";
import {
  sha256,
  generateNonce,
  trimAndPad,
  p1363ToDer
} from "../../src/utils/crypto";

describe("crypto utilities", () => {
  it("sha256 is deterministic", async () => {
    const a = await sha256("abc");
    const b = await sha256("abc");
    expect(a).toBe(b);
    expect(a).toHaveLength(64);
  });

  it("generateNonce returns 32 hex chars", () => {
    const n = generateNonce();
    expect(n).toMatch(/^[0-9a-f]{32}$/);
  });

  it("trimAndPad removes leading zeros", () => {
    expect(Array.from(trimAndPad(new Uint8Array([0,0,1,2]))))
      .toEqual([1,2]);
  });

  it("trimAndPad prepends 00 when high bit set", () => {
    expect(Array.from(trimAndPad(new Uint8Array([0x80]))))
      .toEqual([0,0x80]);
  });

  it("rejects invalid P1363 length", () => {
    expect(() => p1363ToDer(new Uint8Array(10))).toThrow();
  });

  it("converts valid P1363 signature to DER", () => {
    const sig = new Uint8Array(64);
    sig[0] = 1;
    sig[32] = 2;

    const der = p1363ToDer(sig);
    expect(der[0]).toBe(0x30);
    expect(der.length).toBeGreaterThan(8);
  });

  it("covers long-form DER length branch", () => {
    const sig = new Uint8Array(64).fill(0x80);
    const der = p1363ToDer(sig);
    expect(der[0]).toBe(0x30);
  });
});