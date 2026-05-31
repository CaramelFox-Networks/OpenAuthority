import { describe, it, expect } from "vitest";
import {
  validateDomainStrict,
  requireValidDomain
} from "../../src/utils/domain";

describe("validateDomainStrict", () => {
  it("accepts a normal domain", () => {
    const result = validateDomainStrict("example.com");

    expect(result.isValid).toBe(true);
    expect(result.normalized).toBe("example.com");
  });

  it("normalizes uppercase", () => {
    const result = validateDomainStrict("EXAMPLE.COM");

    expect(result.isValid).toBe(true);
    expect(result.normalized).toBe("example.com");
  });

  it("removes trailing dot", () => {
    const result = validateDomainStrict("example.com.");

    expect(result.isValid).toBe(true);
    expect(result.normalized).toBe("example.com");
  });

  it("rejects empty domain", () => {
    expect(validateDomainStrict("").isValid).toBe(false);
  });

  it("rejects consecutive dots", () => {
    expect(
      validateDomainStrict("example..com").isValid
    ).toBe(false);
  });

  it("rejects unicode", () => {
    expect(
      validateDomainStrict("café.com").isValid
    ).toBe(false);
  });

  it("allows punycode", () => {
    expect(
      validateDomainStrict("xn--caf-dma.com").isValid
    ).toBe(true);
  });

  it("allows underscore records", () => {
    expect(
      validateDomainStrict("_acme-challenge.example.com")
        .isValid
    ).toBe(true);
  });

  it("throws via requireValidDomain", () => {
    expect(() =>
      requireValidDomain("bad..domain")
    ).toThrow();
  });
});

describe("domain edge cases", () => {
  it("rejects non-string values", () => {
    expect(
      validateDomainStrict(null as any).isValid
    ).toBe(false);
  });

  it("rejects overlong labels", () => {
    const d = "a".repeat(64) + ".com";
    expect(validateDomainStrict(d).isValid)
      .toBe(false);
  });

  it("rejects invalid leading character", () => {
    expect(validateDomainStrict("-abc.com").isValid)
      .toBe(false);
  });

  it("rejects invalid trailing character", () => {
    expect(validateDomainStrict("abc-.com").isValid)
      .toBe(false);
  });

  it("rejects reserved double hyphen pattern", () => {
    expect(validateDomainStrict("ab--cd.com").isValid)
      .toBe(false);
  });
});
