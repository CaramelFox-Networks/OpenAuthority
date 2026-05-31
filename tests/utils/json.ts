import { describe, it, expect } from "vitest";
import {
  canonicalizeJSON,
  canonicalizeString,
  stringToUTF16CodeUnits
} from "../../src/utils/json";


describe("canonicalizeJSON", () => {
  it("sorts keys", () => {
    expect(
      canonicalizeJSON({
        z: 1,
        a: 2
      })
    ).toBe('{"a":2,"z":1}');
  });

  it("canonicalizes nested objects", () => {
    expect(
      canonicalizeJSON({
        b: {
          z: 1,
          a: 2
        }
      })
    ).toBe(
      '{"b":{"a":2,"z":1}}'
    );
  });

  it("preserves array order", () => {
    expect(
      canonicalizeJSON([3, 2, 1])
    ).toBe("[3,2,1]");
  });

  it("rejects NaN", () => {
    expect(() =>
      canonicalizeJSON({ x: NaN })
    ).toThrow();
  });

  it("rejects Infinity", () => {
    expect(() =>
      canonicalizeJSON({ x: Infinity })
    ).toThrow();
  });
});

describe("canonicalizeString", () => {
  it("escapes quotes", () => {
  expect(canonicalizeString('a"b'))
    .toBe('"a\\"b"');
  });

  it("escapes newlines", () => {
    expect(
      canonicalizeString("a\nb")
    ).toBe('"a\\nb"');
  });

  it("rejects lone surrogate", () => {
    expect(() =>
      canonicalizeString("\uD800")
    ).toThrow();
  });
});

describe("json edge coverage", () => {
  it("handles primitives", () => {
    expect(canonicalizeJSON(null)).toBe("null");
    expect(canonicalizeJSON(true)).toBe("true");
    expect(canonicalizeJSON(false)).toBe("false");
  });

  it("rejects unsupported types", () => {
    expect(() =>
      canonicalizeJSON(Symbol("x") as any)
    ).toThrow();
  });

  it("returns utf16 code units", () => {
    expect(stringToUTF16CodeUnits("AB"))
      .toEqual([65,66]);
  });

  it("escapes control characters", () => {
    expect(canonicalizeString("\b\t\f\r"))
      .toContain("\\b");
  });

  it("rejects lone low surrogate", () => {
    expect(() =>
      canonicalizeString("\uDC00")
    ).toThrow();
  });

  it("rejects bad surrogate pair", () => {
    expect(() =>
      canonicalizeString("\uD800A")
    ).toThrow();
  });
});