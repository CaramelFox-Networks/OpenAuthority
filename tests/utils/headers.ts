import { describe, it, expect } from "vitest";
import { normalizeHeaders } from "../../src/utils/headers";

describe("normalizeHeaders", () => {
  it("supports Headers", () => {
    const result = normalizeHeaders(
      new Headers({ a: "1" })
    );
    expect(result.a).toBe("1");
  });

  it("supports tuple arrays", () => {
    expect(
      normalizeHeaders([["x", "y"]])
    ).toEqual({ x: "y" });
  });

  it("supports plain objects", () => {
    expect(
      normalizeHeaders({ foo: "bar" })
    ).toEqual({ foo: "bar" });
  });
});