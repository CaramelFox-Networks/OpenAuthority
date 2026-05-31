import { describe, it, expect } from "vitest";
import * as rekor from "../../src/rekor";

describe("rekor exports", () => {
  it("exports submitToRekor", () => {
    expect(
      typeof rekor.submitToRekor
    ).toBe("function");
  });

  it("exports createRFC3161Timestamp", () => {
    expect(
      typeof rekor.createRFC3161Timestamp
    ).toBe("function");
  });

  it("exports verifyRekorEntry", () => {
    expect(
      typeof rekor.verifyRekorEntry
    ).toBe("function");
  });
});