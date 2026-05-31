import { describe, it, expect } from "vitest";
import * as certificates from "../../src/certificates";

describe("certificates barrel exports", () => {
  it("exports generateMobileConfig", () => {
    expect(typeof certificates.generateMobileConfig)
      .toBe("function");
  });

  it("exports pemToDer", () => {
    expect(typeof certificates.pemToDer)
      .toBe("function");
  });

  it("exports extractCN", () => {
    expect(typeof certificates.extractCN)
      .toBe("function");
  });
});