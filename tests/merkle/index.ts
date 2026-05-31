import { describe, it, expect } from "vitest";
import * as merkle from "../../src/merkle";

describe("barrel exports", () => {
  it("exports tree functions", () => {
    expect(
      typeof merkle.buildMerkleTree
    ).toBe("function");
  });

  it("exports inclusion functions", () => {
    expect(
      typeof merkle.generateInclusionProof
    ).toBe("function");
  });

  it("exports consistency functions", () => {
    expect(
      typeof merkle.generateConsistencyProof
    ).toBe("function");
  });

  it("exports incremental tree creator", () => {
    expect(
      typeof merkle.createIncrementalMerkleTree
    ).toBe("function");
  });
});