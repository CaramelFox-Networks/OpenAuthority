import { describe, it, expect }
  from "vitest";

import * as trust
  from "../../src/trust";

describe("trust exports", () => {
  it("exports eligibility", () => {
    expect(
      typeof trust
        .verifyCertificateEligibility
    ).toBe("function");
  });

  it("exports snapshot functions", () => {
    expect(
      typeof trust
        .generateTrustStoreSnapshot
    ).toBe("function");

    expect(
      typeof trust
        .verifyTrustStoreSnapshot
    ).toBe("function");
  });
});