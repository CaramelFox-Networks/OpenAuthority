import {
  describe,
  it,
  expect
} from "vitest";

import * as services
  from "../../src/services";

describe(
  "services exports",
  () => {

  it(
    "exports audit service functions",
    () => {

    expect(
      typeof services
        .createAuditLogEntry
    ).toBe(
      "function"
    );

    expect(
      typeof services
        .buildVerificationSummary
    ).toBe(
      "function"
    );
  });
});