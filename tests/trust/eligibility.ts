import {
  describe,
  it,
  expect,
  vi,
} from "vitest";

vi.mock("../../src/utils", () => ({
  canonicalizeJSON: vi.fn(() => "{}")
}));

vi.mock("../../src/merkle", () => ({
  computeLeafHash: vi.fn(async () => "VALID_HASH")
}));

function createEnv(overrides: any = {}) {
  return {
    DB: {
      prepare(sql: string) {
        return {
          bind() {
            return {
              first: async () => {
                if (
                  sql.includes("certificate_added")
                ) {
                  return overrides.addedEvent ??
                    { id: 1 };
                }

                if (
                  sql.includes("COUNT(*)")
                ) {
                  return overrides.auditCount ??
                    { count: 28 };
                }

                if (
                  sql.includes("certificate_promoted")
                ) {
                  return overrides.promotedEvent ??
                    { id: 2 };
                }

                if (
                  sql.includes("checked_at")
                ) {
                  return overrides.recentCheck ?? {
                    checked_at:
                      new Date().toISOString()
                  };
                }

                return null;
              },

              all: async () => ({
                results:
                  overrides.criticalEntries ??
                  [
                    {
                      id: 1,
                      ca_id: 1,
                      check_type:
                        "certificate_added",
                      target: "x",
                      success: 1,
                      details: "{}",
                      checked_at:
                        new Date().toISOString(),
                      nonce: "abc",
                      tree_position: 1,
                      leaf_hash:
                        "VALID_HASH"
                    }
                  ]
              })
            };
          }
        };
      }
    }
  } as any;
}

import {
  verifyCertificateEligibility
} from "../../src/trust/eligibility";

describe("status validation", () => {
  it("rejects inactive cert", async () => {
    const result =
      await verifyCertificateEligibility(
        createEnv(),
        {
          id: 1,
          status: "pending",
          created_at:
            "2020-01-01T00:00:00Z",
          fingerprint_sha256: "abc"
        }
      );

    expect(result.eligible).toBe(false);
    expect(result.reason)
      .toContain("active");
  });
});

it("rejects probationary certificate", async () => {
  const result =
    await verifyCertificateEligibility(
      createEnv(),
      {
        id: 1,
        status: "active",
        created_at:
          new Date().toISOString(),
        fingerprint_sha256: "abc"
      }
    );

  expect(result.eligible).toBe(false);
});

it("rejects insufficient verifications", async () => {
  const result =
    await verifyCertificateEligibility(
      createEnv({
        auditCount: { count: 0 }
      }),
      validCert()
    );

  expect(result.eligible)
    .toBe(false);
});

it("rejects stale verification", async () => {
  const result =
    await verifyCertificateEligibility(
      createEnv({
        recentCheck: {
          checked_at:
            "2020-01-01T00:00:00Z"
        }
      }),
      validCert()
    );

  expect(result.reason)
    .toContain("too old");
});

import { computeLeafHash }
  from "../../src/merkle";

it("rejects hash mismatch", async () => {
  vi.mocked(computeLeafHash)
    .mockResolvedValueOnce(
      "COMPUTED"
    );

  const result =
    await verifyCertificateEligibility(
      createEnv({
        criticalEntries: [
          {
            id: 9,
            ca_id: 1,
            check_type:
              "certificate_added",
            target: "x",
            success: 1,
            details: "{}",
            checked_at:
              new Date().toISOString(),
            nonce: "abc",
            tree_position: 1,
            leaf_hash: "OTHER"
          }
        ]
      }),
      validCert()
    );

  expect(result.reason)
    .toContain("integrity");
});

it("returns eligible", async () => {
  const result =
    await verifyCertificateEligibility(
      createEnv(),
      validCert()
    );

  expect(result)
    .toEqual({ eligible: true });
});

function validCert() {
  return {
    id: 1,
    status: "active",
    created_at:
      "2020-01-01T00:00:00Z",
    fingerprint_sha256: "abc"
  };
}