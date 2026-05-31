import {
  vi,
  expect,
  it,
  describe
} from "vitest";

vi.mock("../../src/trust/eligibility", () => ({
  verifyCertificateEligibility:
    vi.fn(async () => ({
      eligible: true
    }))
}));

vi.mock("../../src/merkle", () => ({
  getInclusionProofForEntry:
    vi.fn(async () => ({
      leafHash: "A",
      root: "ROOT",
      siblings: []
    })),

  buildMerkleTree:
    vi.fn(async () => ({
      root: "ROOT"
    })),

  computeLeafHash:
    vi.fn(async () => "HASH"),

  verifyInclusionProof:
    vi.fn(async () => true),

  createSignedTreeHead:
    vi.fn(async () => ({
      rootHash: "ROOT",
      treeSize: 1
    }))
}));

vi.mock("../../src/utils", () => ({
  sha256:
    vi.fn(async () => "CONTENT_HASH"),

  canonicalizeJSON:
    vi.fn(() => "{}")
}));

import {
  generateTrustStoreSnapshot,
  verifyTrustStoreSnapshot
} from "../../src/trust/snapshot";

function env() {
  return {
    DB: {
      prepare(sql: string) {
        return {
          bind() {
            return this;
          },

          async first() {
            if (
              sql.includes(
                "transparency_checkpoints"
              )
            ) {
              return {
                checkpoint_hash:
                  "CP"
              };
            }

            if (
              sql.includes(
                "certificate_added"
              )
            ) {
              return {
                id: 1,
                tree_position: 1
              };
            }

            return null;
          },

          async all() {
            if (
              sql.includes(
                "certificate_authorities"
              )
            ) {
              return {
                results: [
                  {
                    id: 1,
                    subject:
                      "CN=Root",
                    pem_data:
                      "PEM",
                    fingerprint_sha256:
                      "ABC",
                    created_at:
                      "2020",
                    last_check_at:
                      "2025"
                  }
                ]
              };
            }

            if (
              sql.includes(
                "verification_log"
              )
            ) {
              return {
                results: [
                  {
                    id: 1,
                    leaf_hash:
                      "HASH",
                    nonce:
                      "abc",
                    success: 1
                  }
                ]
              };
            }

            return {
              results: []
            };
          }
        };
      }
    }
  } as any;
}

describe(
  "generateTrustStoreSnapshot",
  () => {
    it("creates snapshot", async () => {
      const snapshot =
        await generateTrustStoreSnapshot(
          env()
        );

      expect(
        snapshot.contentHash
      ).toBe(
        "CONTENT_HASH"
      );

      expect(
        snapshot.certificates
      ).toHaveLength(1);
    });

    it("filters ineligible certs",
      async () => {
        const {
          verifyCertificateEligibility
        } = await import(
          "../../src/trust/eligibility"
        );

        vi.mocked(
          verifyCertificateEligibility
        ).mockResolvedValueOnce({
          eligible: false
        });

        const snapshot =
          await generateTrustStoreSnapshot(
            env()
          );

        expect(
          snapshot.certificates
        ).toHaveLength(0);
      });
  }
);

it("signs snapshot", async () => {
  vi.stubGlobal("crypto", {
    subtle: {
      importKey:
        vi.fn()
          .mockResolvedValue("k"),

      sign:
        vi.fn()
          .mockResolvedValue(
            new Uint8Array([1])
              .buffer
          )
    }
  });

  const snapshot =
    await generateTrustStoreSnapshot(
      {
        ...env(),
        SIGNING_PRIVATE_KEY:
          btoa("abc")
      }
    );

  expect(snapshot.signature)
    .toBeDefined();
});

it("handles signing failure", async () => {
  vi.stubGlobal("crypto", {
    subtle: {
      importKey:
        vi.fn()
          .mockRejectedValue(
            new Error("fail")
          )
    }
  });

  const snapshot =
    await generateTrustStoreSnapshot(
      {
        ...env(),
        SIGNING_PRIVATE_KEY:
          btoa("abc")
      }
    );

  expect(snapshot)
    .toBeDefined();
});

describe(
  "verifyTrustStoreSnapshot",
  () => {
    it("verifies valid snapshot",
      async () => {

      const result =
        await verifyTrustStoreSnapshot({
          contentHash:
            "CONTENT_HASH",

          treeHead: {
            rootHash:
              "ROOT"
          },

          auditLog: [
            {
              id: 1,
              ca_id: 1,
              check_type:
                "dns",
              target: "x",
              success: true,
              details: "{}",
              checked_at:
                "2025",
              nonce: "abc",
              tree_position: 1,
              leaf_hash:
                "HASH"
            }
          ],

          certificates: [
            {
              fingerprint_sha256:
                "ABC",

              inclusionProof: {
                siblings: []
              }
            }
          ]
        } as any);

      expect(result.valid)
        .toBe(true);
    });
});

it("detects content tampering",
  async () => {

  const result =
    await verifyTrustStoreSnapshot({
      contentHash:
        "WRONG",
      treeHead: {
        rootHash:
          "ROOT"
      },
      auditLog: [],
      certificates: []
    } as any);

  expect(
    result.errors[0]
  ).toContain(
    "Content hash mismatch"
  );
});

it("detects missing proof",
  async () => {

  const result =
    await verifyTrustStoreSnapshot({
      contentHash:
        "CONTENT_HASH",

      treeHead: {
        rootHash:
          "ROOT"
      },

      auditLog: [],

      certificates: [
        {
          fingerprint_sha256:
            "ABC"
        }
      ]
    } as any);

  expect(
    result.errors.join()
  ).toContain(
    "missing inclusion proof"
  );
});

import {
  verifyInclusionProof
} from "../../src/merkle";

it("detects invalid proof",
  async () => {

  vi.mocked(
    verifyInclusionProof
  ).mockResolvedValueOnce(
    false
  );

  const result =
    await verifyTrustStoreSnapshot({
      contentHash:
        "CONTENT_HASH",

      treeHead: {
        rootHash:
          "ROOT"
      },

      auditLog: [],

      certificates: [
        {
          fingerprint_sha256:
            "ABC",

          inclusionProof: {
            siblings: []
          }
        }
      ]
    } as any);

  expect(
    result.errors.join()
  ).toContain(
    "invalid"
  );
});

