import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils", () => ({
  generateUUID: vi.fn((seed: string) => {
    if (seed === "openauthority-trust-store-profile") {
      return "PROFILE-UUID";
    }

    return `CERT-${seed}`;
  }),
}));

vi.mock("../../src/certificates/parsing", () => ({
  pemToDer: vi.fn(() => new Uint8Array([1, 2, 3])),
  extractCN: vi.fn((subject: string) => {
    const match = subject.match(/CN=([^,]+)/);
    return match ? match[1] : subject;
  }),
}));

import { generateMobileConfig } from "../../src/certificates/mobileconfig";

describe("generateMobileConfig", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("generates a valid profile with a single certificate", () => {
    const xml = generateMobileConfig([
      {
        pem_data: "PEM",
        subject: "CN=Example Root,O=Example",
        fingerprint_sha256: "fp1",
      },
    ]);

    expect(xml).toContain("PROFILE-UUID");
    expect(xml).toContain("CERT-fp1");
    expect(xml).toContain("Example Root");
    expect(xml).toContain("Example Root.cer");
    expect(xml).toContain(
      "This profile installs 1 CA certificate(s)"
    );
  });

  it("generates multiple certificate payloads", () => {
    const xml = generateMobileConfig([
      {
        pem_data: "PEM1",
        subject: "CN=Root One",
        fingerprint_sha256: "fp1",
      },
      {
        pem_data: "PEM2",
        subject: "CN=Root Two",
        fingerprint_sha256: "fp2",
      },
    ]);

    expect(xml).toContain("Root One");
    expect(xml).toContain("Root Two");

    expect(xml).toContain(
      "org.openauthority.truststore.cert.0"
    );

    expect(xml).toContain(
      "org.openauthority.truststore.cert.1"
    );

    expect(xml).toContain(
      "This profile installs 2 CA certificate(s)"
    );
  });

  it("handles empty certificate arrays", () => {
    const xml = generateMobileConfig([]);

    expect(xml).toContain(
      "This profile installs 0 CA certificate(s)"
    );

    expect(xml).toContain("<array>");
  });

  it("includes base64 encoded certificate data", () => {
    const xml = generateMobileConfig([
      {
        pem_data: "PEM",
        subject: "CN=Root",
        fingerprint_sha256: "fp",
      },
    ]);

    expect(xml).toContain("AQID");
  });
});