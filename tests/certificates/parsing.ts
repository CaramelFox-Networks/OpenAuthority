import { describe, it, expect } from "vitest";
import { pemToDer, extractCN } from "../../src/certificates/parsing";

describe("pemToDer", () => {
  it("converts a PEM certificate to DER bytes", () => {
    const pem = `-----BEGIN CERTIFICATE-----
AQID
-----END CERTIFICATE-----`;

    const der = pemToDer(pem);

    expect(der).toBeInstanceOf(Uint8Array);
    expect(Array.from(der)).toEqual([1, 2, 3]);
  });

  it("removes whitespace before decoding", () => {
    const pem = `-----BEGIN CERTIFICATE-----

AQID

-----END CERTIFICATE-----`;

    expect(Array.from(pemToDer(pem))).toEqual([1, 2, 3]);
  });

  it("handles longer payloads", () => {
    const pem = `-----BEGIN CERTIFICATE-----
AAECAwQFBgcICQ==
-----END CERTIFICATE-----`;

    const der = pemToDer(pem);

    expect(der.length).toBe(10);
    expect(der[0]).toBe(0);
    expect(der[9]).toBe(9);
  });
});

describe("extractCN", () => {
  it("extracts CN from a standard subject", () => {
    expect(
      extractCN("CN=Example CA,O=Example Corp,C=US")
    ).toBe("Example CA");
  });

  it("extracts CN when additional fields follow", () => {
    expect(
      extractCN("CN=Root Authority,OU=PKI,O=Org")
    ).toBe("Root Authority");
  });

  it("returns original subject when CN missing", () => {
    const subject = "O=Example,C=US";
    expect(extractCN(subject)).toBe(subject);
  });

  it("handles empty string", () => {
    expect(extractCN("")).toBe("");
  });
});