/*
 * OpenAuthority
 * Copyright (C) 2026 CaramelFox Networks LLC
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import { AsnParser } from "@peculiar/asn1-schema";
import { 
  BasicConstraints as Asn1BasicConstraints,
  NameConstraints as Asn1NameConstraints
} from "@peculiar/asn1-x509";
import { ParsedCertificate, NameConstraints, BasicConstraints } from "./types";

// OID for Name Constraints extension
const NAME_CONSTRAINTS_OID = "2.5.29.30";
// OID for Basic Constraints extension
const BASIC_CONSTRAINTS_OID = "2.5.29.19";

/**
 * Convert ArrayBuffer to hex string
 */
function bufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Compute SHA-512 hash of certificate DER data
 */
async function computeSHA512(data: ArrayBuffer): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-512', data);
  return bufferToHex(hashBuffer);
}

/**
 * Compute SHA-256 hash of certificate DER data
 */
async function computeSHA256(data: ArrayBuffer): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return bufferToHex(hashBuffer);
}

/**
 * HIGH PRIORITY #2: Properly parse Basic Constraints using ASN.1 library
 * 
 * BasicConstraints ::= SEQUENCE {
 *   cA                      BOOLEAN DEFAULT FALSE,
 *   pathLenConstraint       INTEGER (0..MAX) OPTIONAL
 * }
 */
function parseBasicConstraints(cert: x509.X509Certificate): BasicConstraints {
  const bcExt = cert.extensions.find(ext => ext.type === BASIC_CONSTRAINTS_OID);

  if (!bcExt) {
    return { isCA: false };
  }

  try {
    const parsed = AsnParser.parse(bcExt.value, Asn1BasicConstraints);

    return {
      isCA: parsed.cA === true,
      pathLenConstraint: parsed.pathLenConstraint !== undefined 
        ? parsed.pathLenConstraint 
        : undefined
    };
  } catch (e) {
    console.error("Failed to parse Basic Constraints with ASN.1 library:", e);
    // Fallback: return safe default (not a CA)
    return { isCA: false };
  }
}

/**
 * Parse Name Constraints using ASN.1 library
 * 
 * NameConstraints ::= SEQUENCE {
 *   permittedSubtrees       [0] GeneralSubtrees OPTIONAL,
 *   excludedSubtrees        [1] GeneralSubtrees OPTIONAL
 * }
 */
function parseNameConstraints(cert: x509.X509Certificate): NameConstraints {
  const constraints: NameConstraints = {
    permittedDNS: [],
    permittedIP: [],
    excludedDNS: [],
    excludedIP: []
  };

  const ncExt = cert.extensions.find(ext => ext.type === NAME_CONSTRAINTS_OID);

  if (!ncExt) {
    return constraints;
  }

  try {
    // Use proper ASN.1 parsing
    const parsed = AsnParser.parse(ncExt.value, Asn1NameConstraints);

    // Process permitted subtrees
    if (parsed.permittedSubtrees) {
      for (const subtree of parsed.permittedSubtrees) {
        processGeneralSubtree(subtree, constraints.permittedDNS, constraints.permittedIP);
      }
    }

    // Process excluded subtrees
    if (parsed.excludedSubtrees) {
      for (const subtree of parsed.excludedSubtrees) {
        processGeneralSubtree(subtree, constraints.excludedDNS, constraints.excludedIP);
      }
    }

    return constraints;
  } catch (e) {
    console.error("Failed to parse Name Constraints with ASN.1 library:", e);
    return constraints;
  }
}

/**
 * Process a GeneralSubtree and extract DNS names and IP addresses
 */
function processGeneralSubtree(
  subtree: any, 
  dnsArray: string[], 
  ipArray: string[]
): void {
  const base = subtree.base;

  // Check for dNSName (tag 2)
  if (base.dNSName !== undefined) {
    dnsArray.push(base.dNSName);
  }

  // Check for iPAddress (tag 7)
  if (base.iPAddress !== undefined) {
    const ipBytes = new Uint8Array(base.iPAddress);

    if (ipBytes.length === 8) {
      // IPv4 with mask: 4 bytes IP + 4 bytes mask
      const ip = `${ipBytes[0]}.${ipBytes[1]}.${ipBytes[2]}.${ipBytes[3]}`;
      const maskBits = countMaskBits(ipBytes.slice(4, 8));
      ipArray.push(`${ip}/${maskBits}`);
    } else if (ipBytes.length === 32) {
      // IPv6 with mask: 16 bytes IP + 16 bytes mask
      const ipParts: string[] = [];
      for (let i = 0; i < 16; i += 2) {
        ipParts.push(((ipBytes[i] << 8) | ipBytes[i + 1]).toString(16));
      }
      const maskBits = countMaskBits(ipBytes.slice(16, 32));
      ipArray.push(`${ipParts.join(':')}/${maskBits}`);
    }
  }
}

/**
 * Count the number of 1 bits in a subnet mask
 */
function countMaskBits(mask: Uint8Array): number {
  let bits = 0;
  for (const byte of mask) {
    let b = byte;
    while (b) {
      bits += b & 1;
      b >>= 1;
    }
  }
  return bits;
}

/**
 * Parse a PEM or DER encoded certificate
 */
export async function parseCertificate(certData: string | Uint8Array): Promise<ParsedCertificate> {
  // Parse the certificate
  const cert = new x509.X509Certificate(certData);

  // HIGH PRIORITY #2: Use properly parsed Basic Constraints
  const basicConstraints = parseBasicConstraints(cert);

  if (!basicConstraints.isCA) {
    throw new Error(
      "Certificate is not a CA certificate. " +
      "Basic Constraints extension must be present with cA=TRUE. " +
      "See RFC 5280 Section 4.2.1.9."
    );
  }

  // Use properly parsed Name Constraints
  const nameConstraints = parseNameConstraints(cert);

  if (nameConstraints.permittedDNS.length === 0 && nameConstraints.permittedIP.length === 0) {
    throw new Error(
      "Certificate must have Name Constraints extension with permitted DNS names or IP addresses. " +
      "Unconstrained root CAs are not accepted. " +
      "See RFC 5280 Section 4.2.1.10."
    );
  }

  // Compute fingerprints from the raw DER data
  const fingerprint_sha512 = await computeSHA512(cert.rawData);
  const fingerprint_sha256 = await computeSHA256(cert.rawData);

  // Convert to PEM for storage
  const pemData = cert.toString("pem");

  return {
    fingerprint_sha512,
    fingerprint_sha256,
    subject: cert.subject,
    issuer: cert.issuer,
    serialNumber: cert.serialNumber,
    notBefore: new Date(cert.notBefore),
    notAfter: new Date(cert.notAfter),
    pemData,
    nameConstraints,
    basicConstraints,
    isCA: true
  };
}

/**
 * Convert certificate to PEM format for export
 */
export function toPEM(cert: any): string {
  return cert.pem_data;
}
