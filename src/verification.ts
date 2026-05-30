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

import { VerificationResult, ResolverResult, RDAPProof } from "./types";

// Multi-resolver DNS validators
const DNS_RESOLVERS = [
  { name: "Cloudflare", url: "https://cloudflare-dns.com/dns-query" },
  { name: "Google", url: "https://dns.google/dns-query" },
  { name: "Quad9", url: "https://dns.quad9.net:5053/dns-query" },
  { name: "CaramelFox", url: "https://root.dns.caramelfox.net/dns-query" },
];

const MIN_RESOLVER_AGREEMENT = 2;
const TXT_RECORD_PREFIX = "openauthority-ca-sha512=";
const DNS_FETCH_TIMEOUT_MS = 5000;

// ============================================================================
// DNS PARSER HARDENING: Constants & Limits
// ============================================================================

const DNS_LIMITS = {
  MAX_PACKET_SIZE: 4096,
  MAX_QUESTIONS: 4,
  MAX_ANSWERS: 64,
  MAX_LABEL_LENGTH: 63,
  MAX_TXT_STRING_LENGTH: 255,
  MAX_NAME_LENGTH: 255,
  DNS_HEADER_SIZE: 12,
} as const;

// ============================================================================
// DNS PARSER HARDENING: Error Type
// ============================================================================

class DNSParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DNSParseError';
  }
}

// ============================================================================
// DNS PARSER HARDENING: Bounds Validation Helper
// ============================================================================

function requireBytes(
  offset: number,
  needed: number,
  length: number,
  context: string = 'data'
): void {
  if (offset < 0) {
    throw new DNSParseError(`Negative offset in ${context}`);
  }
  if (needed < 0) {
    throw new DNSParseError(`Negative byte count in ${context}`);
  }
  if (offset + needed > length) {
    throw new DNSParseError(
      `Truncated DNS packet: need ${needed} bytes at offset ${offset}, ` +
      `but only ${length - offset} available (${context})`
    );
  }
}

// ============================================================================
// DNS QUERY BUILDING
// ============================================================================

function buildDNSQuery(domain: string, recordType: number): { query: Uint8Array; id: number } {
  const parts: number[] = [];

  const bytes = new Uint16Array(1);
  crypto.getRandomValues(bytes);
  const id = bytes[0];
  parts.push((id >> 8) & 0xff, id & 0xff);
  parts.push(0x01, 0x00);
  parts.push(0x00, 0x01);
  parts.push(0x00, 0x00);
  parts.push(0x00, 0x00);
  parts.push(0x00, 0x00);

  const labels = domain.split('.');
  for (const label of labels) {
    parts.push(label.length);
    for (const char of label) {
      parts.push(char.charCodeAt(0));
    }
  }
  parts.push(0x00);

  parts.push((recordType >> 8) & 0xff, recordType & 0xff);
  parts.push(0x00, 0x01);

  return { query: new Uint8Array(parts), id };
}

// ============================================================================
// DNS PARSER HARDENING: Safe Name Skipping
// ============================================================================

function skipDNSName(data: Uint8Array, offset: number): number {
  const startOffset = offset;
  let totalLength = 0;

  while (offset < data.length) {
    requireBytes(offset, 1, data.length, 'name label length');
    const len = data[offset];

    if (len === 0) {
      return offset + 1;
    }

    if ((len & 0xc0) === 0xc0) {
      requireBytes(offset, 2, data.length, 'compression pointer');
      return offset + 2;
    }

    if (len > DNS_LIMITS.MAX_LABEL_LENGTH) {
      throw new DNSParseError(
        `Invalid label length ${len} exceeds maximum of ${DNS_LIMITS.MAX_LABEL_LENGTH}`
      );
    }

    requireBytes(offset, len + 1, data.length, 'name label data');

    totalLength += len + 1;
    if (totalLength > DNS_LIMITS.MAX_NAME_LENGTH) {
      throw new DNSParseError(
        `Name length ${totalLength} exceeds maximum of ${DNS_LIMITS.MAX_NAME_LENGTH}`
      );
    }

    offset += len + 1;

    if (offset - startOffset > DNS_LIMITS.MAX_NAME_LENGTH + 2) {
      throw new DNSParseError('Name parsing exceeded maximum iterations');
    }
  }

  return offset;
}

// ============================================================================
// DNS PARSER HARDENING: Safe TXT Response Parsing
// ============================================================================

function parseDNSTXTResponse(data: Uint8Array, expectedId?: number): string[] {
  const results: string[] = [];

  if (data.length > DNS_LIMITS.MAX_PACKET_SIZE) {
    throw new DNSParseError(
      `DNS packet size ${data.length} exceeds maximum of ${DNS_LIMITS.MAX_PACKET_SIZE}`
    );
  }

  if (data.length < DNS_LIMITS.DNS_HEADER_SIZE) {
    throw new DNSParseError(
      `Invalid DNS response: too short (${data.length} bytes, minimum ${DNS_LIMITS.DNS_HEADER_SIZE})`
    );
  }

  // Validate transaction ID
  const responseId = (data[0] << 8) | data[1];
  if (expectedId !== undefined && responseId !== expectedId) {
    throw new DNSParseError(
      `DNS transaction ID mismatch: expected ${expectedId}, got ${responseId}`
    );
  }

  const flags = (data[2] << 8) | data[3];

  // Validate QR bit (bit 15) - must be 1 for response
  const isResponse = (flags & 0x8000) !== 0;
  if (!isResponse) {
    throw new DNSParseError('Expected DNS response (QR=1), got query (QR=0)');
  }

  // Validate opcode (bits 11-14) - must be 0 for standard query
  const opcode = (flags >> 11) & 0x0f;
  if (opcode !== 0) {
    throw new DNSParseError(`Unexpected DNS opcode: ${opcode}, expected 0 (QUERY)`);
  }

  // Check TC (truncation) flag (bit 9)
  const isTruncated = (flags & 0x0200) !== 0;
  if (isTruncated) {
    console.warn('DNS response has TC (truncation) flag set');
  }

  const rcode = flags & 0x000f;
  if (rcode !== 0 && rcode !== 3) {
    throw new DNSParseError(`DNS server returned error RCODE: ${rcode}`);
  }

  const qdcount = (data[4] << 8) | data[5];
  const ancount = (data[6] << 8) | data[7];

  if (qdcount > DNS_LIMITS.MAX_QUESTIONS) {
    throw new DNSParseError(
      `Suspicious DNS packet: ${qdcount} questions exceeds limit of ${DNS_LIMITS.MAX_QUESTIONS}`
    );
  }

  if (ancount > DNS_LIMITS.MAX_ANSWERS) {
    throw new DNSParseError(
      `Suspicious DNS packet: ${ancount} answers exceeds limit of ${DNS_LIMITS.MAX_ANSWERS}`
    );
  }

  let offset: number = DNS_LIMITS.DNS_HEADER_SIZE;

  for (let i = 0; i < qdcount; i++) {
    offset = skipDNSName(data, offset);
    requireBytes(offset, 4, data.length, 'question QTYPE/QCLASS');
    offset += 4;
  }

  for (let i = 0; i < ancount; i++) {
    offset = skipDNSName(data, offset);
    requireBytes(offset, 10, data.length, 'resource record header');

    const type = (data[offset] << 8) | data[offset + 1];
    const rdlength = (data[offset + 8] << 8) | data[offset + 9];

    offset += 10;
    requireBytes(offset, rdlength, data.length, 'resource record RDATA');

    if (type === 16) {
      const txtValue = parseTXTRdata(data, offset, rdlength);
      if (txtValue) {
        results.push(txtValue);
      }
    }

    offset += rdlength;
  }

  return results;
}

// ============================================================================
// TXT RDATA PARSING
// ============================================================================

function parseTXTRdata(
  data: Uint8Array,
  rdataOffset: number,
  rdlength: number
): string {
  const rdataEnd = rdataOffset + rdlength;
  let txtOffset = rdataOffset;
  const chunks: Uint8Array[] = [];

  requireBytes(rdataOffset, rdlength, data.length, 'TXT RDATA region');

  while (txtOffset < rdataEnd) {
    requireBytes(txtOffset, 1, data.length, 'TXT string length');
    const txtLen = data[txtOffset++];

    if (txtLen > DNS_LIMITS.MAX_TXT_STRING_LENGTH) {
      throw new DNSParseError(
        `TXT string length ${txtLen} exceeds maximum of ${DNS_LIMITS.MAX_TXT_STRING_LENGTH}`
      );
    }

    if (txtOffset + txtLen > rdataEnd) {
      throw new DNSParseError(
        `TXT string length ${txtLen} exceeds remaining RDATA (${rdataEnd - txtOffset} bytes)`
      );
    }

    requireBytes(txtOffset, txtLen, data.length, 'TXT string data');

    chunks.push(data.slice(txtOffset, txtOffset + txtLen));
    txtOffset += txtLen;
  }

  if (txtOffset !== rdataEnd) {
    throw new DNSParseError(
      `TXT parsing mismatch: ended at ${txtOffset}, expected ${rdataEnd}`
    );
  }

  // Single decode operation for all chunks
  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const combined = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.length;
  }

  return new TextDecoder('utf-8', { fatal: false }).decode(combined);
}

// ============================================================================
// DNS RESOLVER QUERYING
// ============================================================================

async function querySingleResolver(
  resolverUrl: string, 
  domain: string
): Promise<{ records: string[]; responseTime: number }> {
  const { query, id } = buildDNSQuery(domain, 16);

  const queryBase64 = btoa(String.fromCharCode(...query))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  const url = `${resolverUrl}?dns=${queryBase64}`;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), DNS_FETCH_TIMEOUT_MS);

  const startTime = Date.now();
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/dns-message' },
      signal: controller.signal
    });
    const responseTime = Date.now() - startTime;

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const buffer = await response.arrayBuffer();
    const data = new Uint8Array(buffer);

    const records = parseDNSTXTResponse(data, id);

    return { records, responseTime };
  } finally {
    clearTimeout(timeoutId);
  }
}

async function queryDNSTXTMultiResolver(domain: string): Promise<{
  records: string[];
  resolverResults: ResolverResult[];
}> {
  const resolverResults: ResolverResult[] = [];
  const allRecords: Map<string, number> = new Map();

  const queries = DNS_RESOLVERS.map(async (resolver) => {
    try {
      const result = await querySingleResolver(resolver.url, domain);

      resolverResults.push({
        resolver: resolver.name,
        success: true,
        records: result.records,
        responseTime: result.responseTime
      });

      for (const record of result.records) {
        allRecords.set(record, (allRecords.get(record) || 0) + 1);
      }
    } catch (e) {
      resolverResults.push({
        resolver: resolver.name,
        success: false,
        error: e instanceof Error ? e.message : String(e)
      });
    }
  });

  await Promise.all(queries);

  const agreedRecords = Array.from(allRecords.entries())
    .filter(([_, count]) => count >= MIN_RESOLVER_AGREEMENT)
    .map(([record, _]) => record);

  return { records: agreedRecords, resolverResults };
}

export async function verifyDNSTXT(
  domain: string, 
  expectedHash: string
): Promise<VerificationResult> {
  try {
    const txtRecordDomain = `_openauthority.${domain}`;
    console.log(`[Verify] Checking domain: ${txtRecordDomain} with multi-resolver validation`);

    const { records: txtRecords, resolverResults } = await queryDNSTXTMultiResolver(txtRecordDomain);

    console.log(`[Verify] Found ${txtRecords.length} agreed TXT records from ${resolverResults.filter(r => r.success).length} resolvers`);

    const successfulResolvers = resolverResults.filter(r => r.success).length;
    if (successfulResolvers < MIN_RESOLVER_AGREEMENT) {
      return {
        success: false,
        domain,
        expectedHash,
        error: `Insufficient resolver responses: ${successfulResolvers}/${MIN_RESOLVER_AGREEMENT} required`,
        resolverResults
      };
    }

    for (const record of txtRecords) {
      if (record.startsWith(TXT_RECORD_PREFIX)) {
        const foundHash = record
          .substring(TXT_RECORD_PREFIX.length)
          .replace(/\s+/g, '')
          .toLowerCase();

        if (foundHash === expectedHash.toLowerCase()) {
          return {
            success: true,
            domain,
            expectedHash,
            foundHash,
            resolverResults
          };
        }
      }
    }

    const { records: rootTxtRecords, resolverResults: rootResolverResults } = 
      await queryDNSTXTMultiResolver(domain);

    for (const record of rootTxtRecords) {
      if (record.startsWith(TXT_RECORD_PREFIX)) {
        const foundHash = record.substring(TXT_RECORD_PREFIX.length).toLowerCase();
        if (foundHash === expectedHash.toLowerCase()) {
          return {
            success: true,
            domain,
            expectedHash,
            foundHash,
            resolverResults: [...resolverResults, ...rootResolverResults]
          };
        }
      }
    }

    return {
      success: false,
      domain,
      expectedHash,
      error: `No matching TXT record found across ${successfulResolvers} resolvers. Expected: ${TXT_RECORD_PREFIX}${expectedHash}`,
      resolverResults
    };
  } catch (e) {
    return {
      success: false,
      domain,
      expectedHash,
      error: `DNS query failed: ${e instanceof Error ? e.message : String(e)}`
    };
  }
}

async function computeHash(text: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function queryRDAPWithProof(ip: string): Promise<RDAPProof> {
  const rdapEndpoints = [
    { name: "ARIN", url: `https://rdap.arin.net/registry/ip/${ip}` },
    { name: "RIPE", url: `https://rdap.db.ripe.net/ip/${ip}` },
    { name: "APNIC", url: `https://rdap.apnic.net/ip/${ip}` },
    { name: "LACNIC", url: `https://rdap.lacnic.net/rdap/ip/${ip}` },
    { name: "AFRINIC", url: `https://rdap.afrinic.net/rdap/ip/${ip}` }
  ];

  for (const endpoint of rdapEndpoints) {
    try {
      const queryTimestamp = new Date().toISOString();
      const response = await fetch(endpoint.url, {
        headers: { "Accept": "application/rdap+json" }
      });

      if (response.ok) {
        const rdapData = await response.json();
        const responseText = JSON.stringify(rdapData);
        const responseHash = await computeHash(responseText);

        return {
          ip,
          rdapServer: endpoint.name,
          queryTimestamp,
          responseHash,
          matchLocation: 'not_found',
          fullResponse: rdapData
        };
      }
    } catch {
      continue;
    }
  }

  throw new Error("Could not query RDAP for IP address from any RIR");
}

export async function verifyWHOIS(
  ip: string, 
  expectedHash: string
): Promise<VerificationResult & { rdapProof?: RDAPProof }> {
  try {
    const proof = await queryRDAPWithProof(ip);
    const rdapData = proof.fullResponse;
    const hashLower = expectedHash.toLowerCase();

    if (rdapData.remarks) {
      for (const remark of rdapData.remarks) {
        if (remark.description) {
          for (const desc of remark.description) {
            const descLower = desc.toLowerCase();
            if (descLower.includes(hashLower) || 
                descLower.includes(`openauthority-ca-sha512=${hashLower}`)) {
              proof.matchLocation = 'remarks';
              proof.matchedText = desc;
              return {
                success: true,
                ip,
                expectedHash,
                foundHash: expectedHash,
                rdapProof: proof
              };
            }
          }
        }
      }
    }

    if (rdapData.notices) {
      for (const notice of rdapData.notices) {
        if (notice.description) {
          for (const desc of notice.description) {
            const descLower = desc.toLowerCase();
            if (descLower.includes(hashLower)) {
              proof.matchLocation = 'notices';
              proof.matchedText = desc;
              return {
                success: true,
                ip,
                expectedHash,
                foundHash: expectedHash,
                rdapProof: proof
              };
            }
          }
        }
      }
    }

    const searchText = JSON.stringify(rdapData).toLowerCase();
    if (searchText.includes(hashLower)) {
      proof.matchLocation = 'description';
      return {
        success: true,
        ip,
        expectedHash,
        foundHash: expectedHash,
        rdapProof: proof
      };
    }

    return {
      success: false,
      ip,
      expectedHash,
      error: `CA hash not found in RDAP record. Searched: remarks, notices, full response. RDAP server: ${proof.rdapServer}`,
      rdapProof: proof
    };
  } catch (e) {
    return {
      success: false,
      ip,
      expectedHash,
      error: `RDAP query failed: ${e instanceof Error ? e.message : String(e)}`
    };
  }
}

export function extractBaseDomain(dnsName: string): string {
  return dnsName.replace(/^\*?\.?/, '');
}

export function extractIPAddress(ipRange: string): string {
  return ipRange.split('/')[0];
}
