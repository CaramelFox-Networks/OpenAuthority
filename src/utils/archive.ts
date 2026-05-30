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

import { ExportManifest } from "../types";
import { Env } from "../types";
import { canonicalizeJSON } from "../utils"

export function generateZip(files: Array<{ name: string; data: Uint8Array<ArrayBuffer> }>): ArrayBuffer {
  const encoder = new TextEncoder();

  let centralDirectorySize = 0;
  let localHeadersSize = 0;

  for (const file of files) {
    localHeadersSize += 30 + file.name.length + file.data.length;
    centralDirectorySize += 46 + file.name.length;
  }

  const totalSize = localHeadersSize + centralDirectorySize + 22;
  const buffer = new Uint8Array(totalSize);
  const view = new DataView(buffer.buffer);

  let localOffset = 0;
  let centralOffset = localHeadersSize;
  const centralDirectoryStart = localHeadersSize;

  for (const file of files) {
    const nameBytes = encoder.encode(file.name);
    const crc = crc32(file.data);

    view.setUint32(localOffset, 0x04034b50, true);
    view.setUint16(localOffset + 4, 10, true);
    view.setUint16(localOffset + 6, 0, true);
    view.setUint16(localOffset + 8, 0, true);
    view.setUint16(localOffset + 10, 0, true);
    view.setUint16(localOffset + 12, 0, true);
    view.setUint32(localOffset + 14, crc, true);
    view.setUint32(localOffset + 18, file.data.length, true);
    view.setUint32(localOffset + 22, file.data.length, true);
    view.setUint16(localOffset + 26, nameBytes.length, true);
    view.setUint16(localOffset + 28, 0, true);
    buffer.set(nameBytes, localOffset + 30);
    buffer.set(file.data, localOffset + 30 + nameBytes.length);

    const fileLocalOffset = localOffset;
    localOffset += 30 + nameBytes.length + file.data.length;

    view.setUint32(centralOffset, 0x02014b50, true);
    view.setUint16(centralOffset + 4, 20, true);
    view.setUint16(centralOffset + 6, 10, true);
    view.setUint16(centralOffset + 8, 0, true);
    view.setUint16(centralOffset + 10, 0, true);
    view.setUint16(centralOffset + 12, 0, true);
    view.setUint16(centralOffset + 14, 0, true);
    view.setUint32(centralOffset + 16, crc, true);
    view.setUint32(centralOffset + 20, file.data.length, true);
    view.setUint32(centralOffset + 24, file.data.length, true);
    view.setUint16(centralOffset + 28, nameBytes.length, true);
    view.setUint16(centralOffset + 30, 0, true);
    view.setUint16(centralOffset + 32, 0, true);
    view.setUint16(centralOffset + 34, 0, true);
    view.setUint16(centralOffset + 36, 0, true);
    view.setUint32(centralOffset + 38, 0, true);
    view.setUint32(centralOffset + 42, fileLocalOffset, true);
    buffer.set(nameBytes, centralOffset + 46);

    centralOffset += 46 + nameBytes.length;
  }

  const eocdOffset = centralOffset;
  view.setUint32(eocdOffset, 0x06054b50, true);
  view.setUint16(eocdOffset + 4, 0, true);
  view.setUint16(eocdOffset + 6, 0, true);
  view.setUint16(eocdOffset + 8, files.length, true);
  view.setUint16(eocdOffset + 10, files.length, true);
  view.setUint32(eocdOffset + 12, centralDirectorySize, true);
  view.setUint32(eocdOffset + 16, centralDirectoryStart, true);
  view.setUint16(eocdOffset + 20, 0, true);

  return buffer.buffer.slice(
    buffer.byteOffset,
    buffer.byteOffset + buffer.byteLength
  );
}

export function crc32(data: Uint8Array): number {
  let crc = 0xFFFFFFFF;
  const table = getCrc32Table();
  for (let i = 0; i < data.length; i++) {
    crc = (crc >>> 8) ^ table[(crc ^ data[i]) & 0xFF];
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

let crc32Table: Uint32Array | null = null;
function getCrc32Table(): Uint32Array {
  if (crc32Table) return crc32Table;
  crc32Table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) {
      c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    crc32Table[i] = c;
  }
  return crc32Table;
}

export async function computeContentHash(content: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(content);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export function generateReproducibleExport(
  certificates: Array<{ pem_data: string; subject: string; fingerprint_sha256: string; created_at: string; last_check_at: string }>
): { content: string; manifest: ExportManifest } {
  const sortedCerts = [...certificates].sort((a, b) => 
    a.fingerprint_sha256.localeCompare(b.fingerprint_sha256)
  );

  const bundle = sortedCerts.map(cert => 
    `# Subject: ${cert.subject}\n# Fingerprint: ${cert.fingerprint_sha256}\n${cert.pem_data}`
  ).join("\n\n");

  const manifest: ExportManifest = {
    version: "1.0.0",
    generatedAt: new Date().toISOString(),
    certificateCount: sortedCerts.length,
    certificates: sortedCerts.map(c => ({
      fingerprint_sha256: c.fingerprint_sha256,
      subject: c.subject,
      addedAt: c.created_at,
      lastVerified: c.last_check_at
    })),
    contentHash: ""
  };

  return { content: bundle, manifest };
}

export async function signManifest(env: Env, manifest: ExportManifest): Promise<ExportManifest> {
  if (!env.SIGNING_PRIVATE_KEY) {
    return manifest;
  }

  try {
    const keyData = Uint8Array.from(atob(env.SIGNING_PRIVATE_KEY), c => c.charCodeAt(0));
    const privateKey = await crypto.subtle.importKey(
      "pkcs8", keyData, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]
    );

    const manifestForSigning = { ...manifest };
    delete manifestForSigning.signature;
    delete manifestForSigning.signatureAlgorithm;
    delete (manifestForSigning as any).canonicalization;

    // CRITICAL: Use RFC 8785 canonical JSON for signing
    const canonicalJson = canonicalizeJSON(manifestForSigning);

    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      privateKey,
      new TextEncoder().encode(canonicalJson)
    );

    return {
      ...manifest,
      signature: btoa(String.fromCharCode(...new Uint8Array(signature))),
      signatureAlgorithm: "ECDSA-P256-SHA256",
      canonicalization: "RFC8785-JCS"
    };
  } catch (e: unknown) {
    console.error("Failed to sign manifest:", e);
    return manifest;
  }
}