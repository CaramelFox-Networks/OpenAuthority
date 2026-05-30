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


// ============================================================
// CRYPTOGRAPHIC UTILITIES
// ============================================================

export async function sha256(message: string): Promise<string> {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export function generateNonce(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Convert IEEE P1363 signature format (r||s) to ASN.1 DER format
 * Web Crypto API produces P1363, but Rekor expects DER
 */
export function p1363ToDer(signature: Uint8Array): Uint8Array {
  // P-256 signatures are 64 bytes: 32 bytes r + 32 bytes s
  if (signature.length !== 64) {
    throw new Error(`Invalid P1363 signature length: expected 64, got ${signature.length}`);
  }

  const r = signature.slice(0, 32);
  const s = signature.slice(32, 64);

  // Trim leading zeros and add 0x00 prefix if high bit is set (to keep positive)
  const rTrimmed = trimAndPad(r);
  const sTrimmed = trimAndPad(s);

  // Build ASN.1 DER structure:
  // SEQUENCE { INTEGER r, INTEGER s }
  const rDer = new Uint8Array([0x02, rTrimmed.length, ...rTrimmed]);
  const sDer = new Uint8Array([0x02, sTrimmed.length, ...sTrimmed]);

  const sequenceLength = rDer.length + sDer.length;

  // Handle length encoding (short form for < 128 bytes)
  if (sequenceLength < 128) {
    return new Uint8Array([0x30, sequenceLength, ...rDer, ...sDer]);
  } else {
    // Long form length encoding (unlikely for P-256 but handle it)
    return new Uint8Array([0x30, 0x81, sequenceLength, ...rDer, ...sDer]);
  }
}

/**
 * Trim leading zeros but add 0x00 prefix if high bit is set (to keep positive)
 */
export function trimAndPad(bytes: Uint8Array): Uint8Array {
  // Remove leading zeros
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) {
    start++;
  }

  // If high bit is set, prepend 0x00 to indicate positive number
  if (bytes[start] & 0x80) {
    const result = new Uint8Array(bytes.length - start + 1);
    result[0] = 0x00;
    result.set(bytes.slice(start), 1);
    return result;
  }

  return bytes.slice(start);
}