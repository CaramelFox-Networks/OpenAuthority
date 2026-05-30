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

import { Env, ExternalAnchor } from "../types";

// ============================================================
// RFC 3161 TIMESTAMP ANCHORING
// ============================================================

export async function createRFC3161Timestamp(
  env: Env,
  dataHash: string
): Promise<ExternalAnchor | null> {
  const TSA_URL = env.TIMESTAMP_SERVICE_URL || "https://freetsa.org/tsr";

  try {
    const hashBytes = new Uint8Array(
      dataHash.match(/.{2}/g)!.map(byte => parseInt(byte, 16))
    );

    const sha256Oid = new Uint8Array([
      0x30, 0x31, 0x30, 0x0d, 0x06, 0x09,
      0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
      0x05, 0x00, 0x04, 0x20,
      ...hashBytes
    ]);

    const version = new Uint8Array([0x02, 0x01, 0x01]);
    const certReq = new Uint8Array([0x01, 0x01, 0xff]);

    const innerLength = version.length + sha256Oid.length + certReq.length;
    const tsReq = new Uint8Array([
      0x30, innerLength,
      ...version,
      ...sha256Oid,
      ...certReq
    ]);

    const response = await fetch(TSA_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/timestamp-query' },
      body: tsReq
    });

    if (!response.ok) return null;

    const tsrBuffer = await response.arrayBuffer();
    const tsrBase64 = btoa(String.fromCharCode(...new Uint8Array(tsrBuffer)));

    return {
      type: 'rfc3161',
      timestamp: new Date().toISOString(),
      proof: tsrBase64,
      serviceUrl: TSA_URL
    };
  } catch (e: unknown) {
    console.error("Failed to create RFC 3161 timestamp:", e);
    return null;
  }
}