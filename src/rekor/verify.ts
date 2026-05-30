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

export async function verifyRekorEntry(
  uuid: string,
  expectedHash: string
): Promise<{ valid: boolean; error?: string }> {
  const REKOR_URL = "https://rekor.sigstore.dev";

  try {
    const response = await fetch(`${REKOR_URL}/api/v1/log/entries/${uuid}`);

    if (!response.ok) {
      return { valid: false, error: `Entry not found: ${response.status}` };
    }

    const result = await response.json() as Record<string, any>;
    const entryData = result[uuid];

    const body = JSON.parse(atob(entryData.body));
    const storedHash = body.spec?.data?.hash?.value;

    if (storedHash !== expectedHash) {
      return { valid: false, error: 'Hash mismatch' };
    }

    return { valid: true };
  } catch (e: unknown) {
    return { valid: false, error: `Verification failed: ${e}` };
  }
}
