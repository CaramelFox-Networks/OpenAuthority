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

import { validateDomainStrict } from "./domain";

export async function safeDNSLookup(
  domain: string,
  fingerprint: string,
  lookupFn: (domain: string, fingerprint: string) => Promise<{ success: boolean; error?: string }>
): Promise<{ success: boolean; error?: string; normalizedDomain?: string }> {
  const validation = validateDomainStrict(domain);
  if (!validation.isValid) {
    return { success: false, error: `Invalid domain: ${validation.error}` };
  }

  const result = await lookupFn(validation.normalized, fingerprint);
  return { ...result, normalizedDomain: validation.normalized };
}