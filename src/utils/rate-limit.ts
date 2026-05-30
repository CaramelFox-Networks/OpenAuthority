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

import { RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECONDS } from "../config/constants";
import { Env } from "../types";

export async function checkRateLimit(env: Env, ip: string): Promise<{ allowed: boolean; remaining: number }> {
  if (!env.RATE_LIMIT_KV) {
    console.warn("Rate limiting KV not configured - allowing request");
    return { allowed: true, remaining: RATE_LIMIT_MAX_REQUESTS };
  }

  const key = `upload:${ip}`;
  const current = await env.RATE_LIMIT_KV.get(key);
  const count = current ? parseInt(current, 10) : 0;

  if (count >= RATE_LIMIT_MAX_REQUESTS) {
    return { allowed: false, remaining: 0 };
  }

  await env.RATE_LIMIT_KV.put(key, String(count + 1), { expirationTtl: RATE_LIMIT_WINDOW_SECONDS });
  return { allowed: true, remaining: RATE_LIMIT_MAX_REQUESTS - count - 1 };
}