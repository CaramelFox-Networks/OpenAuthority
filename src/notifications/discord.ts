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

import { Env, AuditEventType } from "../types";
import { extractCN } from "../certificates";

// ============================================================
// DISCORD NOTIFICATIONS
// ============================================================

export async function sendDiscordNotification(
  env: Env,
  eventType: AuditEventType,
  subject: string,
  success: boolean,
  details: string
): Promise<void> {
  if (!env.DISCORD_WEBHOOK_URL) {
    return;
  }

  const notifiableEvents: AuditEventType[] = [
    'certificate_added',
    'certificate_promoted', 
    'certificate_revoked',
    'dns',
    'whois'
  ];

  if (!notifiableEvents.includes(eventType)) {
    return;
  }

  const cn = extractCN(subject);

  const eventConfig: Record<string, { title: string; color: number; emoji: string }> = {
    'certificate_added': { title: 'Certificate Created', color: 0x57F287, emoji: '🆕' },
    'certificate_promoted': { title: 'CA Promoted to Active', color: 0x5865F2, emoji: '⬆️' },
    'certificate_revoked': { title: 'Certificate Revoked', color: 0xED4245, emoji: '🚫' },
    'dns': { title: 'DNS Validation', color: success ? 0x57F287 : 0xFEE75C, emoji: success ? '✅' : '⚠️' },
    'whois': { title: 'WHOIS Validation', color: success ? 0x57F287 : 0xFEE75C, emoji: success ? '✅' : '⚠️' }
  };

  const config = eventConfig[eventType] || { title: eventType, color: 0x99AAB5, emoji: '📋' };

  const embed = {
    title: `${config.emoji} ${config.title}`,
    color: config.color,
    fields: [
      { name: 'Common Name (CN)', value: cn || 'N/A', inline: true },
      { name: 'Status', value: success ? 'Success' : 'Failed', inline: true },
      { name: 'Details', value: details.substring(0, 1024) }
    ],
    timestamp: new Date().toISOString(),
    footer: { text: 'OpenAuthority Trust Store' }
  };

  try {
    await fetch(env.DISCORD_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ embeds: [embed] })
    });
  } catch (e: unknown) {
    console.error('Discord notification failed:', e);
  }
}