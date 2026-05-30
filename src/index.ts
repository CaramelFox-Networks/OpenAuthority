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
import { 
  Env, THREAT_MODEL_VERSION, OPERATOR_TRUST_VERSION
} from "./types";
import { ScheduledEvent, ExecutionContext } from "@cloudflare/workers-types/experimental";
import {
  MERKLE_TREE_VERSION,
  MAX_MERKLE_TREE_SIZE,
  MAX_PROOF_SIBLINGS,
  MAX_EXPORT_CERTIFICATES,
  DNS_MAX_NAME_LENGTH,
  DNS_MAX_LABEL_LENGTH,
} from './config/constants';
import { runPeriodicVerification } from './jobs/periodic-validation';
import {
  handlePublicRoutes,
  handleCertificateRoutes,
  handleAuditRoutes,
  handleTransparencyRoutes,
  handleExportRoutes
} from './routes';


// ============================================================
// MAIN EXPORT DEFAULT HANDLER
// ============================================================

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      if (url.pathname === "/health") {
        return new Response(JSON.stringify({ 
          status: "ok", 
          timestamp: new Date().toISOString(),
          threatModelVersion: THREAT_MODEL_VERSION,
          operatorTrustVersion: OPERATOR_TRUST_VERSION,
          merkleTreeVersion: MERKLE_TREE_VERSION,
          canonicalization: "RFC8785-JCS",
          limits: {
            maxTreeSize: MAX_MERKLE_TREE_SIZE,
            maxProofSiblings: MAX_PROOF_SIBLINGS,
            maxExportCertificates: MAX_EXPORT_CERTIFICATES,
            maxDomainLength: DNS_MAX_NAME_LENGTH,
            maxLabelLength: DNS_MAX_LABEL_LENGTH
          }
        }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      const routeResponse =
        await handlePublicRoutes(request, env, corsHeaders)
        ?? await handleCertificateRoutes(request, env, corsHeaders)
        ?? await handleAuditRoutes(request, env, corsHeaders)
        ?? await handleTransparencyRoutes(request, env, corsHeaders)
        ?? await handleExportRoutes(request, env, corsHeaders);

      if (routeResponse) {
        return routeResponse;
      }

      return new Response("Not Found", { status: 404, headers: corsHeaders });
    } catch (e: unknown) {
      console.error("Error:", e);
      return new Response(
        JSON.stringify({ error: e instanceof Error ? e.message : "Unknown error" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }
  },

  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(runPeriodicVerification(env));
  }
};