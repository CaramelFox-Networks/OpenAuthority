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

import { Env } from "../types";
import { p1363ToDer } from "../utils";
import { RekorEntry } from "../merkle";

// ============================================================
// EXTERNAL ANCHORING - SIGSTORE REKOR
// ============================================================

export async function submitToRekor(
  env: Env,
  checkpointHash: string,
  checkpointData: string
): Promise<RekorEntry | null> {
  const REKOR_URL = env.REKOR_URL || "https://rekor.sigstore.dev";

  try {
    if (!env.SIGNING_PRIVATE_KEY) {
      console.warn("No signing key available for Rekor submission");
      return null;
    }

    // Use the PEM version for Rekor
    let publicKeyForRekor = env.SIGNING_PUBLIC_KEY_PEM;

    if (!publicKeyForRekor && env.SIGNING_PUBLIC_KEY) {
      // Reconstruct PEM format from raw base64 and then base64-encode it
      const pemContent = `-----BEGIN PUBLIC KEY-----\n${env.SIGNING_PUBLIC_KEY.match(/.{1,64}/g)?.join('\n')}\n-----END PUBLIC KEY-----\n`;
      publicKeyForRekor = btoa(pemContent);
    }

    if (!publicKeyForRekor) {
      console.warn("No public key available for Rekor submission");
      return null;
    }

    const keyData = Uint8Array.from(atob(env.SIGNING_PRIVATE_KEY), c => c.charCodeAt(0));
    const privateKey = await crypto.subtle.importKey(
      "pkcs8",
      keyData,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"]
    );

    const signatureP1363 = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      privateKey,
      new TextEncoder().encode(checkpointData) 
    );

    // Convert P1363 signature to ASN.1 DER format for Rekor
    const signatureDer = p1363ToDer(new Uint8Array(signatureP1363));
    const signatureBase64 = btoa(String.fromCharCode(...signatureDer));

    const entry = {
      apiVersion: "0.0.1",
      kind: "hashedrekord",
      spec: {
        data: {
          hash: {
            algorithm: "sha256",
            value: checkpointHash
          }
        },
        signature: {
          content: signatureBase64,
          publicKey: {
            content: publicKeyForRekor
          }
        }
      }
    };

    const rekorLeafBody = JSON.stringify(entry);
    const rekorLeafBodyBase64 = btoa(rekorLeafBody);

    const response = await fetch(`${REKOR_URL}/api/v1/log/entries`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: rekorLeafBody
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error("Rekor submission failed:", response.status, errorText);
      return null;
    }

    const result = await response.json() as Record<string, any>;
    const uuid = Object.keys(result)[0];
    const entryData = result[uuid];

    return {
      uuid,
      logIndex: entryData.logIndex,
      integratedTime: entryData.integratedTime,
      body: entryData.body,
      submittedBody: rekorLeafBodyBase64,
      inclusionProof: entryData.verification?.inclusionProof || {
        logIndex: entryData.logIndex,
        rootHash: '',
        treeSize: 0,
        hashes: []
      }
    };
  } catch (e: unknown) {
    console.error("Failed to submit to Rekor:", e);
    return null;
  }
}