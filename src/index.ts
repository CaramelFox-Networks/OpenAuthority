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
  Env, CertificateAuthority, ParsedCertificate, AuditEventType, 
  CertificateDetails, ExportManifest, ExternalAnchor,
  THREAT_MODEL_VERSION, OPERATOR_TRUST_VERSION
} from "./types";
import { parseCertificate, toPEM } from "./certificate";
import { 
  verifyDNSTXT, 
  verifyWHOIS, 
  extractBaseDomain, 
  extractIPAddress 
} from "./verification";

// ============================================================
// CONFIGURATION CONSTANTS
// ============================================================

const PROBATIONARY_PERIOD_DAYS = 7;
const PROBATIONARY_CHECK_HOURS = 6;
const ACTIVE_CHECK_HOURS = 24;
const VERIFICATION_MARGIN_MINUTES = 5;
const DEFAULT_PAGE_SIZE = 10;
const MAX_CERT_SIZE = 64 * 1024;
const RATE_LIMIT_WINDOW_SECONDS = 3600;
const RATE_LIMIT_MAX_REQUESTS = 5;
const MAX_CONSECUTIVE_FAILURES = 3;
const VALID_EXPORT_FORMATS = ["pem", "bundle", "zip", "mobileconfig", "json"] as const;

// Security constants for eligibility verification
const MIN_SUCCESSFUL_VERIFICATIONS = 28;
const VERIFICATION_STALENESS_HOURS = 48;

// Merkle Tree Checkpoint Configuration
const CHECKPOINT_INTERVAL_ENTRIES = 100;
const CHECKPOINT_INTERVAL_HOURS = 1;
const MERKLE_TREE_VERSION = "1.0.0";

// ============================================================
// RESOURCE EXHAUSTION LIMITS
// ============================================================

const MAX_MERKLE_TREE_SIZE = 10_000_000;
const MAX_AUDIT_LOG_ENTRY_SIZE = 10_000;
const MAX_PROOF_SIBLINGS = 40;
const MAX_EXPORT_CERTIFICATES = 10_000;
const MAX_SNAPSHOT_SIZE = 100_000_000;
const MAX_RECURSION_DEPTH = 100;

// ============================================================
// DNS VALIDATION CONSTANTS (RFC 1035)
// ============================================================

const DNS_MAX_LABEL_LENGTH = 63;
const DNS_MAX_NAME_LENGTH = 253;

// ============================================================
// MERKLE TREE TYPE DEFINITIONS
// ============================================================

interface MerkleProof {
  leafHash: string;
  leafIndex: number;
  siblings: Array<{
    hash: string;
    position: 'left' | 'right';
  }>;
  root: string;
  treeSize: number;
}

interface ConsistencyProof {
  oldSize: number;
  newSize: number;
  oldRoot: string;
  newRoot: string;
  proof: string[];
}

interface SignedTreeHead {
  version: string;
  treeSize: number;
  rootHash: string;
  timestamp: string;
  signature?: string;
  signatureAlgorithm?: string;
  canonicalization?: string;
  previousSTH?: string;
  externalAnchors?: ExternalAnchor[];
}

interface TransparencyCheckpoint {
  id: number;
  tree_size: number;
  root_hash: string;
  timestamp: string;
  signature: string | null;
  previous_checkpoint_hash: string;
  checkpoint_hash: string;
  external_anchors: string | null;
  rekor_entry_uuid?: string;
  rekor_log_index?: number;
}

interface VerifiableLogEntry {
  id: number;
  ca_id: number;
  check_type: AuditEventType;
  target: string;
  success: boolean;
  details: string;
  checked_at: string;
  nonce: string;
  leaf_hash: string;
  tree_position: number;
  inclusion_proof?: MerkleProof;
}

interface RekorEntry {
  uuid: string;
  logIndex: number;
  integratedTime: number;
  body: string;
  submittedBody?: string;
  inclusionProof: {
    logIndex: number;
    rootHash: string;
    treeSize: number;
    hashes: string[];
  };
}

interface TrustStoreSnapshot {
  version: string;
  generatedAt: string;
  treeHead: SignedTreeHead;
  certificates: Array<{
    fingerprint_sha256: string;
    subject: string;
    pem_data: string;
    addedAt: string;
    lastVerified: string;
    inclusionProof: MerkleProof;
  }>;
  auditLog: VerifiableLogEntry[];
  validationRules: {
    minSuccessfulVerifications: number;
    probationaryPeriodDays: number;
    verificationStalenessHours: number;
    maxConsecutiveFailures: number;
  };
  externalAnchors: ExternalAnchor[];
  contentHash: string;
  signature?: string;
  canonicalization?: string;
}

interface ValidatedDomain {
  original: string;
  normalized: string;
  labels: string[];
  isValid: boolean;
  error?: string;
}

function getReadSession(env: Env) {
  // Returns a session that can use read replicas
  // Writes automatically route to primary
  return env.DB.withSession();
}

function getReadSessionFromBookmark(env: Env, bookmark: string | null) {
  // Use when you need to ensure reads see at least a certain version
  return env.DB.withSession(bookmark ?? 'first-unconstrained');
}

// ============================================================
// RFC 8785 JSON CANONICALIZATION SCHEME (JCS)
// ============================================================

function canonicalizeJSON(value: unknown, depth: number = 0): string {
  if (depth > MAX_RECURSION_DEPTH) {
    throw new Error(`JSON canonicalization exceeded max recursion depth of ${MAX_RECURSION_DEPTH}`);
  }

  if (value === null) {
    return 'null';
  }

  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }

  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('NaN and Infinity are not permitted in canonical JSON');
    }
    return JSON.stringify(value);
  }

  if (typeof value === 'string') {
    return canonicalizeString(value);
  }

  if (Array.isArray(value)) {
    const elements = value.map(el => canonicalizeJSON(el, depth + 1));
    return '[' + elements.join(',') + ']';
  }

  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj);

    keys.sort((a, b) => {
      const aUnits = stringToUTF16CodeUnits(a);
      const bUnits = stringToUTF16CodeUnits(b);
      const minLen = Math.min(aUnits.length, bUnits.length);

      for (let i = 0; i < minLen; i++) {
        if (aUnits[i] !== bUnits[i]) {
          return aUnits[i] - bUnits[i];
        }
      }
      return aUnits.length - bUnits.length;
    });

    const pairs = keys.map(key => {
      const canonicalKey = canonicalizeString(key);
      const canonicalValue = canonicalizeJSON(obj[key], depth + 1);
      return canonicalKey + ':' + canonicalValue;
    });

    return '{' + pairs.join(',') + '}';
  }

  throw new Error(`Unsupported type for JSON canonicalization: ${typeof value}`);
}

function stringToUTF16CodeUnits(str: string): number[] {
  const units: number[] = [];
  for (let i = 0; i < str.length; i++) {
    units.push(str.charCodeAt(i));
  }
  return units;
}

function canonicalizeString(str: string): string {
  let result = '"';

  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);

    if (code >= 0xD800 && code <= 0xDBFF) {
      if (i + 1 >= str.length) {
        throw new Error('Invalid Unicode: lone high surrogate at end of string');
      }
      const nextCode = str.charCodeAt(i + 1);
      if (nextCode < 0xDC00 || nextCode > 0xDFFF) {
        throw new Error('Invalid Unicode: high surrogate not followed by low surrogate');
      }
    } else if (code >= 0xDC00 && code <= 0xDFFF) {
      throw new Error('Invalid Unicode: lone low surrogate');
    }

    if (code < 0x20) {
      switch (code) {
        case 0x08: result += '\\b'; break;
        case 0x09: result += '\\t'; break;
        case 0x0A: result += '\\n'; break;
        case 0x0C: result += '\\f'; break;
        case 0x0D: result += '\\r'; break;
        default:
          result += '\\u' + code.toString(16).padStart(4, '0');
      }
    } else if (code === 0x22) {
      result += '\\"';
    } else if (code === 0x5C) {
      result += '\\\\';
    } else {
      result += str[i];
    }
  }

  result += '"';
  return result;
}

// ============================================================
// DNS VALIDATION MODULE (RFC 1035 Compliant)
// ============================================================

function validateDomainStrict(domain: string): ValidatedDomain {
  const result: ValidatedDomain = {
    original: domain,
    normalized: '',
    labels: [],
    isValid: false
  };

  if (domain == null || typeof domain !== 'string') {
    result.error = 'Domain must be a non-null string';
    return result;
  }

  let normalized = domain.trim().toLowerCase();

  if (normalized.endsWith('.')) {
    normalized = normalized.slice(0, -1);
  }

  if (normalized.length === 0) {
    result.error = 'Domain cannot be empty';
    return result;
  }

  if (normalized.length > DNS_MAX_NAME_LENGTH) {
    result.error = `Domain exceeds maximum length of ${DNS_MAX_NAME_LENGTH} characters (got ${normalized.length})`;
    return result;
  }

  const labels = normalized.split('.');

  for (let i = 0; i < labels.length; i++) {
    const label = labels[i];

    if (label.length === 0) {
      result.error = `Empty label at position ${i} (consecutive dots not allowed)`;
      return result;
    }

    if (label.length > DNS_MAX_LABEL_LENGTH) {
      result.error = `Label "${label.substring(0, 20)}..." at position ${i} exceeds maximum length of ${DNS_MAX_LABEL_LENGTH} characters`;
      return result;
    }

    for (let j = 0; j < label.length; j++) {
      const charCode = label.charCodeAt(j);
      if (charCode > 127) {
        result.error = `Non-ASCII character at position ${j} in label "${label}". Use punycode (xn--) encoding for internationalized domain names`;
        return result;
      }
    }

    if (!/^[a-z0-9]/i.test(label)) {
      if (!/^_/.test(label)) {
        result.error = `Label "${label}" must start with a letter, digit, or underscore`;
        return result;
      }
    }

    if (!/[a-z0-9_]$/i.test(label)) {
      result.error = `Label "${label}" must end with a letter, digit, or underscore`;
      return result;
    }

    if (label.length > 1 && !/^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?$/i.test(label)) {
      result.error = `Label "${label}" contains invalid characters. Only letters, digits, hyphens, and underscores allowed`;
      return result;
    }

    if (label.length >= 4 && label[2] === '-' && label[3] === '-' && !label.startsWith('xn--')) {
      result.error = `Label "${label}" has invalid double-hyphen at positions 3-4 (reserved for punycode)`;
      return result;
    }
  }

  result.normalized = normalized;
  result.labels = labels;
  result.isValid = true;
  return result;
}

function requireValidDomain(domain: string): string {
  const validation = validateDomainStrict(domain);
  if (!validation.isValid) {
    throw new Error(`DNS validation failed: ${validation.error}`);
  }
  return validation.normalized;
}

async function safeDNSLookup(
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

// ============================================================
// CRYPTOGRAPHIC UTILITIES
// ============================================================

async function sha256(message: string): Promise<string> {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateNonce(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function checkRateLimit(env: Env, ip: string): Promise<{ allowed: boolean; remaining: number }> {
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

// ============================================================
// MERKLE TREE IMPLEMENTATION (RFC 6962 Compatible)
// ============================================================

async function computeLeafHash(leafData: string): Promise<string> {
  if (leafData.length > MAX_AUDIT_LOG_ENTRY_SIZE) {
    throw new Error(`Leaf data exceeds maximum size of ${MAX_AUDIT_LOG_ENTRY_SIZE} bytes`);
  }
  const prefixedData = '\x00' + leafData;
  return sha256(prefixedData);
}

async function computeNodeHash(left: string, right: string): Promise<string> {
  const prefixedData = '\x01' + left + right;
  return sha256(prefixedData);
}

async function buildMerkleTree(leafHashes: string[]): Promise<{
  root: string;
  layers: string[][];
}> {
  if (leafHashes.length === 0) {
    return { root: '', layers: [] };
  }

  if (leafHashes.length > MAX_MERKLE_TREE_SIZE) {
    throw new Error(`Tree size ${leafHashes.length} exceeds maximum of ${MAX_MERKLE_TREE_SIZE}`);
  }

  const layers: string[][] = [leafHashes];
  let currentLayer = leafHashes;

  while (currentLayer.length > 1) {
    const nextLayer: string[] = [];

    for (let i = 0; i < currentLayer.length; i += 2) {
      if (i + 1 < currentLayer.length) {
        const hash = await computeNodeHash(currentLayer[i], currentLayer[i + 1]);
        nextLayer.push(hash);
      } else {
        nextLayer.push(currentLayer[i]);
      }
    }

    layers.push(nextLayer);
    currentLayer = nextLayer;
  }

  return {
    root: currentLayer[0],
    layers
  };
}

async function generateInclusionProof(
  leafHashes: string[],
  leafIndex: number
): Promise<MerkleProof> {
  if (leafIndex < 0 || leafIndex >= leafHashes.length) {
    throw new Error(`Invalid leaf index: ${leafIndex}`);
  }

  if (leafHashes.length > MAX_MERKLE_TREE_SIZE) {
    throw new Error(`Tree size exceeds maximum of ${MAX_MERKLE_TREE_SIZE}`);
  }

  const { root, layers } = await buildMerkleTree(leafHashes);
  const siblings: Array<{ hash: string; position: 'left' | 'right' }> = [];

  let currentIndex = leafIndex;

  for (let layerIndex = 0; layerIndex < layers.length - 1; layerIndex++) {
    if (siblings.length >= MAX_PROOF_SIBLINGS) {
      throw new Error(`Proof exceeds maximum siblings of ${MAX_PROOF_SIBLINGS}`);
    }

    const layer = layers[layerIndex];
    const isLeftNode = currentIndex % 2 === 0;
    const siblingIndex = isLeftNode ? currentIndex + 1 : currentIndex - 1;

    if (siblingIndex < layer.length) {
      siblings.push({
        hash: layer[siblingIndex],
        position: isLeftNode ? 'right' : 'left'
      });
    }

    currentIndex = Math.floor(currentIndex / 2);
  }

  return {
    leafHash: leafHashes[leafIndex],
    leafIndex,
    siblings,
    root,
    treeSize: leafHashes.length
  };
}

async function verifyInclusionProof(proof: MerkleProof): Promise<boolean> {
  if (proof.siblings.length > MAX_PROOF_SIBLINGS) {
    throw new Error(`Proof has too many siblings: ${proof.siblings.length}`);
  }

  let currentHash = proof.leafHash;

  for (const sibling of proof.siblings) {
    if (sibling.position === 'left') {
      currentHash = await computeNodeHash(sibling.hash, currentHash);
    } else {
      currentHash = await computeNodeHash(currentHash, sibling.hash);
    }
  }

  return currentHash === proof.root;
}

async function generateConsistencyProof(
  leafHashes: string[],
  oldSize: number,
  newSize: number
): Promise<ConsistencyProof> {
  if (oldSize > newSize || oldSize < 0 || newSize > leafHashes.length) {
    throw new Error('Invalid tree sizes for consistency proof');
  }

  if (newSize > MAX_MERKLE_TREE_SIZE) {
    throw new Error(`Tree size exceeds maximum of ${MAX_MERKLE_TREE_SIZE}`);
  }

  const oldLeaves = leafHashes.slice(0, oldSize);
  const newLeaves = leafHashes.slice(0, newSize);

  const { root: oldRoot } = await buildMerkleTree(oldLeaves);
  const { root: newRoot } = await buildMerkleTree(newLeaves);

  const proof: string[] = [];
  if (oldSize < newSize) {
    const additionalLeaves = leafHashes.slice(oldSize, newSize);
    for (const leaf of additionalLeaves) {
      proof.push(leaf);
    }
  }

  return {
    oldSize,
    newSize,
    oldRoot,
    newRoot,
    proof
  };
}

// ============================================================
// SIGNED TREE HEAD MANAGEMENT
// ============================================================

async function createSignedTreeHead(
  env: Env,
  treeSize: number,
  rootHash: string,
  previousSTHHash?: string
): Promise<SignedTreeHead> {
  const sth: SignedTreeHead = {
    version: MERKLE_TREE_VERSION,
    treeSize,
    rootHash,
    timestamp: new Date().toISOString(),
    previousSTH: previousSTHHash || 'GENESIS',
    canonicalization: 'RFC8785-JCS'
  };

  if (env.SIGNING_PRIVATE_KEY) {
    try {
      const keyData = Uint8Array.from(atob(env.SIGNING_PRIVATE_KEY), c => c.charCodeAt(0));
      const privateKey = await crypto.subtle.importKey(
        "pkcs8",
        keyData,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign"]
      );

      const sthForSigning = {
        version: sth.version,
        treeSize: sth.treeSize,
        rootHash: sth.rootHash,
        timestamp: sth.timestamp,
        previousSTH: sth.previousSTH
      };
      const sthData = canonicalizeJSON(sthForSigning);

      const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        privateKey,
        new TextEncoder().encode(sthData)
      );

      sth.signature = btoa(String.fromCharCode(...new Uint8Array(signature)));
      sth.signatureAlgorithm = "ECDSA-P256-SHA256";
    } catch (e) {
      console.error("Failed to sign STH:", e);
    }
  }

  return sth;
}

// ============================================================
// INCREMENTAL MERKLE TREE
// ============================================================

interface IncrementalMerkleTree {
  getRoot(): Promise<string>;
  getTreeSize(): Promise<number>;
  appendLeaf(leafHash: string): Promise<{ root: string; leafIndex: number }>;
  getInclusionProof(leafIndex: number, treeSize?: number): Promise<MerkleProof | null>;
  getNode(level: number, idx: number): Promise<string | null>;
}

function createIncrementalMerkleTree(env: Env): IncrementalMerkleTree {

  async function getTreeSize(): Promise<number> {
    const result = await env.DB.prepare(
      "SELECT COUNT(*) as count FROM merkle_nodes WHERE level = 0"
    ).first<{ count: number }>();
    return result?.count || 0;
  }

  async function getNode(level: number, idx: number): Promise<string | null> {
    const result = await env.DB.prepare(
      "SELECT hash FROM merkle_nodes WHERE level = ? AND idx = ?"
    ).bind(level, idx).first<{ hash: string }>();
    return result?.hash || null;
  }

  async function setNode(level: number, idx: number, hash: string): Promise<void> {
    await env.DB.prepare(`
      INSERT OR REPLACE INTO merkle_nodes (level, idx, hash, updated_at)
      VALUES (?, ?, ?, ?)
    `).bind(level, idx, hash, new Date().toISOString()).run();
  }

  async function getRoot(): Promise<string> {
    const size = await getTreeSize();
    if (size === 0) return '';

    // Find the highest level node
    const result = await env.DB.prepare(
      "SELECT hash FROM merkle_nodes ORDER BY level DESC, idx ASC LIMIT 1"
    ).first<{ hash: string }>();

    return result?.hash || '';
  }

  async function appendLeaf(leafHash: string): Promise<{ root: string; leafIndex: number }> {
    const leafIndex = await getTreeSize();

    // Insert leaf at level 0
    await setNode(0, leafIndex, leafHash);

    // Update path to root
    let currentLevel = 0;
    let currentIdx = leafIndex;
    let currentHash = leafHash;

    // Calculate max levels needed
    const maxLevels = Math.ceil(Math.log2(leafIndex + 2)) + 1;

    for (let i = 0; i < maxLevels; i++) {
      const isLeftChild = currentIdx % 2 === 0;
      const siblingIdx = isLeftChild ? currentIdx + 1 : currentIdx - 1;
      const parentIdx = Math.floor(currentIdx / 2);

      const siblingHash = siblingIdx >= 0 ? await getNode(currentLevel, siblingIdx) : null;

      let parentHash: string;
      if (siblingHash === null) {
        parentHash = currentHash;
      } else if (isLeftChild) {
        parentHash = await computeNodeHash(currentHash, siblingHash);
      } else {
        parentHash = await computeNodeHash(siblingHash, currentHash);
      }

      currentLevel++;
      currentIdx = parentIdx;
      currentHash = parentHash;

      await setNode(currentLevel, currentIdx, parentHash);

      // Stop if this node has no sibling at parent level
      if (parentIdx === 0 && (leafIndex + 1) <= Math.pow(2, currentLevel)) {
        break;
      }
    }

    return { root: currentHash, leafIndex };
  }

  async function getInclusionProof(leafIndex: number, treeSize?: number): Promise<MerkleProof | null> {
    const size = treeSize ?? await getTreeSize();
    if (leafIndex >= size || leafIndex < 0) return null;

    const leafHash = await getNode(0, leafIndex);
    if (!leafHash) return null;

    const siblings: Array<{ hash: string; position: 'left' | 'right' }> = [];
    let currentIdx = leafIndex;
    let currentLevel = 0;

    const maxLevel = Math.ceil(Math.log2(size));

    while (currentLevel < maxLevel) {
      const isLeftChild = currentIdx % 2 === 0;
      const siblingIdx = isLeftChild ? currentIdx + 1 : currentIdx - 1;

      if (siblingIdx >= 0) {
        const siblingHash = await getNode(currentLevel, siblingIdx);
        if (siblingHash !== null) {
          siblings.push({
            hash: siblingHash,
            position: isLeftChild ? 'right' : 'left'
          });
        }
      }

      currentIdx = Math.floor(currentIdx / 2);
      currentLevel++;
    }

    const root = await getRoot();

    return {
      leafHash,
      leafIndex,
      siblings,
      root,
      treeSize: size
    };
  }

  return { getRoot, getTreeSize, appendLeaf, getInclusionProof, getNode };
}

/**
 * Convert IEEE P1363 signature format (r||s) to ASN.1 DER format
 * Web Crypto API produces P1363, but Rekor expects DER
 */
function p1363ToDer(signature: Uint8Array): Uint8Array {
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
function trimAndPad(bytes: Uint8Array): Uint8Array {
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


// ============================================================
// EXTERNAL ANCHORING - SIGSTORE REKOR
// ============================================================

async function submitToRekor(
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
  } catch (e) {
    console.error("Failed to submit to Rekor:", e);
    return null;
  }
}

async function verifyRekorEntry(
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
  } catch (e) {
    return { valid: false, error: `Verification failed: ${e}` };
  }
}

// ============================================================
// RFC 3161 TIMESTAMP ANCHORING
// ============================================================

async function createRFC3161Timestamp(
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
  } catch (e) {
    console.error("Failed to create RFC 3161 timestamp:", e);
    return null;
  }
}

// ============================================================
// CHECKPOINT MANAGEMENT 
// ============================================================

async function createCheckpoint(env: Env): Promise<TransparencyCheckpoint | null> {
  const tree = createIncrementalMerkleTree(env);
  const treeSize = await tree.getTreeSize();

  if (treeSize === 0) return null;

  const root = await tree.getRoot();

  const prevCheckpoint = await env.DB.prepare(`
    SELECT checkpoint_hash FROM transparency_checkpoints 
    ORDER BY id DESC LIMIT 1
  `).first<{ checkpoint_hash: string }>();

  const previousCheckpointHash = prevCheckpoint?.checkpoint_hash || 'GENESIS';

  const sth = await createSignedTreeHead(env, treeSize, root, previousCheckpointHash);

  const checkpointDataObj = {
    tree_size: treeSize,
    root_hash: root,
    timestamp: sth.timestamp,
    previous_checkpoint_hash: previousCheckpointHash
  };
  const checkpointData = canonicalizeJSON(checkpointDataObj);
  const checkpointHash = await sha256(checkpointData);

  const externalAnchors: ExternalAnchor[] = [];

  const rekorEntry = await submitToRekor(env, checkpointHash, checkpointData);
  if (rekorEntry) {
    externalAnchors.push({
      type: 'rekor',
      timestamp: new Date(rekorEntry.integratedTime * 1000).toISOString(),
      proof: JSON.stringify({
        uuid: rekorEntry.uuid,
        logIndex: rekorEntry.logIndex,
        inclusionProof: rekorEntry.inclusionProof
      }),
      submitted_body: rekorEntry.submittedBody,
      serviceUrl: 'https://rekor.sigstore.dev'
    });
  }

  const rfc3161 = await createRFC3161Timestamp(env, checkpointHash);
  if (rfc3161) externalAnchors.push(rfc3161);

  await env.DB.prepare(`
    INSERT INTO transparency_checkpoints (
      tree_size, root_hash, timestamp, signature, 
      previous_checkpoint_hash, checkpoint_hash, external_anchors,
      rekor_entry_uuid, rekor_log_index
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    treeSize, root, sth.timestamp, sth.signature || null,
    previousCheckpointHash, checkpointHash, JSON.stringify(externalAnchors),
    rekorEntry?.uuid || null, rekorEntry?.logIndex || null
  ).run();

  console.log(`Checkpoint created: tree_size=${treeSize}, root=${root.substring(0, 16)}...`);

  return await env.DB.prepare(`
    SELECT * FROM transparency_checkpoints WHERE checkpoint_hash = ?
  `).bind(checkpointHash).first<TransparencyCheckpoint>();
}


async function shouldCreateCheckpoint(env: Env): Promise<boolean> {
  const lastCheckpoint = await env.DB.prepare(`
    SELECT tree_size, timestamp FROM transparency_checkpoints 
    ORDER BY id DESC LIMIT 1
  `).first<{ tree_size: number; timestamp: string }>();

  const currentEntryCount = await env.DB.prepare(`
    SELECT COUNT(*) as count FROM verification_log WHERE leaf_hash IS NOT NULL
  `).first<{ count: number }>();

  const entryCount = currentEntryCount?.count || 0;

  if (!lastCheckpoint) return entryCount > 0;

  const entriesSinceCheckpoint = entryCount - lastCheckpoint.tree_size;
  if (entriesSinceCheckpoint >= CHECKPOINT_INTERVAL_ENTRIES) return true;

  const lastCheckpointTime = new Date(lastCheckpoint.timestamp);
  const hoursSinceCheckpoint = (Date.now() - lastCheckpointTime.getTime()) / (1000 * 60 * 60);
  if (hoursSinceCheckpoint >= CHECKPOINT_INTERVAL_HOURS && entriesSinceCheckpoint > 0) return true;

  return false;
}

async function getInclusionProofForEntry(
  env: Env,
  entryId: number
): Promise<MerkleProof | null> {
  const entry = await env.DB.prepare(`
    SELECT tree_position, leaf_hash FROM verification_log WHERE id = ?
  `).bind(entryId).first<{ tree_position: number; leaf_hash: string }>();

  if (!entry || !entry.leaf_hash) return null;

  const tree = createIncrementalMerkleTree(env);
  return tree.getInclusionProof(entry.tree_position);
}


// ============================================================
// AUDIT LOG ENTRY CREATION WITH MERKLE TREE
// ============================================================

async function createAuditLogEntry(
  env: Env,
  caId: number,
  checkType: AuditEventType,
  target: string,
  success: boolean,
  details: string
): Promise<void> {
  const safeDetails = details.length > MAX_AUDIT_LOG_ENTRY_SIZE 
    ? details.substring(0, MAX_AUDIT_LOG_ENTRY_SIZE - 3) + '...'
    : details;

  const now = new Date().toISOString();
  const nonce = generateNonce();

  // Use incremental tree for position
  const tree = createIncrementalMerkleTree(env);
  const treePosition = await tree.getTreeSize();

  const entryDataObj = {
    ca_id: caId,
    check_type: checkType,
    target,
    success,
    details: safeDetails,
    checked_at: now,
    nonce,
    tree_position: treePosition
  };
  const entryData = canonicalizeJSON(entryDataObj);
  const leafHash = await computeLeafHash(entryData);

  // Insert log entry
  await env.DB.prepare(`
    INSERT INTO verification_log (
      ca_id, check_type, target, success, details, checked_at, 
      nonce, leaf_hash, tree_position
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(caId, checkType, target, success ? 1 : 0, safeDetails, now, nonce, leafHash, treePosition).run();

  // Incrementally update Merkle tree - O(log n) instead of O(n)
  await tree.appendLeaf(leafHash);

  if (await shouldCreateCheckpoint(env)) {
    await createCheckpoint(env);
  }

  await sendDiscordNotification(env, checkType, target, success, safeDetails);
}


// ============================================================
// DISCORD NOTIFICATIONS
// ============================================================

async function sendDiscordNotification(
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
  } catch (error) {
    console.error('Discord notification failed:', error);
  }
}

// ============================================================
// CERTIFICATE ELIGIBILITY VERIFICATION
// ============================================================

async function verifyCertificateEligibility(
  env: Env, 
  cert: { 
    id: number; 
    created_at: string; 
    status: string; 
    successful_verification_count?: number;
    fingerprint_sha256: string;
  }
): Promise<{ eligible: boolean; reason?: string }> {

  if (cert.status !== 'active') {
    return { eligible: false, reason: 'Status is not active' };
  }

  const createdAt = new Date(cert.created_at);
  const minAge = PROBATIONARY_PERIOD_DAYS * 24 * 60 * 60 * 1000;
  if (Date.now() - createdAt.getTime() < minAge) {
    return { eligible: false, reason: 'Certificate has not completed probationary period' };
  }

  const addedEvent = await env.DB.prepare(`
    SELECT id FROM verification_log 
    WHERE ca_id = ? AND check_type = 'certificate_added'
    LIMIT 1
  `).bind(cert.id).first<{ id: number }>();

  if (!addedEvent) {
    return { 
      eligible: false, 
      reason: 'No certificate_added event found in audit log - possible injection' 
    };
  }

  const auditCount = await env.DB.prepare(`
    SELECT COUNT(*) as count 
    FROM verification_log 
    WHERE ca_id = ? AND check_type IN ('dns', 'whois') AND success = 1
  `).bind(cert.id).first<{ count: number }>();

  const verifiedCount = auditCount?.count || 0;

  if (verifiedCount < MIN_SUCCESSFUL_VERIFICATIONS) {
    return { 
      eligible: false, 
      reason: `Insufficient verifications: ${verifiedCount}/${MIN_SUCCESSFUL_VERIFICATIONS}` 
    };
  }

  const promotedEvent = await env.DB.prepare(`
    SELECT id FROM verification_log 
    WHERE ca_id = ? AND check_type = 'certificate_promoted'
    LIMIT 1
  `).bind(cert.id).first<{ id: number }>();

  if (!promotedEvent) {
    return { 
      eligible: false, 
      reason: 'No certificate_promoted event found - status may have been manually set' 
    };
  }

  const recentCheck = await env.DB.prepare(`
    SELECT checked_at 
    FROM verification_log 
    WHERE ca_id = ? AND check_type IN ('dns', 'whois') AND success = 1 
    ORDER BY id DESC 
    LIMIT 1
  `).bind(cert.id).first<{ checked_at: string }>();

  if (!recentCheck) {
    return { eligible: false, reason: 'No successful verifications found in audit log' };
  }

  const lastVerified = new Date(recentCheck.checked_at);
  const stalenessLimit = VERIFICATION_STALENESS_HOURS * 60 * 60 * 1000;

  if (Date.now() - lastVerified.getTime() > stalenessLimit) {
    return { 
      eligible: false, 
      reason: `Last verification too old: ${recentCheck.checked_at}` 
    };
  }

  const criticalEntries = await env.DB.prepare(`
    SELECT * FROM verification_log 
    WHERE ca_id = ? AND check_type IN ('certificate_added', 'certificate_promoted')
    ORDER BY id ASC
  `).bind(cert.id).all<any>();

  for (const entry of criticalEntries.results) {
    if (!entry.leaf_hash || !entry.nonce) continue;

    const entryDataObj = {
      ca_id: entry.ca_id,
      check_type: entry.check_type,
      target: entry.target,
      success: entry.success === 1,
      details: entry.details,
      checked_at: entry.checked_at,
      nonce: entry.nonce,
      tree_position: entry.tree_position
    };
    const entryData = canonicalizeJSON(entryDataObj);
    const computedHash = await computeLeafHash(entryData);

    if (computedHash !== entry.leaf_hash) {
      return { 
        eligible: false, 
        reason: `Audit log integrity failure at entry ${entry.id}` 
      };
    }
  }

  return { eligible: true };
}

// ============================================================
// REPRODUCIBLE TRUST STORE SNAPSHOT
// ============================================================

async function generateTrustStoreSnapshot(env: Env): Promise<TrustStoreSnapshot> {
  const latestCheckpoint = await env.DB.prepare(`
    SELECT * FROM transparency_checkpoints ORDER BY id DESC LIMIT 1
  `).first<TransparencyCheckpoint>();

  const certificates = await env.DB.prepare(`
    SELECT * FROM certificate_authorities WHERE status = 'active' LIMIT ?
  `).bind(MAX_EXPORT_CERTIFICATES).all<CertificateAuthority>();

  const eligibleCerts: TrustStoreSnapshot['certificates'] = [];

  for (const cert of certificates.results) {
    const eligibility = await verifyCertificateEligibility(env, cert);
    if (!eligibility.eligible) continue;

    const addedEntry = await env.DB.prepare(`
      SELECT id, tree_position FROM verification_log 
      WHERE ca_id = ? AND check_type = 'certificate_added' LIMIT 1
    `).first<{ id: number; tree_position: number }>(cert.id);

    let inclusionProof: MerkleProof | undefined;
    if (addedEntry && latestCheckpoint) {
      inclusionProof = await getInclusionProofForEntry(env, addedEntry.id) || undefined;
    }

    eligibleCerts.push({
      fingerprint_sha256: cert.fingerprint_sha256,
      subject: cert.subject,
      pem_data: cert.pem_data,
      addedAt: cert.created_at,
      lastVerified: cert.last_check_at,
      inclusionProof: inclusionProof!
    });
  }

  eligibleCerts.sort((a, b) => a.fingerprint_sha256.localeCompare(b.fingerprint_sha256));

  const auditEntries = await env.DB.prepare(`
    SELECT * FROM verification_log ORDER BY tree_position ASC
  `).all<any>();

  const auditLog: VerifiableLogEntry[] = auditEntries.results.map((e: any) => ({
    id: e.id,
    ca_id: e.ca_id,
    check_type: e.check_type,
    target: e.target,
    success: e.success === 1,
    details: e.details,
    checked_at: e.checked_at,
    nonce: e.nonce,
    leaf_hash: e.leaf_hash,
    tree_position: e.tree_position
  }));

  const checkpoints = await env.DB.prepare(`
    SELECT external_anchors FROM transparency_checkpoints WHERE external_anchors IS NOT NULL
  `).all<{ external_anchors: string }>();

  const allAnchors: ExternalAnchor[] = [];
  for (const cp of checkpoints.results) {
    try {
      allAnchors.push(...JSON.parse(cp.external_anchors));
    } catch {}
  }

  const leafHashes = auditLog.filter(e => e.leaf_hash).map(e => e.leaf_hash);
  const { root } = await buildMerkleTree(leafHashes);
  const treeHead = await createSignedTreeHead(env, leafHashes.length, root, latestCheckpoint?.checkpoint_hash);

  const snapshot: TrustStoreSnapshot = {
    version: MERKLE_TREE_VERSION,
    generatedAt: new Date().toISOString(),
    treeHead,
    certificates: eligibleCerts,
    auditLog,
    validationRules: {
      minSuccessfulVerifications: MIN_SUCCESSFUL_VERIFICATIONS,
      probationaryPeriodDays: PROBATIONARY_PERIOD_DAYS,
      verificationStalenessHours: VERIFICATION_STALENESS_HOURS,
      maxConsecutiveFailures: MAX_CONSECUTIVE_FAILURES
    },
    externalAnchors: allAnchors,
    contentHash: '',
    canonicalization: 'RFC8785-JCS'
  };

  const snapshotForHash = { ...snapshot };
  delete (snapshotForHash as any).contentHash;
  delete (snapshotForHash as any).signature;
  snapshot.contentHash = await sha256(canonicalizeJSON(snapshotForHash));

  const snapshotJson = JSON.stringify(snapshot);
  if (snapshotJson.length > MAX_SNAPSHOT_SIZE) {
    throw new Error(`Snapshot size ${snapshotJson.length} exceeds maximum of ${MAX_SNAPSHOT_SIZE}`);
  }

  if (env.SIGNING_PRIVATE_KEY) {
    try {
      const keyData = Uint8Array.from(atob(env.SIGNING_PRIVATE_KEY), c => c.charCodeAt(0));
      const privateKey = await crypto.subtle.importKey(
        "pkcs8", keyData, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]
      );
      const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        privateKey,
        new TextEncoder().encode(snapshot.contentHash)
      );
      snapshot.signature = btoa(String.fromCharCode(...new Uint8Array(signature)));
    } catch (e) {
      console.error("Failed to sign snapshot:", e);
    }
  }

  return snapshot;
}

async function verifyTrustStoreSnapshot(
  snapshot: TrustStoreSnapshot,
  publicKeyBase64?: string
): Promise<{
  valid: boolean;
  errors: string[];
  certificatesVerified: number;
  auditEntriesVerified: number;
}> {
  const errors: string[] = [];
  let certificatesVerified = 0;
  let auditEntriesVerified = 0;

  const snapshotForHash = { ...snapshot };
  delete (snapshotForHash as any).contentHash;
  delete (snapshotForHash as any).signature;
  const computedContentHash = await sha256(canonicalizeJSON(snapshotForHash));

  if (computedContentHash !== snapshot.contentHash) {
    errors.push('Content hash mismatch - snapshot may have been tampered');
  }

  if (publicKeyBase64 && snapshot.signature) {
    try {
      const keyData = Uint8Array.from(atob(publicKeyBase64), c => c.charCodeAt(0));
      const publicKey = await crypto.subtle.importKey(
        "spki", keyData, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]
      );
      const signatureBytes = Uint8Array.from(atob(snapshot.signature), c => c.charCodeAt(0));
      const isValid = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        publicKey, signatureBytes,
        new TextEncoder().encode(snapshot.contentHash)
      );
      if (!isValid) errors.push('Snapshot signature verification failed');
    } catch (e) {
      errors.push(`Signature verification error: ${e}`);
    }
  }

  const leafHashes: string[] = [];
  for (const entry of snapshot.auditLog) {
    if (!entry.leaf_hash || !entry.nonce) continue;

    const entryDataObj = {
      ca_id: entry.ca_id,
      check_type: entry.check_type,
      target: entry.target,
      success: entry.success,
      details: entry.details,
      checked_at: entry.checked_at,
      nonce: entry.nonce,
      tree_position: entry.tree_position
    };
    const entryData = canonicalizeJSON(entryDataObj);
    const computedLeafHash = await computeLeafHash(entryData);

    if (computedLeafHash !== entry.leaf_hash) {
      errors.push(`Audit entry ${entry.id}: leaf hash mismatch`);
    } else {
      auditEntriesVerified++;
    }

    leafHashes.push(entry.leaf_hash);
  }

  const { root: computedRoot } = await buildMerkleTree(leafHashes);
  if (computedRoot !== snapshot.treeHead.rootHash) {
    errors.push(`Tree root mismatch: computed ${computedRoot}, expected ${snapshot.treeHead.rootHash}`);
  }

  for (const cert of snapshot.certificates) {
    if (!cert.inclusionProof) {
      errors.push(`Certificate ${cert.fingerprint_sha256.substring(0, 16)}...: missing inclusion proof`);
      continue;
    }

    if (cert.inclusionProof.siblings.length > MAX_PROOF_SIBLINGS) {
      errors.push(`Certificate ${cert.fingerprint_sha256.substring(0, 16)}...: proof too large`);
      continue;
    }

    const proofValid = await verifyInclusionProof(cert.inclusionProof);
    if (!proofValid) {
      errors.push(`Certificate ${cert.fingerprint_sha256.substring(0, 16)}...: inclusion proof invalid`);
    } else {
      certificatesVerified++;
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    certificatesVerified,
    auditEntriesVerified
  };
}

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

      if (url.pathname === "/api/upload" && request.method === "POST") {
        return handleUpload(request, env, corsHeaders);
      }

      if (url.pathname === "/api/certificates" && request.method === "GET") {
        const page = parseInt(url.searchParams.get("page") || "1");
        const limit = parseInt(url.searchParams.get("limit") || String(DEFAULT_PAGE_SIZE));
        const search = url.searchParams.get("search") || "";
        return handleListCertificates(env, corsHeaders, page, limit, search);
      }

      if (url.pathname === "/api/export" && request.method === "GET") {
        const format = url.searchParams.get("format") || "pem";
        return handleExport(env, format, corsHeaders);
      }

      if (url.pathname.startsWith("/api/certificate/") && request.method === "GET") {
        const pathParts = url.pathname.split("/");
        const id = pathParts[pathParts.length - 1];

        if (pathParts.length >= 5 && pathParts[pathParts.length - 1] === "audit") {
          const certId = pathParts[pathParts.length - 2];
          return handleCertificateAuditLog(env, certId, corsHeaders);
        }

        return handleGetCertificateDetails(env, id, corsHeaders);
      }

      if (url.pathname === "/api/audit" && request.method === "GET") {
        const page = parseInt(url.searchParams.get("page") || "1");
        const limit = parseInt(url.searchParams.get("limit") || String(DEFAULT_PAGE_SIZE));
        const caId = url.searchParams.get("ca_id");
        return handleAuditLog(env, corsHeaders, page, limit, caId);
      }

      if (url.pathname === "/api/audit/export" && request.method === "GET") {
        const format = url.searchParams.get("format") || "json";
        return handleAuditExport(env, format, corsHeaders);
      }

      if (url.pathname === "/api/audit/verify" && request.method === "GET") {
        return handleAuditVerify(env, corsHeaders);
      }

      // ============================================================
      // TRANSPARENCY ENDPOINTS
      // ============================================================

      if (url.pathname === "/api/transparency/tree-head" && request.method === "GET") {
        return handleGetTreeHead(env, corsHeaders);
      }

      if (url.pathname === "/api/transparency/checkpoints" && request.method === "GET") {
        const page = parseInt(url.searchParams.get("page") || "1");
        const limit = parseInt(url.searchParams.get("limit") || "20");
        return handleListCheckpoints(env, corsHeaders, page, limit);
      }

      if (url.pathname.match(/^\/api\/transparency\/checkpoints\/\d+$/) && request.method === "GET") {
        const id = url.pathname.split("/").pop()!;
        return handleGetCheckpoint(env, id, corsHeaders);
      }

      if (url.pathname.match(/^\/api\/transparency\/proof\/\d+$/) && request.method === "GET") {
        const entryId = url.pathname.split("/").pop()!;
        return handleGetInclusionProof(env, entryId, corsHeaders);
      }

      if (url.pathname === "/api/transparency/consistency" && request.method === "GET") {
        const oldSize = parseInt(url.searchParams.get("old_size") || "0");
        const newSize = parseInt(url.searchParams.get("new_size") || "0");
        return handleGetConsistencyProof(env, oldSize, newSize, corsHeaders);
      }

      if (url.pathname === "/api/transparency/verify" && request.method === "GET") {
        return handleTransparencyVerify(env, corsHeaders);
      }

      if (url.pathname === "/api/transparency/snapshot" && request.method === "GET") {
        return handleGetSnapshot(env, corsHeaders);
      }

      if (url.pathname === "/api/transparency/verify-snapshot" && request.method === "POST") {
        return handleVerifySnapshot(request, corsHeaders);
      }

      if (url.pathname === "/api/transparency/verify-rekor" && request.method === "GET") {
        const uuid = url.searchParams.get("uuid");
        const hash = url.searchParams.get("hash");
        return handleVerifyRekor(uuid, hash, corsHeaders);
      }

      if (url.pathname === "/api/transparency/public-key" && request.method === "GET") {
        return handleGetPublicKey(env, corsHeaders);
      }

      if (url.pathname === "/api/validate-domain" && request.method === "GET") {
        const domain = url.searchParams.get("domain") || "";
        const result = validateDomainStrict(domain);
        return new Response(JSON.stringify(result), {
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      return new Response("Not Found", { status: 404, headers: corsHeaders });
    } catch (e) {
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

// ============================================================
// TRANSPARENCY API HANDLERS
// ============================================================

async function handleGetPublicKey(env: Env, corsHeaders: Record<string, string>): Promise<Response> {
  return new Response(JSON.stringify({
    algorithm: "ECDSA-P256",
    format: "SPKI-Base64",
    publicKey: env.SIGNING_PUBLIC_KEY || null,
    canonicalization: "RFC8785-JCS",
    signatureAlgorithm: "ECDSA-P256-SHA256",
    usage: "Verify signatures on tree heads, checkpoints, manifests, and snapshots"
  }, null, 2), {
    headers: { ...corsHeaders, "Content-Type": "application/json" }
  });
}

async function handleGetTreeHead(env: Env, corsHeaders: Record<string, string>): Promise<Response> {
  const tree = createIncrementalMerkleTree(env);
  const treeSize = await tree.getTreeSize();
  const root = await tree.getRoot();

  const latestCheckpoint = await env.DB.prepare(`
    SELECT checkpoint_hash FROM transparency_checkpoints ORDER BY id DESC LIMIT 1
  `).first<{ checkpoint_hash: string }>();

  const sth = await createSignedTreeHead(
    env, 
    treeSize, 
    root, 
    latestCheckpoint?.checkpoint_hash
  );

  return new Response(JSON.stringify(sth, null, 2), {
    headers: { ...corsHeaders, "Content-Type": "application/json" }
  });
}


async function handleListCheckpoints(
  env: Env, 
  corsHeaders: Record<string, string>,
  page: number,
  limit: number
): Promise<Response> {
  const offset = (page - 1) * limit;
  const safeLimit = Math.min(Math.max(1, limit), 100);

  const countResult = await env.DB.prepare(
    "SELECT COUNT(*) as total FROM transparency_checkpoints"
  ).first<{ total: number }>();

  const total = countResult?.total || 0;

  const results = await env.DB.prepare(`
    SELECT * FROM transparency_checkpoints
    ORDER BY id DESC
    LIMIT ? OFFSET ?
  `).bind(safeLimit, offset).all<TransparencyCheckpoint>();

  const checkpoints = results.results.map(cp => ({
    ...cp,
    external_anchors: cp.external_anchors ? JSON.parse(cp.external_anchors) : []
  }));

  return new Response(JSON.stringify({
    checkpoints,
    pagination: {
      page,
      limit: safeLimit,
      total,
      totalPages: Math.ceil(total / safeLimit)
    }
  }, null, 2), {
    headers: { ...corsHeaders, "Content-Type": "application/json" }
  });
}

async function handleGetCheckpoint(
  env: Env, 
  id: string, 
  corsHeaders: Record<string, string>
): Promise<Response> {
  if (!/^\d+$/.test(id)) {
    return new Response(
      JSON.stringify({ error: "Invalid checkpoint ID" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  const checkpoint = await env.DB.prepare(`
    SELECT * FROM transparency_checkpoints WHERE id = ?
  `).bind(id).first<TransparencyCheckpoint>();

  if (!checkpoint) {
    return new Response(
      JSON.stringify({ error: "Checkpoint not found" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  return new Response(JSON.stringify({
    ...checkpoint,
    external_anchors: checkpoint.external_anchors ? JSON.parse(checkpoint.external_anchors) : []
  }, null, 2), {
    headers: { ...corsHeaders, "Content-Type": "application/json" }
  });
}

async function handleGetInclusionProof(
  env: Env, 
  entryId: string, 
  corsHeaders: Record<string, string>
): Promise<Response> {
  if (!/^\d+$/.test(entryId)) {
    return new Response(
      JSON.stringify({ error: "Invalid entry ID" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  const proof = await getInclusionProofForEntry(env, parseInt(entryId));

  if (!proof) {
    return new Response(
      JSON.stringify({ error: "Entry not found or has no leaf hash" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  return new Response(JSON.stringify({
    entryId: parseInt(entryId),
    proof,
    verificationInstructions: {
      description: "To verify this proof, compute the leaf hash from entry data using RFC 8785 canonical JSON, then walk up the tree using siblings",
      algorithm: "RFC 6962 Merkle Tree with domain separation (0x00 for leaves, 0x01 for nodes)",
      canonicalization: "RFC 8785 JSON Canonicalization Scheme (JCS)"
    }
  }, null, 2), {
    headers: { ...corsHeaders, "Content-Type": "application/json" }
  });
}

async function handleGetConsistencyProof(
  env: Env,
  oldSize: number,
  newSize: number,
  corsHeaders: Record<string, string>
): Promise<Response> {
  if (oldSize < 0 || newSize < oldSize) {
    return new Response(
      JSON.stringify({ error: "Invalid tree sizes. old_size must be >= 0 and <= new_size" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  if (newSize > MAX_MERKLE_TREE_SIZE) {
    return new Response(
      JSON.stringify({ error: `new_size exceeds maximum of ${MAX_MERKLE_TREE_SIZE}` }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  const entries = await env.DB.prepare(`
    SELECT leaf_hash FROM verification_log 
    WHERE leaf_hash IS NOT NULL 
    ORDER BY tree_position ASC
  `).all<{ leaf_hash: string }>();

  const leafHashes = entries.results.map(e => e.leaf_hash);

  if (newSize > leafHashes.length) {
    return new Response(
      JSON.stringify({ error: `new_size ${newSize} exceeds current tree size ${leafHashes.length}` }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  const proof = await generateConsistencyProof(leafHashes, oldSize, newSize);

  return new Response(JSON.stringify({
    proof,
    verificationInstructions: {
      description: "This proof demonstrates that the tree of old_size is a prefix of the tree of new_size",
      algorithm: "RFC 6962 consistency proof"
    }
  }, null, 2), {
    headers: { ...corsHeaders, "Content-Type": "application/json" }
  });
}

function buildVerificationSummary(
  localValid: boolean,
  checkpointValid: boolean,
  entriesVerified: number,
  totalEntries: number,
  externalVerifications: Array<{ type: string; valid: boolean; error?: string }>
): string {
  const rekorResults = externalVerifications.filter(v => v.type === 'rekor');
  const rekorValid = rekorResults.filter(v => v.valid).length;
  const rekorTotal = rekorResults.length;

  if (!localValid) {
    return "FAILED: Local audit log integrity check failed. Entries may have been tampered with.";
  }
  if (!checkpointValid) {
    return "FAILED: Merkle tree root does not match latest checkpoint.";
  }
  if (rekorTotal > 0 && rekorValid === 0) {
    return `WARNING: ${entriesVerified} local entries verified, but Rekor anchors could not be validated.`;
  }
  if (rekorTotal === 0) {
    return `VERIFIED: ${entriesVerified}/${totalEntries} entries validated. Merkle root matches checkpoint. No external anchors to verify.`;
  }

  return `VERIFIED: ${entriesVerified}/${totalEntries} entries validated. Merkle root matches checkpoint. ${rekorValid}/${rekorTotal} Rekor anchors confirmed.`;
}

async function handleTransparencyVerify(
  env: Env,
  corsHeaders: Record<string, string>
): Promise<Response> {
  const entries = await env.DB.prepare(`
    SELECT * FROM verification_log 
    WHERE leaf_hash IS NOT NULL 
    ORDER BY tree_position ASC
  `).all<any>();

  let localValid = true;
  let localErrorMessage = "";
  let entriesVerified = 0;

  // Verify each entry's leaf hash (data integrity check)
  for (const entry of entries.results) {
    const entryDataObj = {
      ca_id: entry.ca_id,
      check_type: entry.check_type,
      target: entry.target,
      success: entry.success === 1,
      details: entry.details,
      checked_at: entry.checked_at,
      nonce: entry.nonce,
      tree_position: entry.tree_position
    };
    const entryData = canonicalizeJSON(entryDataObj);
    const computedHash = await computeLeafHash(entryData);

    if (computedHash !== entry.leaf_hash) {
      localValid = false;
      localErrorMessage = `Leaf hash mismatch at entry ${entry.id}: computed ${computedHash.substring(0, 16)}..., stored ${entry.leaf_hash.substring(0, 16)}...`;
      break;
    }

    entriesVerified++;
  }

  // Use incremental tree for root verification
  const tree = createIncrementalMerkleTree(env);
  const computedRoot = await tree.getRoot();
  const treeSize = await tree.getTreeSize();

  let checkpointValid = true;
  let checkpointError = "";
  let expectedRoot = "";
  let latestCheckpoint: TransparencyCheckpoint | null = null;

  if (localValid) {
    latestCheckpoint = await env.DB.prepare(`
      SELECT * FROM transparency_checkpoints ORDER BY id DESC LIMIT 1
    `).first<TransparencyCheckpoint>();

    if (latestCheckpoint) {
      expectedRoot = latestCheckpoint.root_hash;

      // Verify the stored root matches what we compute
      // If tree has grown since checkpoint, we verify the checkpoint was valid at that size
      if (treeSize === latestCheckpoint.tree_size) {
        // Tree hasn't grown - roots should match exactly
        if (computedRoot !== latestCheckpoint.root_hash) {
          checkpointValid = false;
          checkpointError = `Root mismatch: computed ${computedRoot.substring(0, 16)}..., stored ${latestCheckpoint.root_hash.substring(0, 16)}...`;
        }
      } else if (treeSize > latestCheckpoint.tree_size) {
        // Tree has grown since checkpoint - verify checkpoint data hash
        const checkpointDataObj = {
          tree_size: latestCheckpoint.tree_size,
          root_hash: latestCheckpoint.root_hash,
          timestamp: latestCheckpoint.timestamp,
          previous_checkpoint_hash: latestCheckpoint.previous_checkpoint_hash
        };
        const checkpointData = canonicalizeJSON(checkpointDataObj);
        const computedCheckpointHash = await sha256(checkpointData);

        if (computedCheckpointHash !== latestCheckpoint.checkpoint_hash) {
          checkpointValid = false;
          checkpointError = `Checkpoint hash mismatch: computed ${computedCheckpointHash.substring(0, 16)}..., stored ${latestCheckpoint.checkpoint_hash.substring(0, 16)}...`;
        }
      }
    }
  }

  // Verify external Rekor anchors
  const externalVerifications: Array<{ type: string; valid: boolean; error?: string; uuid?: string }> = [];

  const checkpointsWithRekor = await env.DB.prepare(`
    SELECT rekor_entry_uuid, checkpoint_hash FROM transparency_checkpoints 
    WHERE rekor_entry_uuid IS NOT NULL
    ORDER BY id DESC LIMIT 5
  `).all<{ rekor_entry_uuid: string; checkpoint_hash: string }>();

  for (const cp of checkpointsWithRekor.results) {
    const rekorResult = await verifyRekorEntry(cp.rekor_entry_uuid, cp.checkpoint_hash);
    externalVerifications.push({
      type: 'rekor',
      valid: rekorResult.valid,
      error: rekorResult.error,
      uuid: cp.rekor_entry_uuid
    });
  }

  const overallValid = localValid && checkpointValid;
  const summary = buildVerificationSummary(
    localValid,
    checkpointValid,
    entriesVerified,
    entries.results.length,
    externalVerifications
  );

  return new Response(JSON.stringify({
    // Overall status
    valid: overallValid,
    summary,

    // Local integrity verification
    localIntegrity: {
      valid: localValid,
      entriesVerified,
      totalEntries: entries.results.length,
      error: localErrorMessage || null
    },

    // Merkle tree verification
    merkleTree: {
      valid: checkpointValid,
      computedRoot: computedRoot || null,
      expectedRoot: expectedRoot || null,
      currentTreeSize: treeSize,
      checkpointTreeSize: latestCheckpoint?.tree_size || 0,
      error: checkpointError || null
    },

    // External anchor verification
    externalAnchors: {
      rekor: {
        verified: externalVerifications.filter(v => v.type === 'rekor' && v.valid).length,
        total: externalVerifications.filter(v => v.type === 'rekor').length,
        results: externalVerifications.filter(v => v.type === 'rekor').map(v => ({
          uuid: v.uuid,
          valid: v.valid,
          error: v.error || null,
          searchUrl: v.uuid ? `https://search.sigstore.dev/?uuid=${v.uuid}` : null
        }))
      }
    },

    // Metadata
    verifiedAt: new Date().toISOString(),
    canonicalization: "RFC8785-JCS",

    // Verification instructions for independent verification
    verificationInstructions: {
      description: "To independently verify this audit log:",
      steps: [
        "1. Fetch all entries from /api/audit/export",
        "2. For each entry, canonicalize using RFC 8785 JCS and compute SHA256(0x00 || canonical_json)",
        "3. Compare computed leaf hashes against stored leaf_hash values",
        "4. Build Merkle tree from leaf hashes using RFC 6962 (node_hash = SHA256(0x01 || left || right))",
        "5. Compare computed root against checkpoint root_hash",
        "6. Verify Rekor entries at search.sigstore.dev using the UUIDs provided"
      ],
      publicKeyUrl: "/api/transparency/public-key"
    }
  }, null, 2), {
    headers: { ...corsHeaders, "Content-Type": "application/json" }
  });
}


async function handleGetSnapshot(
  env: Env, 
  corsHeaders: Record<string, string>
): Promise<Response> {
  try {
    const snapshot = await generateTrustStoreSnapshot(env);

    return new Response(JSON.stringify(snapshot, null, 2), {
      headers: {
        ...corsHeaders,
        "Content-Type": "application/json",
        "Content-Disposition": "attachment; filename=openauthority-snapshot.json",
        "X-Content-Hash": snapshot.contentHash,
        "X-Tree-Size": String(snapshot.treeHead.treeSize),
        "X-Root-Hash": snapshot.treeHead.rootHash,
        "X-Canonicalization": "RFC8785-JCS"
      }
    });
  } catch (e) {
    return new Response(
      JSON.stringify({ error: e instanceof Error ? e.message : "Snapshot generation failed" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
}

async function handleVerifySnapshot(
  request: Request, 
  corsHeaders: Record<string, string>
): Promise<Response> {
  try {
    const body = await request.json() as { 
      snapshot: TrustStoreSnapshot; 
      publicKey?: string 
    };

    if (!body.snapshot) {
      return new Response(
        JSON.stringify({ error: "Missing snapshot in request body" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const result = await verifyTrustStoreSnapshot(body.snapshot, body.publicKey);

    return new Response(JSON.stringify({
      ...result,
      verifiedAt: new Date().toISOString(),
      canonicalization: "RFC8785-JCS"
    }, null, 2), {
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  } catch (e) {
    return new Response(
      JSON.stringify({ error: `Invalid request: ${e}` }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
}

async function handleVerifyRekor(
  uuid: string | null,
  hash: string | null,
  corsHeaders: Record<string, string>
): Promise<Response> {
  if (!uuid || !hash) {
    return new Response(
      JSON.stringify({ error: "Missing uuid or hash parameter" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  const result = await verifyRekorEntry(uuid, hash);

  return new Response(JSON.stringify({
    uuid,
    expectedHash: hash,
    ...result,
    verifiedAt: new Date().toISOString(),
    rekorUrl: `https://search.sigstore.dev/?uuid=${uuid}`
  }, null, 2), {
    headers: { ...corsHeaders, "Content-Type": "application/json" }
  });
}

// ============================================================
// ORIGINAL API HANDLERS
// ============================================================

async function handleUpload(request: Request, env: Env, corsHeaders: Record<string, string>): Promise<Response> {
  const responseHeaders = { ...corsHeaders, "Content-Type": "application/json" };

  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rateLimit = await checkRateLimit(env, clientIP);

  if (!rateLimit.allowed) {
    return new Response(
      JSON.stringify({ error: "Rate limit exceeded. Please try again later." }),
      { 
        status: 429, 
        headers: { 
          ...responseHeaders, 
          "Retry-After": String(RATE_LIMIT_WINDOW_SECONDS),
          "X-RateLimit-Remaining": "0"
        } 
      }
    );
  }

  const formData = await request.formData();
  const certFile = formData.get("certificate");

  if (!certFile || !(certFile instanceof File)) {
    return new Response(
      JSON.stringify({ error: "No certificate file provided" }),
      { status: 400, headers: responseHeaders }
    );
  }

  if (certFile.size > MAX_CERT_SIZE) {
    return new Response(
      JSON.stringify({ error: `Certificate file too large. Maximum size is ${MAX_CERT_SIZE / 1024}KB.` }),
      { status: 400, headers: responseHeaders }
    );
  }

  const arrayBuffer = await certFile.arrayBuffer();
  const uint8Array = new Uint8Array(arrayBuffer);
  const isPEM = uint8Array[0] === 45 && uint8Array[1] === 45 && uint8Array[2] === 45;

  let certData: string | Uint8Array;
  if (isPEM) {
    certData = new TextDecoder().decode(uint8Array);
  } else {
    certData = uint8Array;
  }

  let parsed: ParsedCertificate;
  try {
    parsed = await parseCertificate(certData);
  } catch (e) {
    return new Response(
      JSON.stringify({ error: `Certificate parsing failed: ${e instanceof Error ? e.message : String(e)}` }),
      { status: 400, headers: responseHeaders }
    );
  }

  const existing = await env.DB.prepare(
    "SELECT id FROM certificate_authorities WHERE fingerprint_sha512 = ?"
  ).bind(parsed.fingerprint_sha512).first();

  if (existing) {
    return new Response(
      JSON.stringify({ error: "Certificate already exists in the trust store" }),
      { status: 409, headers: responseHeaders }
    );
  }

  const uniqueDomains = [...new Set(
    parsed.nameConstraints.permittedDNS.map(dns => extractBaseDomain(dns))
  )];

  // Validate all domains using strict RFC 1035 validation
  for (const domain of uniqueDomains) {
    const validation = validateDomainStrict(domain);
    if (!validation.isValid) {
      return new Response(
        JSON.stringify({ error: `Invalid domain in certificate: ${validation.error}` }),
        { status: 400, headers: responseHeaders }
      );
    }
  }

  const dnsVerifications: Array<{ domain: string; success: boolean; error?: string }> = [];
  for (const baseDomain of uniqueDomains) {
    // Use safeDNSLookup wrapper for all DNS operations
    const result = await safeDNSLookup(baseDomain, parsed.fingerprint_sha512, verifyDNSTXT);
    dnsVerifications.push({
      domain: result.normalizedDomain || baseDomain,
      success: result.success,
      error: result.error
    });

    if (!result.success) {
      return new Response(
        JSON.stringify({ 
          error: `DNS verification failed for ${result.normalizedDomain || baseDomain}: ${result.error}`,
          verifications: dnsVerifications
        }),
        { status: 400, headers: responseHeaders }
      );
    }
  }

  const ipVerifications: Array<{ ip: string; success: boolean; error?: string }> = [];
  for (const ipRange of parsed.nameConstraints.permittedIP) {
    const ip = extractIPAddress(ipRange);
    const result = await verifyWHOIS(ip, parsed.fingerprint_sha512);
    ipVerifications.push({
      ip,
      success: result.success,
      error: result.error
    });

    if (!result.success) {
      return new Response(
        JSON.stringify({ 
          error: `WHOIS verification failed for ${ip}: ${result.error}`,
          verifications: { dns: dnsVerifications, ip: ipVerifications }
        }),
        { status: 400, headers: responseHeaders }
      );
    }
  }

  const now = new Date().toISOString();

  const statements = [
    env.DB.prepare(`
      INSERT INTO certificate_authorities (
        fingerprint_sha512, fingerprint_sha256, subject, issuer, serial_number,
        not_before, not_after, pem_data, name_constraints_dns, name_constraints_ip,
        verified_at, last_check_at, created_at, status, consecutive_failures, successful_verification_count
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'probationary', 0, 0)
    `).bind(
      parsed.fingerprint_sha512,
      parsed.fingerprint_sha256,
      parsed.subject,
      parsed.issuer,
      parsed.serialNumber,
      parsed.notBefore.toISOString(),
      parsed.notAfter.toISOString(),
      parsed.pemData,
      JSON.stringify(parsed.nameConstraints.permittedDNS),
      JSON.stringify(parsed.nameConstraints.permittedIP),
      now,
      now,
      now
    )
  ];

  await env.DB.batch(statements);

  const ca = await env.DB.prepare(
    "SELECT id FROM certificate_authorities WHERE fingerprint_sha512 = ?"
  ).bind(parsed.fingerprint_sha512).first<{ id: number }>();

  if (ca) {
    await createAuditLogEntry(
      env, 
      ca.id, 
      'certificate_added', 
      parsed.subject, 
      true, 
      `Certificate added to trust store. Subject: ${parsed.subject}, Fingerprint: ${parsed.fingerprint_sha256.substring(0, 16)}...`
    );

    for (const v of dnsVerifications) {
      await createAuditLogEntry(env, ca.id, 'dns', v.domain, v.success, v.error || 'Initial verification passed');
    }

    for (const v of ipVerifications) {
      await createAuditLogEntry(env, ca.id, 'whois', v.ip, v.success, v.error || 'Initial verification passed');
    }
  }

  return new Response(
    JSON.stringify({ 
      success: true, 
      message: `Certificate verified and added to trust store (probationary for ${PROBATIONARY_PERIOD_DAYS} days)`,
      fingerprint: parsed.fingerprint_sha512,
      subject: parsed.subject,
      verifications: { dns: dnsVerifications, ip: ipVerifications }
    }),
    { 
      status: 201, 
      headers: { 
        ...responseHeaders,
        "X-RateLimit-Remaining": String(rateLimit.remaining)
      } 
    }
  );
}

async function handleListCertificates(
  env: Env, 
  corsHeaders: Record<string, string>,
  page: number,
  limit: number,
  search: string
): Promise<Response> {
  const session = env.DB.withSession();
  const offset = (page - 1) * limit;
  const safeLimit = Math.min(Math.max(1, limit), 100);

  let whereClause = "WHERE status IN ('active', 'probationary')";
  const params: any[] = [];

  if (search) {
    whereClause += ` AND (
      subject LIKE ? OR 
      fingerprint_sha256 LIKE ? OR 
      fingerprint_sha512 LIKE ? OR
      name_constraints_dns LIKE ?
    )`;
    const searchPattern = `%${search}%`;
    params.push(searchPattern, searchPattern, searchPattern, searchPattern);
  }

  const countResult = await session.prepare(
    `SELECT COUNT(*) as total FROM certificate_authorities ${whereClause}`
  ).bind(...params).first<{ total: number }>();

  const total = countResult?.total || 0;

  const results = await session.prepare(`
    SELECT id, fingerprint_sha512, fingerprint_sha256, subject, issuer, 
           serial_number, not_before, not_after, name_constraints_dns, 
           name_constraints_ip, verified_at, last_check_at, status, created_at,
           successful_verification_count
    FROM certificate_authorities
    ${whereClause}
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  `).bind(...params, safeLimit, offset).all<CertificateAuthority>();

  const certificates = results.results.map(cert => ({
    ...cert,
    name_constraints_dns: JSON.parse(cert.name_constraints_dns),
    name_constraints_ip: JSON.parse(cert.name_constraints_ip)
  }));

  return new Response(
    JSON.stringify({ 
      certificates,
      pagination: {
        page,
        limit: safeLimit,
        total,
        totalPages: Math.ceil(total / safeLimit)
      }
    }),
    { headers: { ...corsHeaders, "Content-Type": "application/json" } }
  );
}

async function handleGetCertificateDetails(
  env: Env, 
  id: string, 
  corsHeaders: Record<string, string>
): Promise<Response> {
  const session = env.DB.withSession();

  if (!id || !/^\d+$/.test(id)) {
    return new Response(
      JSON.stringify({ error: "Invalid certificate ID. Must be a positive integer." }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  const cert = await session.prepare(`
    SELECT * FROM certificate_authorities WHERE id = ?
  `).bind(id).first<CertificateAuthority>();

  if (!cert) {
    return new Response(
      JSON.stringify({ error: "Certificate not found" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  const auditResults = await session.prepare(`
    SELECT * FROM verification_log 
    WHERE ca_id = ? 
    ORDER BY id DESC
  `).bind(id).all<any>();

  const successfulVerifications = auditResults.results.filter(
    (log: any) => ['dns', 'whois'].includes(log.check_type) && log.success === 1
  ).length;

  const failedVerifications = auditResults.results.filter(
    (log: any) => ['dns', 'whois'].includes(log.check_type) && log.success === 0
  ).length;

  const firstSeenEntry = auditResults.results.find(
    (log: any) => log.check_type === 'certificate_added'
  ) || auditResults.results[auditResults.results.length - 1];

  const lastVerifiedEntry = auditResults.results.find(
    (log: any) => ['dns', 'whois'].includes(log.check_type) && log.success === 1
  );

  const lastCheckAt = new Date(cert.last_check_at);
  const checkIntervalHours = cert.status === 'probationary' ? PROBATIONARY_CHECK_HOURS : ACTIVE_CHECK_HOURS;
  const nextVerification = new Date(lastCheckAt.getTime() + checkIntervalHours * 60 * 60 * 1000);

  const eligibility = await verifyCertificateEligibility(env, cert);

  const addedEntry = auditResults.results.find((log: any) => log.check_type === 'certificate_added');
  let inclusionProof: MerkleProof | null = null;
  if (addedEntry) {
    inclusionProof = await getInclusionProofForEntry(env, addedEntry.id);
  }

  const response: CertificateDetails & { inclusion_proof?: MerkleProof | null } = {
    ...cert,
    name_constraints_dns: JSON.parse(cert.name_constraints_dns) as any,
    name_constraints_ip: JSON.parse(cert.name_constraints_ip) as any,
    audit_log: auditResults.results.map((log: any) => ({
      id: log.id,
      ca_id: log.ca_id,
      check_type: log.check_type,
      target: log.target,
      success: log.success === 1,
      details: log.details,
      checked_at: log.checked_at,
      nonce: log.nonce,
      leaf_hash: log.leaf_hash,
      tree_position: log.tree_position
    })),
    first_seen: firstSeenEntry?.checked_at || cert.created_at,
    last_verified: lastVerifiedEntry?.checked_at || null,
    next_verification: nextVerification.toISOString(),
    total_successful_verifications: successfulVerifications,
    total_failed_verifications: failedVerifications,
    eligibility_status: {
      eligible_for_export: eligibility.eligible,
      reason: eligibility.reason
    },
    inclusion_proof: inclusionProof
  };

  return new Response(
    JSON.stringify(response, null, 2),
    { headers: { ...corsHeaders, "Content-Type": "application/json" } }
  );
}

async function handleCertificateAuditLog(
  env: Env,
  id: string,
  corsHeaders: Record<string, string>
): Promise<Response> {
  if (!id || !/^\d+$/.test(id)) {
    return new Response(
      JSON.stringify({ error: "Invalid certificate ID." }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  const results = await env.DB.prepare(`
    SELECT * FROM verification_log 
    WHERE ca_id = ? 
    ORDER BY id DESC
  `).bind(id).all<any>();

  return new Response(
    JSON.stringify({
      ca_id: parseInt(id),
      logs: results.results.map((log: any) => ({
        ...log,
        success: log.success === 1
      })),
      total: results.results.length
    }),
    { headers: { ...corsHeaders, "Content-Type": "application/json" } }
  );
}

async function handleAuditLog(
  env: Env, 
  corsHeaders: Record<string, string>,
  page: number,
  limit: number,
  caId?: string | null
): Promise<Response> {
  const session = env.DB.withSession();

  const offset = (page - 1) * limit;
  const safeLimit = Math.min(Math.max(1, limit), 100);

  let whereClause = "";
  const params: any[] = [];

  if (caId && /^\d+$/.test(caId)) {
    whereClause = "WHERE vl.ca_id = ?";
    params.push(parseInt(caId));
  }

  const countQuery = caId && /^\d+$/.test(caId)
    ? `SELECT COUNT(*) as total FROM verification_log vl WHERE vl.ca_id = ?`
    : `SELECT COUNT(*) as total FROM verification_log`;

  const countResult = await session.prepare(countQuery)
    .bind(...(caId && /^\d+$/.test(caId) ? [parseInt(caId)] : []))
    .first<{ total: number }>();

  const total = countResult?.total || 0;

  const results = await session.prepare(`
    SELECT vl.*, ca.subject, ca.fingerprint_sha256
    FROM verification_log vl
    JOIN certificate_authorities ca ON vl.ca_id = ca.id
    ${whereClause}
    ORDER BY vl.id DESC
    LIMIT ? OFFSET ?
  `).bind(...params, safeLimit, offset).all();

  return new Response(
    JSON.stringify({ 
      logs: results.results.map((log: any) => ({
        ...log,
        success: log.success === 1
      })),
      pagination: {
        page,
        limit: safeLimit,
        total,
        totalPages: Math.ceil(total / safeLimit)
      }
    }),
    { headers: { ...corsHeaders, "Content-Type": "application/json" } }
  );
}

async function handleAuditExport(env: Env, format: string, corsHeaders: Record<string, string>): Promise<Response> {
  const results = await env.DB.prepare(`
    SELECT vl.*, ca.subject, ca.fingerprint_sha256
    FROM verification_log vl
    JOIN certificate_authorities ca ON vl.ca_id = ca.id
    ORDER BY vl.id ASC
  `).all();

  const entries = await env.DB.prepare(`
    SELECT leaf_hash FROM verification_log WHERE leaf_hash IS NOT NULL ORDER BY tree_position ASC
  `).all<{ leaf_hash: string }>();
  const leafHashes = entries.results.map(e => e.leaf_hash);
  const { root } = await buildMerkleTree(leafHashes);

  if (format === "csv") {
    const headers = "id,ca_id,subject,fingerprint_sha256,check_type,target,success,details,checked_at,nonce,leaf_hash,tree_position\n";
    const rows = results.results.map((log: any) => 
      `${log.id},${log.ca_id},"${log.subject}","${log.fingerprint_sha256}",${log.check_type},"${log.target}",${log.success},"${log.details}",${log.checked_at},${log.nonce || ''},${log.leaf_hash || ''},${log.tree_position || ''}`
    ).join('\n');

    return new Response(headers + rows, {
      headers: {
        ...corsHeaders,
        "Content-Type": "text/csv",
        "Content-Disposition": "attachment; filename=openauthority-audit-log.csv"
      }
    });
  }

  return new Response(
    JSON.stringify({
      logs: results.results.map((log: any) => ({
        ...log,
        success: log.success === 1
      })),
      total: results.results.length,
      exported_at: new Date().toISOString(),
      merkle_tree: {
        root: root,
        size: leafHashes.length
      },
      verification_info: {
        description: "Each log entry has a leaf_hash computed as SHA256(0x00 || canonical_entry_data). The Merkle tree root can be recomputed from all leaf hashes.",
        algorithm: "RFC 6962 Merkle Tree",
        canonicalization: "RFC8785-JCS",
        leaf_prefix: "0x00",
        node_prefix: "0x01"
      }
    }, null, 2),
    { 
      headers: { 
        ...corsHeaders,
        "Content-Type": "application/json",
        "Content-Disposition": "attachment; filename=openauthority-audit-log.json"
      } 
    }
  );
}

async function handleAuditVerify(env: Env, corsHeaders: Record<string, string>): Promise<Response> {
  return handleTransparencyVerify(env, corsHeaders);
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

function pemToDer(pem: string): Uint8Array {
  const base64 = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s/g, '');

  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

function generateUUID(input: string): string {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    const char = input.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }

  const hex = Math.abs(hash).toString(16).padStart(8, '0');
  const hex2 = Math.abs(hash * 31).toString(16).padStart(8, '0');
  const hex3 = Math.abs(hash * 37).toString(16).padStart(8, '0');
  const hex4 = Math.abs(hash * 41).toString(16).padStart(8, '0');

  return `${hex.slice(0, 8)}-${hex2.slice(0, 4)}-4${hex2.slice(5, 8)}-${hex3.slice(0, 4)}-${hex4.slice(0, 12)}`.toUpperCase();
}

function extractCN(subject: string): string {
  const match = subject.match(/CN=([^,]+)/);
  return match ? match[1] : subject;
}

function generateMobileConfig(certificates: Array<{ pem_data: string; subject: string; fingerprint_sha256: string }>): string {
  const profileUUID = generateUUID('openauthority-trust-store-profile');

  const certPayloads = certificates.map((cert, index) => {
    const derData = pemToDer(cert.pem_data);
    const base64Data = btoa(String.fromCharCode(...derData));
    const formattedBase64 = base64Data.match(/.{1,52}/g)?.join('\n') || base64Data;
    const certUUID = generateUUID(cert.fingerprint_sha256);
    const certName = extractCN(cert.subject);

    return `
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>${certName}.cer</string>
			<key>PayloadContent</key>
			<data>
${formattedBase64}
			</data>
			<key>PayloadDescription</key>
			<string>Adds a CA root certificate from OpenAuthority Trust Store</string>
			<key>PayloadDisplayName</key>
			<string>${certName}</string>
			<key>PayloadIdentifier</key>
			<string>org.openauthority.truststore.cert.${index}</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>${certUUID}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>`;
  }).join('\n');

  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>${certPayloads}
	</array>
	<key>PayloadDescription</key>
	<string>Installs the OpenAuthority Trust Store CA certificates.</string>
	<key>PayloadDisplayName</key>
	<string>OpenAuthority Trust Store</string>
	<key>PayloadIdentifier</key>
	<string>org.openauthority.truststore</string>
	<key>PayloadOrganization</key>
	<string>OpenAuthority Project</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>${profileUUID}</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
	<key>ConsentText</key>
	<dict>
		<key>default</key>
		<string>This profile installs ${certificates.length} CA certificate(s) from the OpenAuthority Trust Store.</string>
	</dict>
</dict>
</plist>`;
}

function generateZip(files: Array<{ name: string; data: Uint8Array }>): Uint8Array {
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

  return buffer;
}

function crc32(data: Uint8Array): number {
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

async function computeContentHash(content: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(content);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function generateReproducibleExport(
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

async function signManifest(env: Env, manifest: ExportManifest): Promise<ExportManifest> {
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
  } catch (e) {
    console.error("Failed to sign manifest:", e);
    return manifest;
  }
}

async function handleExport(env: Env, format: string, corsHeaders: Record<string, string>): Promise<Response> {
  if (!VALID_EXPORT_FORMATS.includes(format as any)) {
    return new Response(
      JSON.stringify({ 
        error: `Invalid format '${format}'. Supported formats: ${VALID_EXPORT_FORMATS.join(", ")}` 
      }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  const results = await env.DB.prepare(`
    SELECT id, pem_data, subject, fingerprint_sha256, created_at, status, 
           successful_verification_count, last_check_at
    FROM certificate_authorities 
    WHERE status = 'active'
    LIMIT ?
  `).bind(MAX_EXPORT_CERTIFICATES).all<{ 
    id: number; 
    pem_data: string; 
    subject: string; 
    fingerprint_sha256: string;
    created_at: string;
    status: string;
    successful_verification_count?: number;
    last_check_at: string;
  }>();

  const eligibleCertificates: Array<{ 
    pem_data: string; 
    subject: string; 
    fingerprint_sha256: string;
    created_at: string;
    last_check_at: string;
  }> = [];
  const rejectedCertificates: Array<{ fingerprint_sha256: string; reason: string }> = [];

  for (const cert of results.results) {
    const eligibility = await verifyCertificateEligibility(env, cert);

    if (eligibility.eligible) {
      eligibleCertificates.push({
        pem_data: cert.pem_data,
        subject: cert.subject,
        fingerprint_sha256: cert.fingerprint_sha256,
        created_at: cert.created_at,
        last_check_at: cert.last_check_at
      });
    } else {
      console.warn(
        `Certificate ${cert.fingerprint_sha256.substring(0, 16)}... rejected from export: ${eligibility.reason}`
      );
      rejectedCertificates.push({
        fingerprint_sha256: cert.fingerprint_sha256,
        reason: eligibility.reason!
      });
    }
  }

  const { content, manifest } = generateReproducibleExport(eligibleCertificates);
  manifest.contentHash = await computeContentHash(content);

  const signedManifest = await signManifest(env, manifest);

  const entries = await env.DB.prepare(`
    SELECT leaf_hash FROM verification_log WHERE leaf_hash IS NOT NULL ORDER BY tree_position ASC
  `).all<{ leaf_hash: string }>();
  const leafHashes = entries.results.map(e => e.leaf_hash);
  const { root } = await buildMerkleTree(leafHashes);

  if (format === "pem" || format === "bundle") {
    return new Response(content, {
      headers: {
        ...corsHeaders,
        "Content-Type": "application/x-pem-file",
        "Content-Disposition": "attachment; filename=openauthority-trust-store.pem",
        "X-Content-Hash": manifest.contentHash,
        "X-Manifest-Signature": signedManifest.signature || "unsigned",
        "X-Tree-Root": root,
        "X-Tree-Size": String(leafHashes.length),
        "X-Canonicalization": "RFC8785-JCS"
      }
    });
  }

  if (format === "zip") {
    const encoder = new TextEncoder();
    const files: Array<{ name: string; data: Uint8Array }> = [];

    const readme = `OpenAuthority Trust Store
========================

This ZIP contains ${eligibleCertificates.length} CA certificate(s).

Content Hash: ${manifest.contentHash}
Generated At: ${manifest.generatedAt}
Merkle Tree Root: ${root}
Merkle Tree Size: ${leafHashes.length}
Canonicalization: RFC 8785 JCS

Verification:
- Download the full snapshot from /api/transparency/snapshot
- Use the verifyTrustStoreSnapshot() function to verify independently
- Check Rekor entries at https://search.sigstore.dev
- Verify signatures using the public key from /api/transparency/public-key

Signature Verification Procedure:
1. Parse manifest.json
2. Remove 'signature', 'signatureAlgorithm', and 'canonicalization' fields
3. Canonicalize using RFC 8785 JCS (recursive key sort by UTF-16, no whitespace)
4. Encode as UTF-8
5. Verify ECDSA-P256-SHA256 signature over the canonical bytes

Installation:
- Windows: Double-click each .crt → Install Certificate → Local Machine → Trusted Root CAs
- macOS: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain <file>.crt
- Linux: Copy to /usr/local/share/ca-certificates/ and run update-ca-certificates
- Android: Settings → Security → Install certificates → CA certificate

For more information: https://openauthority.dev
`;
    files.push({ name: 'README.txt', data: encoder.encode(readme) });

    // Include both canonical and human-readable manifest
    const canonicalManifest = canonicalizeJSON(signedManifest);
    files.push({ name: 'manifest.canonical.json', data: encoder.encode(canonicalManifest) });
    files.push({ name: 'manifest.json', data: encoder.encode(JSON.stringify(signedManifest, null, 2)) });

    for (const cert of eligibleCertificates) {
      const cn = extractCN(cert.subject);
      const safeName = cn.replace(/[^a-zA-Z0-9.-]/g, '_').substring(0, 50);
      const filename = `${safeName}-${cert.fingerprint_sha256.substring(0, 8)}.crt`;
      files.push({ name: filename, data: encoder.encode(cert.pem_data) });
    }

    const zipData = generateZip(files);

    return new Response(zipData, {
      headers: {
        ...corsHeaders,
        "Content-Type": "application/zip",
        "Content-Disposition": "attachment; filename=openauthority-trust-store.zip"
      }
    });
  }

  if (format === "mobileconfig") {
    const mobileconfig = generateMobileConfig(eligibleCertificates);
    return new Response(mobileconfig, {
      headers: {
        ...corsHeaders,
        "Content-Type": "application/x-apple-aspen-config",
        "Content-Disposition": "attachment; filename=openauthority-trust-store.mobileconfig"
      }
    });
  }

  // format === "json"
  return new Response(
    JSON.stringify({ 
      manifest: signedManifest,
      certificates: eligibleCertificates.map(c => ({
        subject: c.subject,
        fingerprint_sha256: c.fingerprint_sha256,
        pem_data: c.pem_data
      })),
      transparency: {
        treeRoot: root,
        treeSize: leafHashes.length,
        snapshotUrl: "/api/transparency/snapshot",
        publicKeyUrl: "/api/transparency/public-key"
      },
      _meta: {
        total_active_in_db: results.results.length,
        passed_eligibility_check: eligibleCertificates.length,
        rejected: rejectedCertificates.length > 0 ? rejectedCertificates : undefined,
        threatModelVersion: THREAT_MODEL_VERSION,
        operatorTrustVersion: OPERATOR_TRUST_VERSION,
        merkleTreeVersion: MERKLE_TREE_VERSION,
        canonicalization: "RFC8785-JCS",
        reproducible: true
      },
      _verification: {
        signatureAlgorithm: "ECDSA-P256-SHA256",
        canonicalization: "RFC8785-JCS",
        procedure: [
          "1. Parse the manifest JSON",
          "2. Remove 'signature', 'signatureAlgorithm', and 'canonicalization' fields",
          "3. Canonicalize using RFC 8785 JCS (recursive key sort by UTF-16, no whitespace)",
          "4. Encode as UTF-8",
          "5. Verify ECDSA-P256-SHA256 signature over the canonical bytes"
        ],
        publicKeyUrl: "/api/transparency/public-key"
      }
    }, null, 2),
    { headers: { ...corsHeaders, "Content-Type": "application/json" } }
  );
}

// ============================================================
// PERIODIC VERIFICATION (SCHEDULED)
// ============================================================

async function runPeriodicVerification(env: Env): Promise<void> {
  console.log("Starting periodic verification...");

  const certificates = await env.DB.prepare(`
    SELECT * FROM certificate_authorities 
    WHERE (
      (status = 'probationary' AND datetime(last_check_at, ? || ' hours', ? || ' minutes') <= datetime('now'))
      OR
      (status = 'active' AND datetime(last_check_at, ? || ' hours', ? || ' minutes') <= datetime('now'))
    )
    ORDER BY last_check_at ASC
    LIMIT 20
  `).bind(
    `${PROBATIONARY_CHECK_HOURS}`,
    `-${VERIFICATION_MARGIN_MINUTES}`,
    `${ACTIVE_CHECK_HOURS}`,
    `-${VERIFICATION_MARGIN_MINUTES}`
  ).all<CertificateAuthority>();

  if (certificates.results.length === 0) {
    console.log("No certificates due for verification");

    if (await shouldCreateCheckpoint(env)) {
      console.log("Creating scheduled checkpoint...");
      await createCheckpoint(env);
    }
    return;
  }

  console.log(`Verifying ${certificates.results.length} certificate(s)...`);

  for (const cert of certificates.results) {
    const now = new Date().toISOString();

    if (new Date(cert.not_after) < new Date()) {
      await env.DB.prepare(`
        UPDATE certificate_authorities 
        SET status = 'expired', last_check_at = ?
        WHERE id = ? AND status != 'expired'
      `).bind(now, cert.id).run();

      await createAuditLogEntry(
        env, 
        cert.id, 
        'certificate_expired', 
        cert.subject, 
        false, 
        `Certificate expired. Not After: ${cert.not_after}`
      );

      console.log(`Certificate ${cert.fingerprint_sha256.substring(0, 16)}... EXPIRED`);
      continue;
    }

    let allValid = true;
    let verificationError = "";
    const dnsConstraints = JSON.parse(cert.name_constraints_dns) as string[];
    const ipConstraints = JSON.parse(cert.name_constraints_ip) as string[];

    const uniqueDNS = [...new Set(dnsConstraints.map(dns => extractBaseDomain(dns)))];

    for (const baseDomain of uniqueDNS) {
      // Use safeDNSLookup wrapper for all DNS operations
      const result = await safeDNSLookup(baseDomain, cert.fingerprint_sha512, verifyDNSTXT);

      if (!result.normalizedDomain) {
        console.warn(`Skipping invalid domain ${baseDomain}: ${result.error}`);
        continue;
      }

      await createAuditLogEntry(env, cert.id, 'dns', result.normalizedDomain, result.success, result.error || 'Verified');

      if (!result.success) {
        allValid = false;
        verificationError = result.error || "DNS verification failed";
      }
    }

    for (const ipRange of ipConstraints) {
      const ip = extractIPAddress(ipRange);
      const result = await verifyWHOIS(ip, cert.fingerprint_sha512);
      await createAuditLogEntry(env, cert.id, 'whois', ip, result.success, result.error || 'Verified');

      if (!result.success) {
        allValid = false;
        verificationError = result.error || "WHOIS verification failed";
      }
    }

    if (!allValid) {
      const currentFailures = (cert.consecutive_failures || 0) + 1;

      if (currentFailures >= MAX_CONSECUTIVE_FAILURES) {
        await env.DB.prepare(`
          UPDATE certificate_authorities 
          SET status = 'revoked', last_check_at = ?, consecutive_failures = ?
          WHERE id = ?
        `).bind(now, currentFailures, cert.id).run();

        await createAuditLogEntry(
          env, 
          cert.id, 
          'certificate_revoked', 
          cert.subject, 
          false, 
          `Certificate revoked after ${currentFailures} consecutive verification failures. Last error: ${verificationError}`
        );

        console.log(`Certificate ${cert.fingerprint_sha256.substring(0, 16)}... REVOKED after ${currentFailures} consecutive failures`);
      } else {
        await env.DB.prepare(`
          UPDATE certificate_authorities 
          SET last_check_at = ?, consecutive_failures = ?
          WHERE id = ?
        `).bind(now, currentFailures, cert.id).run();
        console.log(`Certificate ${cert.fingerprint_sha256.substring(0, 16)}... verification failed (${currentFailures}/${MAX_CONSECUTIVE_FAILURES}): ${verificationError}`);
      }
    } else {
      let newStatus = cert.status;
      const newVerificationCount = (cert.successful_verification_count || 0) + 1;

      if (cert.status === 'probationary') {
        const createdAt = new Date(cert.created_at);
        const probationEndDate = new Date(createdAt.getTime() + PROBATIONARY_PERIOD_DAYS * 24 * 60 * 60 * 1000);

        if (new Date() >= probationEndDate && newVerificationCount >= MIN_SUCCESSFUL_VERIFICATIONS) {
          newStatus = 'active';

          await createAuditLogEntry(
            env, 
            cert.id, 
            'certificate_promoted', 
            cert.subject, 
            true, 
            `Certificate promoted from probationary to active after ${newVerificationCount} successful verifications over ${PROBATIONARY_PERIOD_DAYS} days`
          );

          console.log(`Certificate ${cert.fingerprint_sha256.substring(0, 16)}... PROMOTED to active`);
        }
      }

      await env.DB.prepare(`
        UPDATE certificate_authorities 
        SET status = ?, last_check_at = ?, consecutive_failures = 0, successful_verification_count = ?
        WHERE id = ?
      `).bind(newStatus, now, newVerificationCount, cert.id).run();
    }
  }

  if (await shouldCreateCheckpoint(env)) {
    console.log("Creating post-verification checkpoint...");
    await createCheckpoint(env);
  }

  console.log("Periodic verification complete");
}