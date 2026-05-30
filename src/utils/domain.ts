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

import { ValidatedDomain } from "../merkle";
import { DNS_MAX_LABEL_LENGTH, DNS_MAX_NAME_LENGTH } from "../config/constants";

// ============================================================
// DNS VALIDATION MODULE (RFC 1035 Compliant)
// ============================================================

export function validateDomainStrict(domain: string): ValidatedDomain {
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

export function requireValidDomain(domain: string): string {
  const validation = validateDomainStrict(domain);
  if (!validation.isValid) {
    throw new Error(`DNS validation failed: ${validation.error}`);
  }
  return validation.normalized;
}