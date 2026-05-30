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

import { MAX_RECURSION_DEPTH } from "../config/constants";

// ============================================================
// RFC 8785 JSON CANONICALIZATION SCHEME (JCS)
// ============================================================

export function canonicalizeJSON(value: unknown, depth: number = 0): string {
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

export function stringToUTF16CodeUnits(str: string): number[] {
  const units: number[] = [];
  for (let i = 0; i < str.length; i++) {
    units.push(str.charCodeAt(i));
  }
  return units;
}

export function canonicalizeString(str: string): string {
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