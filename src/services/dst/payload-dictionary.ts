/**
 * DST Payload Dictionary -- Static data for the reverse mapper.
 *
 * This module contains:
 * - Sink subtype -> payload class mapping (SINK_CLASS_MAP)
 * - CWE -> payload class inference (for fallback when sink lookup fails)
 * - Payload templates per class (SQL injection MVP, stubs for future classes)
 * - Transform effect classification map
 * - Safe command allowlist for command injection proofs
 *
 * This is DATA, not logic. Adding a CWE is adding a line.
 */

import type { NeuralMapNode } from './types';

// ---------------------------------------------------------------------------
// Payload class -- what family of payload to generate
// ---------------------------------------------------------------------------

export type PayloadClass =
  | 'sql_injection'
  | 'command_injection'
  | 'xss'
  | 'path_traversal'
  | 'ldap_injection'
  | 'xpath_injection'
  | 'xxe'
  | 'deserialization'
  | 'open_redirect'
  | 'log_injection'
  | 'ssti';

// ---------------------------------------------------------------------------
// Sink subtype -> payload class mapping
// ---------------------------------------------------------------------------

export const SINK_CLASS_MAP: Record<string, PayloadClass> = {
  // SQL Injection
  'db_read': 'sql_injection',
  'db_write': 'sql_injection',
  'db_stored_proc': 'sql_injection',
  'sql_query': 'sql_injection',
  // Command Injection
  'system_exec': 'command_injection',
  // XSS
  'http_response': 'xss',
  // Open Redirect
  'redirect': 'open_redirect',
  // LDAP Injection
  'ldap_query': 'ldap_injection',
  // XPath Injection
  'xpath_query': 'xpath_injection',
  // XXE
  'xml_parse': 'xxe',
  // Path Traversal
  'file_read': 'path_traversal',
  'file_write': 'path_traversal',
  'file_access': 'path_traversal',
  // Deserialization
  'deserialize': 'deserialization',
  'deserialize_rce': 'deserialization',
  // Log Injection
  'log_write': 'log_injection',
  // SSTI
  'template_render': 'ssti',
};

/**
 * Resolve a sink's node_subtype to a payload class.
 * Uses exact match first, then fuzzy `.includes()` fallback.
 */
export function resolveSinkClass(subtype: string): PayloadClass | null {
  // Exact match
  const exact = SINK_CLASS_MAP[subtype];
  if (exact) return exact;

  // Fuzzy fallback -- check if any known key is contained in the subtype
  for (const [key, cls] of Object.entries(SINK_CLASS_MAP)) {
    if (subtype.includes(key) || key.includes(subtype)) {
      return cls;
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// CWE -> payload class inference (fallback for synthetic findings)
// ---------------------------------------------------------------------------

const CWE_TO_PAYLOAD_CLASS: Record<string, PayloadClass> = {
  'CWE-89': 'sql_injection',
  'CWE-564': 'sql_injection',
  'CWE-78': 'command_injection',
  'CWE-77': 'command_injection',
  'CWE-79': 'xss',
  'CWE-22': 'path_traversal',
  'CWE-23': 'path_traversal',
  'CWE-36': 'path_traversal',
  'CWE-90': 'ldap_injection',
  'CWE-643': 'xpath_injection',
  'CWE-611': 'xxe',
  'CWE-918': 'open_redirect',
  'CWE-601': 'open_redirect',
  'CWE-502': 'deserialization',
  'CWE-117': 'log_injection',
  'CWE-1336': 'ssti',
};

export function inferPayloadClassFromCWE(cwe: string): PayloadClass | null {
  return CWE_TO_PAYLOAD_CLASS[cwe] ?? null;
}

// ---------------------------------------------------------------------------
// SQL Injection payloads
// ---------------------------------------------------------------------------

export interface ProofPayloadTemplate {
  value: string;
  canary: string;
  context: string;
  execution_safe: boolean;
}

export const SQL_INJECTION_PAYLOADS: Record<string, ProofPayloadTemplate> = {
  // String context (single-quote delimited)
  sql_string_tautology: {
    value: "' OR '1'='1",
    canary: '1',
    context: 'sql_string',
    execution_safe: true,
  },
  sql_string_union_canary: {
    value: "' UNION SELECT 'DST_CANARY_SQLI' --",
    canary: 'DST_CANARY_SQLI',
    context: 'sql_string',
    execution_safe: true,
  },
  sql_string_error: {
    value: "' AND 1=CONVERT(int,'DST_CANARY') --",
    canary: 'DST_CANARY',
    context: 'sql_string',
    execution_safe: true,
  },
  // Numeric context (no quotes)
  sql_numeric_tautology: {
    value: '1 OR 1=1',
    canary: '1',
    context: 'sql_numeric',
    execution_safe: true,
  },
  sql_numeric_union_canary: {
    value: "1 UNION SELECT 'DST_CANARY_SQLI' --",
    canary: 'DST_CANARY_SQLI',
    context: 'sql_numeric',
    execution_safe: true,
  },
  // Time-based blind -- CRITICAL FIX #3: execution_safe = false
  sql_time_mysql: {
    value: "' OR SLEEP(2) -- -",
    canary: '',
    context: 'sql_string',
    execution_safe: false,  // SLEEP can DOS connection pools
  },
  sql_time_postgres: {
    value: "'; SELECT pg_sleep(2) --",
    canary: '',
    context: 'sql_string',
    execution_safe: false,
  },
  sql_time_mssql: {
    value: "'; WAITFOR DELAY '00:00:02' --",
    canary: '',
    context: 'sql_string',
    execution_safe: false,
  },
};

// ---------------------------------------------------------------------------
// Transform effects -- what a TRANSFORM node does to a payload in transit
// ---------------------------------------------------------------------------

export interface TransformEffect {
  effect: 'encoding' | 'type_coercion' | 'destruction' | 'format_constraint'
        | 'path_normalization' | 'xml_processing' | 'none' | 'unknown';
  payload_action: 'encode_before_delivery' | 'check_if_numeric_only'
                | 'payload_blocked' | 'embed_in_format' | 'check_traversal_survival'
                | 'embed_in_xml' | 'pass_through' | 'flag_uncertain';
}

export const TRANSFORM_EFFECTS: Record<string, TransformEffect> = {
  'codec':        { effect: 'encoding',           payload_action: 'encode_before_delivery' },
  'format':       { effect: 'type_coercion',      payload_action: 'check_if_numeric_only' },
  'encrypt':      { effect: 'destruction',         payload_action: 'payload_blocked' },
  'parse':        { effect: 'format_constraint',   payload_action: 'embed_in_format' },
  'path_resolve': { effect: 'path_normalization',  payload_action: 'check_traversal_survival' },
  'alloc':        { effect: 'none',                payload_action: 'pass_through' },
  'xml_parse':    { effect: 'xml_processing',      payload_action: 'embed_in_xml' },
  'prng_weak':    { effect: 'none',                payload_action: 'pass_through' },
};

/**
 * Classify what a TRANSFORM node does to a payload.
 * Primary: subtype-based. Fallback: code_snapshot regex.
 *
 * CRITICAL FIX #2: `sanitize` maps to DESTRUCTION, not encoding.
 * HtmlUtils.htmlEscape DESTROYS payloads.
 */
export function classifyTransform(node: NeuralMapNode): TransformEffect {
  // Primary: subtype-based classification
  const effect = TRANSFORM_EFFECTS[node.node_subtype];
  if (effect) return effect;

  // Fallback: code_snapshot analysis
  const snap = node.analysis_snapshot || node.code_snapshot;

  // FIX #2: sanitize/escape = destruction. These DESTROY the payload.
  if (/\b(sanitize|htmlEscape|escapeHtml|encodeForHTML|xssFilter|DOMPurify|bleach)\b/i.test(snap)) {
    return { effect: 'destruction', payload_action: 'payload_blocked' };
  }
  // General encoding (URL, Base64) -- payload survives but must be pre-encoded
  if (/\b(encode|encodeURI|encodeURIComponent|URLEncoder|Base64)\b/i.test(snap)) {
    return { effect: 'encoding', payload_action: 'encode_before_delivery' };
  }
  if (/\b(parseInt|parseLong|parseDouble|parseFloat|Number\(|int\(|float\()\b/.test(snap)) {
    return { effect: 'type_coercion', payload_action: 'check_if_numeric_only' };
  }
  if (/\b(hash|digest|encrypt|cipher)\b/i.test(snap)) {
    return { effect: 'destruction', payload_action: 'payload_blocked' };
  }

  // Unknown transform
  return { effect: 'unknown', payload_action: 'flag_uncertain' };
}

// ---------------------------------------------------------------------------
// Safe command allowlist (for command injection proofs)
// ---------------------------------------------------------------------------

export const SAFE_COMMANDS = [
  'echo DST_CMDI_PROOF',
  'printf DST_CMDI_PROOF',
  'id',
  'whoami',
  'hostname',
  'uname -a',
  'ver',
];

// ---------------------------------------------------------------------------
// Safety validation constants
// ---------------------------------------------------------------------------

export const SQL_DESTRUCTIVE = /\b(DROP|DELETE|TRUNCATE|ALTER|CREATE|INSERT|UPDATE|GRANT|REVOKE|EXEC)\b/i;
export const SQL_READ_ONLY = /\b(SELECT|OR|AND|UNION|SLEEP|WAITFOR|pg_sleep|CONVERT)\b/i;
