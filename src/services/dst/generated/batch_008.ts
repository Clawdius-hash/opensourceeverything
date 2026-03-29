/**
 * DST Generated Verifiers — Batch 008
 * Pattern shape: INGRESS→EGRESS without CONTROL
 * 17 CWEs: incomplete filtering, validation order, crypto strength,
 * session exposure, credential transport, network amplification.
 *
 * Sub-groups:
 *   A. Incomplete filtering    (8 CWEs) — factory-driven (CWE-790 through 797)
 *   B. Individual patterns     (9 CWEs) — per-CWE
 */

import type { NeuralMap, NeuralMapNode } from '../types';
import {
  nodeRef, nodesOfType, hasTaintedPathWithoutControl, createGenericVerifier,
  type VerificationResult, type Finding, type Severity,
} from './_helpers';

// ---------------------------------------------------------------------------
// Sink filters
// ---------------------------------------------------------------------------

function egressNodes(map: NeuralMap): NeuralMapNode[] {
  return nodesOfType(map, 'EGRESS');
}

// ---------------------------------------------------------------------------
// Safe patterns
// ---------------------------------------------------------------------------

const FILTER_COMPLETE_SAFE = /\breplaceAll\b|\bglobal\b.*\breplace\b|\b\/g\b|\bsanitize\b|\bescape\b|\bDOMPurify\b|\bencode\b|\bfilterAll\b/i;
const CRYPTO_STRENGTH_SAFE = /\bAES-256\b|\bRSA-2048\b|\bRSA-4096\b|\bcurve25519\b|\bP-256\b|\bstrong\b.*\bcipher\b|\bTLS\s*1\.[23]\b/i;
const SESSION_SAFE = /\bsession\b.*\bisolat\b|\buser\b.*\bcontext\b|\bscoped\b|\brbac\b|\bcheck.*session\b/i;
const TRANSPORT_SAFE = /\bhttps\b|\bTLS\b|\bSSL\b|\bSecure\b|\bencrypt\b|\bHSTS\b/i;
const METHOD_SAFE = /\bPOST\b|\bmethod\s*:\s*['"]POST['"]|\bmethod.*enforce\b|\bredirect.*POST\b/i;

// ---------------------------------------------------------------------------
// Factory: Incomplete filtering (CWE-790 through 797)
// ---------------------------------------------------------------------------

function createFilteringVerifier(
  cweId: string, cweName: string, severity: Severity,
): (map: NeuralMap) => VerificationResult {
  return (map: NeuralMap): VerificationResult => {
    const findings: Finding[] = [];
    const ingress = nodesOfType(map, 'INGRESS');
    const sinks = egressNodes(map);

    for (const src of ingress) {
      for (const sink of sinks) {
        if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
          if (!FILTER_COMPLETE_SAFE.test(sink.code_snapshot)) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: 'CONTROL (complete filtering — all instances, all locations)',
              severity,
              description: `User input from ${src.label} reaches output at ${sink.label} without complete filtering. ` +
                `Vulnerable to ${cweName}.`,
              fix: 'Use global replacement (replaceAll or /g flag) to filter ALL instances. ' +
                'Apply filtering at all locations, not just the first occurrence. ' +
                'Use proven sanitization libraries instead of custom regex.',
            });
          }
        }
      }
    }

    return { cwe: cweId, name: cweName, holds: findings.length === 0, findings };
  };
}

// ===========================================================================
// A. INCOMPLETE FILTERING (8 CWEs)
// ===========================================================================

export const verifyCWE790 = createFilteringVerifier('CWE-790', 'Improper Filtering of Special Elements', 'medium');
export const verifyCWE791 = createFilteringVerifier('CWE-791', 'Incomplete Filtering of One or More Instances of Special Elements', 'medium');
export const verifyCWE792 = createFilteringVerifier('CWE-792', 'Incomplete Filtering of One Instance of a Special Element', 'medium');
export const verifyCWE793 = createFilteringVerifier('CWE-793', 'Only Filtering One Instance of a Special Element', 'medium');
export const verifyCWE794 = createFilteringVerifier('CWE-794', 'Incomplete Filtering of Multiple Instances of a Special Element', 'medium');
export const verifyCWE795 = createFilteringVerifier('CWE-795', 'Only Filtering Special Elements at a Designated Location', 'medium');
export const verifyCWE796 = createFilteringVerifier('CWE-796', 'Only Filtering Special Elements Relative to a Marker', 'medium');
export const verifyCWE797 = createFilteringVerifier('CWE-797', 'Only Filtering Special Elements at an Absolute Position', 'medium');

// ===========================================================================
// B. INDIVIDUAL PATTERNS (9 CWEs)
// ===========================================================================

export const verifyCWE181 = createGenericVerifier(
  'CWE-181', 'Incorrect Behavior Order: Validate Before Filter', 'high',
  egressNodes,
  /\bfilter\b.*\bvalid\b|\bsanitize\b.*\bcheck\b|\bnormalize\b.*\bvalid\b/i,
  'CONTROL (correct order: filter THEN validate)',
  'Apply filtering/sanitization BEFORE validation. Validating before filtering allows ' +
    'crafted input to pass validation, then be altered by filtering into a dangerous form.',
);

export const verifyCWE182 = createGenericVerifier(
  'CWE-182', 'Collapse of Data into Unsafe Value', 'high',
  egressNodes,
  /\bcollapse\b.*\bcheck\b|\bpost.*filter.*valid\b|\bafter.*sanitize.*check\b/i,
  'CONTROL (post-collapse validation — check value after filtering)',
  'Re-validate data after filtering/collapsing operations. Removing characters from input ' +
    'can cause the remaining string to form a dangerous value (e.g., "scr"+"ipt" → "script").',
);

export const verifyCWE326 = createGenericVerifier(
  'CWE-326', 'Inadequate Encryption Strength', 'high',
  egressNodes, CRYPTO_STRENGTH_SAFE,
  'CONTROL (minimum encryption strength enforcement)',
  'Use AES-256 for symmetric encryption, RSA-2048+ for asymmetric. ' +
    'Disable weak ciphers (DES, RC4, 3DES). Enforce TLS 1.2+ minimum.',
);

export const verifyCWE358 = createGenericVerifier(
  'CWE-358', 'Improperly Implemented Security Check for Standard', 'high',
  egressNodes,
  /\bstandard\b.*\bcomply\b|\bspec\b.*\bfollow\b|\bRFC\b|\bNIST\b|\bOWASP\b/i,
  'CONTROL (standard-compliant security check implementation)',
  'Implement security checks per the relevant standard (RFC, NIST, OWASP). ' +
    'Do not create custom interpretations of security standards.',
);

export const verifyCWE406 = createGenericVerifier(
  'CWE-406', 'Insufficient Control of Network Message Volume (Network Amplification)', 'high',
  egressNodes,
  /\brate.*limit\b|\bthrottle\b|\bquota\b|\bmax.*response\b|\bamplification.*check\b/i,
  'CONTROL (response size / rate limiting to prevent amplification)',
  'Limit response sizes relative to request sizes. Implement rate limiting. ' +
    'Do not allow small requests to trigger large responses without authentication.',
);

export const verifyCWE430 = createGenericVerifier(
  'CWE-430', 'Deployment of Wrong Handler (Not Verifying Handler)', 'medium',
  egressNodes,
  /\bhandler\b.*\bverif\b|\broute\b.*\bcheck\b|\bdispatch\b.*\bvalid\b/i,
  'CONTROL (handler verification before dispatch)',
  'Verify that the correct handler is dispatched for each request type. ' +
    'Validate handler registration. Do not allow user input to select handlers.',
);

export const verifyCWE488 = createGenericVerifier(
  'CWE-488', 'Exposure of Data Element to Wrong Session', 'high',
  egressNodes, SESSION_SAFE,
  'CONTROL (session isolation — data scoped to correct user)',
  'Ensure response data is scoped to the requesting session. ' +
    'Never serve cached responses containing another user\'s data. ' +
    'Use per-request context, not shared state, for user-specific data.',
);

export const verifyCWE523 = createGenericVerifier(
  'CWE-523', 'Unprotected Transport of Credentials', 'high',
  egressNodes, TRANSPORT_SAFE,
  'CONTROL (encrypted transport — HTTPS/TLS for credentials)',
  'Always transport credentials over HTTPS/TLS. Enable HSTS. ' +
    'Never send passwords, tokens, or API keys over unencrypted HTTP.',
);

export const verifyCWE598 = createGenericVerifier(
  'CWE-598', 'Use of GET Request Method With Sensitive Query Strings', 'medium',
  egressNodes, METHOD_SAFE,
  'CONTROL (POST method for sensitive data — not GET query strings)',
  'Use POST for sensitive data submission. GET parameters appear in browser history, ' +
    'server logs, Referer headers, and proxy logs. Enforce method restrictions.',
);

// ===========================================================================
// REGISTRY
// ===========================================================================

export const BATCH_008_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  'CWE-790': verifyCWE790,
  'CWE-791': verifyCWE791,
  'CWE-792': verifyCWE792,
  'CWE-793': verifyCWE793,
  'CWE-794': verifyCWE794,
  'CWE-795': verifyCWE795,
  'CWE-796': verifyCWE796,
  'CWE-797': verifyCWE797,
  'CWE-181': verifyCWE181,
  'CWE-182': verifyCWE182,
  'CWE-326': verifyCWE326,
  'CWE-358': verifyCWE358,
  'CWE-406': verifyCWE406,
  'CWE-430': verifyCWE430,
  'CWE-488': verifyCWE488,
  'CWE-523': verifyCWE523,
  'CWE-598': verifyCWE598,
};
