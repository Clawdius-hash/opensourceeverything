/**
 * DST Generated Verifiers -- Batch 020
 * Gap-fill for CWEs 600-799 that were missing from GENERATED_REGISTRY
 * and CWE_REGISTRY despite having taxonomy definitions.
 *
 * 8 CWEs:
 *   CWE-601  Open Redirect                        (INGRESS->EGRESS without CONTROL)
 *   CWE-613  Insufficient Session Expiration       (STORAGE->AUTH without CONTROL)
 *   CWE-614  Cookie without Secure attribute       (TRANSFORM->EGRESS without CONTROL)
 *   CWE-668  Resource Exposure to Wrong Sphere     (STORAGE->EGRESS without AUTH)
 *   CWE-696  Incorrect Behavior Order              (TRANSFORM->CONTROL without META)
 *   CWE-732  Incorrect Permission Assignment       (TRANSFORM->STORAGE without CONTROL)
 *   CWE-770  Resource Allocation Without Limits    (INGRESS->STORAGE without CONTROL)
 *   CWE-778  Insufficient Logging                  (AUTH->META without META)
 */

import type { NeuralMap, NeuralMapNode, NodeType } from '../types';
import {
  nodeRef, nodesOfType, hasTaintedPathWithoutControl,
  hasPathWithoutIntermediateType,
  type VerificationResult, type Finding, type Severity,
} from './_helpers';

// ---------------------------------------------------------------------------
// Compact factory (same pattern as batch_015/016)
// ---------------------------------------------------------------------------

type BfsCheck = (map: NeuralMap, srcId: string, sinkId: string) => boolean;

function v(
  cweId: string, cweName: string, severity: Severity,
  sourceType: NodeType, sinkType: NodeType,
  bfsCheck: BfsCheck,
  safePattern: RegExp,
  missingDesc: string,
  fixDesc: string,
): (map: NeuralMap) => VerificationResult {
  return (map: NeuralMap): VerificationResult => {
    const findings: Finding[] = [];
    const sources = nodesOfType(map, sourceType);
    const sinks = nodesOfType(map, sinkType);
    for (const src of sources) {
      for (const sink of sinks) {
        if (src.id === sink.id) continue;
        if (bfsCheck(map, src.id, sink.id)) {
          if (!safePattern.test(sink.code_snapshot) && !safePattern.test(src.code_snapshot)) {
            findings.push({
              source: nodeRef(src), sink: nodeRef(sink),
              missing: missingDesc, severity,
              description: `${sourceType} at ${src.label} -> ${sinkType} at ${sink.label} without controls. Vulnerable to ${cweName}.`,
              fix: fixDesc,
            });
          }
        }
      }
    }
    return { cwe: cweId, name: cweName, holds: findings.length === 0, findings };
  };
}

// BFS shortcuts
const nC: BfsCheck = hasTaintedPathWithoutControl;
const nA: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'AUTH');
const nM: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'META');
const nCi: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'CONTROL');

// ===========================================================================
// CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
// Pattern: INGRESS[url_param] -> EGRESS[http_redirect] without CONTROL[url_allowlist]
// Severity: medium | OWASP A01:2021 | SANS Top 25
// ===========================================================================

export const verifyCWE601 = v(
  'CWE-601',
  'URL Redirection to Untrusted Site (Open Redirect)',
  'medium',
  'INGRESS', 'EGRESS',
  nC,
  /\ballowlist\b|\bwhitelist\b|\ballowed.*url\b|\bsame.*origin\b|\burl.*valid\b|\bnew URL\(.*\)\.host\b|\bstartsWith\(["']\/\b/i,
  'CONTROL (URL allowlist validation before redirect)',
  'Validate redirect URLs against an allowlist of trusted domains. Reject absolute URLs to external sites. Use relative paths where possible.',
);

// ===========================================================================
// CWE-613: Insufficient Session Expiration
// Pattern: STORAGE[session] -> AUTH[session_check] without CONTROL[session_expiration]
// Severity: medium | OWASP A07:2021
// ===========================================================================

export const verifyCWE613 = v(
  'CWE-613',
  'Insufficient Session Expiration',
  'medium',
  'STORAGE', 'AUTH',
  nCi,
  /\bmaxAge\b|\bexpir\b|\bttl\b|\btimeout\b|\bidleTimeout\b|\babsoluteTimeout\b|\bsession.*destroy\b|\binvalidate\b/i,
  'CONTROL (session expiration and timeout enforcement)',
  'Set session idle timeout and absolute timeout. Invalidate sessions on logout. Use server-side session storage with TTL.',
);

// ===========================================================================
// CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
// Pattern: TRANSFORM[set_cookie] -> EGRESS[http_response] without CONTROL[secure_flag]
// Severity: medium | OWASP A05:2021
// ===========================================================================

export const verifyCWE614 = v(
  'CWE-614',
  "Sensitive Cookie Without 'Secure' Attribute",
  'medium',
  'TRANSFORM', 'EGRESS',
  nC,
  /\bsecure\s*[=:]\s*true\b|\bSecure\b|\b__Secure-\b|\bcookie.*secure\b/i,
  'CONTROL (Secure attribute on sensitive cookies)',
  'Set the Secure attribute on all sensitive cookies so they are only transmitted over HTTPS. Use __Secure- prefix where supported.',
);

// ===========================================================================
// CWE-668: Exposure of Resource to Wrong Sphere
// Pattern: STORAGE[protected_resource] -> EGRESS|EXTERNAL without AUTH|CONTROL[access_control]
// Severity: high | OWASP A01:2021
// ===========================================================================

export const verifyCWE668 = v(
  'CWE-668',
  'Exposure of Resource to Wrong Sphere',
  'high',
  'STORAGE', 'EGRESS',
  nA,
  /\bauthoriz\b|\baccess.*control\b|\bpermission\b|\brole\b|\bacl\b|\bprivate\b|\brestrict\b|\bcheckAccess\b/i,
  'AUTH (access control enforcing sphere boundaries)',
  'Enforce access control on all resources. Validate that the requesting actor belongs to the correct sphere before granting access.',
);

// ===========================================================================
// CWE-696: Incorrect Behavior Order
// Pattern: TRANSFORM -> CONTROL where canonicalization/normalization happens
//          after validation instead of before it
// Severity: medium
// ===========================================================================

export const verifyCWE696 = v(
  'CWE-696',
  'Incorrect Behavior Order',
  'medium',
  'TRANSFORM', 'CONTROL',
  nM,
  /\bcanonicalize.*then.*valid\b|\bnormalize.*before\b|\border.*enforc\b|\bpipeline\b|\bmiddleware.*order\b/i,
  'META (behavior ordering documentation and enforcement)',
  'Canonicalize and normalize input before validation. Authenticate before authorizing. Document and enforce operation ordering in middleware pipelines.',
);

// ===========================================================================
// CWE-732: Incorrect Permission Assignment for Critical Resource
// Pattern: TRANSFORM[resource_create|chmod] -> STORAGE[critical_resource]
//          without CONTROL[least_privilege_permissions]
// Severity: high | OWASP A01:2021 | SANS Top 25
// ===========================================================================

export const verifyCWE732 = v(
  'CWE-732',
  'Incorrect Permission Assignment for Critical Resource',
  'high',
  'TRANSFORM', 'STORAGE',
  nC,
  /\b0[0-7]{3}\b|\bchmod\b|\bchown\b|\bleast.*privilege\b|\bprivate\b|\breadonly\b|\b0600\b|\b0400\b|\bumask\b/i,
  'CONTROL (least-privilege permission enforcement)',
  'Apply least-privilege permissions to critical resources. Use restrictive defaults (0600 for files, 0700 for directories). Validate permissions after creation.',
);

// ===========================================================================
// CWE-770: Allocation of Resources Without Limits or Throttling
// Pattern: INGRESS -> TRANSFORM|STORAGE[resource_alloc] without CONTROL[quota|throttle]
// Severity: high | SANS Top 25
// ===========================================================================

export const verifyCWE770 = v(
  'CWE-770',
  'Allocation of Resources Without Limits or Throttling',
  'high',
  'INGRESS', 'STORAGE',
  nC,
  /\brateLimit\b|\bthrottle\b|\bquota\b|\bmaxSize\b|\bmaxCount\b|\bpool\b|\blimit\b|\bconcurrency\b/i,
  'CONTROL (resource allocation limits and throttling)',
  'Impose limits on resource allocation: max size, max count, per-user quotas, rate limiting, and connection pool bounds. Reject requests that exceed thresholds.',
);

// ===========================================================================
// CWE-778: Insufficient Logging
// Pattern: AUTH[security_event] -> processing without META[comprehensive_logging]
// Severity: medium | OWASP A09:2021
// ===========================================================================

export const verifyCWE778 = v(
  'CWE-778',
  'Insufficient Logging',
  'medium',
  'AUTH', 'META',
  nM,
  /\blog\b|\baudit\b|\brecord\b|\btrack\b|\bmonitor\b|\bjournal\b|\bevent.*log\b|\bsecurity.*log\b/i,
  'META (comprehensive security event logging)',
  'Log all security-critical events with who, what, when, where, and outcome. Include failed auth attempts, privilege changes, and access denials. Use structured logging.',
);

// ===========================================================================
// BATCH REGISTRY
// ===========================================================================

export const BATCH_020_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  'CWE-601': verifyCWE601,
  'CWE-613': verifyCWE613,
  'CWE-614': verifyCWE614,
  'CWE-668': verifyCWE668,
  'CWE-696': verifyCWE696,
  'CWE-732': verifyCWE732,
  'CWE-770': verifyCWE770,
  'CWE-778': verifyCWE778,
};
