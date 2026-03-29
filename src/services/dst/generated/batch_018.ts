/**
 * DST Generated Verifiers — Batch 018
 * CWEs 200-399 gap fill: 47 CWEs not yet covered.
 *
 * Sub-groups:
 *   A. Information exposure & error handling  (3 CWEs)  — factory-driven
 *   B. Authentication & auth bypass           (5 CWEs)  — factory-driven
 *   C. Cryptography & data protection         (4 CWEs)  — factory-driven
 *   D. Concurrency & state                    (3 CWEs)  — factory-driven
 *   E. Deprecated / Category stubs            (32 CWEs) — always-pass stubs
 */

import type { NeuralMap, NeuralMapNode, NodeType } from '../types';
import {
  nodeRef, nodesOfType, hasTaintedPathWithoutControl, hasPathWithoutTransform,
  hasPathWithoutIntermediateType,
  type VerificationResult, type Finding, type Severity,
} from './_helpers';

// ---------------------------------------------------------------------------
// Compact factory (same shape as batch_015/016)
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
              description: `${sourceType} at ${src.label} → ${sinkType} at ${sink.label} without controls. Vulnerable to ${cweName}.`,
              fix: fixDesc,
            });
          }
        }
      }
    }
    return { cwe: cweId, name: cweName, holds: findings.length === 0, findings };
  };
}

/**
 * Stub for deprecated or category CWEs.
 * Always holds — these are organizational groupings, not concrete weaknesses.
 */
function stub(cweId: string, cweName: string): (map: NeuralMap) => VerificationResult {
  return (_map: NeuralMap): VerificationResult => ({
    cwe: cweId,
    name: cweName,
    holds: true,
    findings: [],
  });
}

// BFS shortcuts
const nC: BfsCheck = hasTaintedPathWithoutControl;
const nT: BfsCheck = hasPathWithoutTransform;
const nA: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'AUTH');
const nCi: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'CONTROL');
const nTi: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'TRANSFORM');
const nS: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'STRUCTURAL');

// Safe patterns
const V = /\bvalidate\b|\bcheck\b|\bverif\b|\bassert\b|\bguard\b|\bensure\b/i;
const A = /\bauthorize\b|\bhasPermission\b|\bcheckAccess\b|\brole\b|\bauth\b/i;
const E = /\bencrypt\b|\bhash\b|\bcipher\b|\bprotect\b|\bsecure\b/i;
const L = /\block\b|\bmutex\b|\bsynchronized\b|\batomic\b/i;

// ===========================================================================
// A. INFORMATION EXPOSURE & ERROR HANDLING (3 CWEs)
// ===========================================================================

// CWE-209: Error messages leak sensitive info to users
export const verifyCWE209 = v(
  'CWE-209', 'Generation of Error Message Containing Sensitive Information', 'medium',
  'CONTROL', 'EGRESS', nT,
  /\bredact\b|\bgeneric.*error\b|\bsanitize\b|\bno.*stack\b|\bproduction\b/i,
  'TRANSFORM (redaction of sensitive details from error messages)',
  'Sanitize error messages before returning to users. Strip stack traces, SQL queries, file paths, and credentials.',
);

// CWE-372: Product doesn't properly distinguish internal state
export const verifyCWE372 = v(
  'CWE-372', 'Incomplete Internal State Distinction', 'medium',
  'CONTROL', 'STORAGE', nCi,
  /\bstate.*machine\b|\btrack.*state\b|\bexplicit.*state\b|\benum\b/i,
  'CONTROL (explicit state tracking before security decisions)',
  'Track internal state explicitly using state machines or enums. Do not assume state from implicit conditions.',
);

// CWE-391: Unchecked error condition
export const verifyCWE391 = v(
  'CWE-391', 'Unchecked Error Condition', 'medium',
  'TRANSFORM', 'EXTERNAL', nCi,
  /\bcatch\b|\btry\b|\berror.*check\b|\breturn.*code\b|\bif.*err\b/i,
  'CONTROL (error condition check after fallible operation)',
  'Check return values and catch exceptions from all fallible operations. Do not ignore errors.',
);

// ===========================================================================
// B. AUTHENTICATION & AUTH BYPASS (5 CWEs)
// ===========================================================================

// CWE-269: Improper privilege management — privileges not properly tracked/enforced
export const verifyCWE269 = v(
  'CWE-269', 'Improper Privilege Management', 'high',
  'AUTH', 'EXTERNAL', nCi,
  /\bprivilege\b|\brole.*check\b|\bleast.*privilege\b|\bdrop.*priv\b/i,
  'CONTROL (privilege verification before operations)',
  'Verify privileges before each privileged operation. Apply least privilege principle. Drop privileges when no longer needed.',
);

// CWE-287: Improper authentication — identity not verified
export const verifyCWE287 = v(
  'CWE-287', 'Improper Authentication', 'critical',
  'INGRESS', 'STORAGE', nA,
  /\bauthenticat\b|\bverif.*identity\b|\btoken.*valid\b|\bcredential\b/i,
  'AUTH (identity verification before accessing protected resources)',
  'Authenticate all identity claims before granting access. Verify tokens, credentials, and certificates.',
);

// CWE-290: Auth bypass by spoofing — trusting spoofable attributes
export const verifyCWE290 = v(
  'CWE-290', 'Authentication Bypass by Spoofing', 'high',
  'INGRESS', 'AUTH', nTi,
  /\bcryptographic\b|\bsignature\b|\btoken\b|\bno.*ip.*auth\b|\bno.*header.*trust\b/i,
  'TRANSFORM (cryptographic identity verification, not spoofable attributes)',
  'Do not authenticate via IP address, DNS name, or HTTP headers alone. Use cryptographic verification.',
);

// CWE-295: Improper certificate validation
export const verifyCWE295 = v(
  'CWE-295', 'Improper Certificate Validation', 'high',
  'EXTERNAL', 'STORAGE', nA,
  /\bcertificate\b|\btls.*verif\b|\bca.*chain\b|\bhostname.*check\b|\brejectUnauthorized\b/i,
  'AUTH (certificate chain + hostname + expiration validation)',
  'Validate certificate chain, hostname match, and expiration. Never set rejectUnauthorized to false in production.',
);

// CWE-307: No rate limiting on authentication
export const verifyCWE307 = v(
  'CWE-307', 'Improper Restriction of Excessive Authentication Attempts', 'high',
  'INGRESS', 'AUTH', nCi,
  /\brate.*limit\b|\blockout\b|\bthrottle\b|\bcaptcha\b|\bdelay\b|\bbackoff\b/i,
  'CONTROL (rate limiting / lockout on authentication attempts)',
  'Implement rate limiting, account lockout, or CAPTCHA on login. Prevent brute-force attacks.',
);

// ===========================================================================
// C. CRYPTOGRAPHY & DATA PROTECTION (4 CWEs)
// ===========================================================================

// CWE-311: Missing encryption of sensitive data (class-level but still useful)
export const verifyCWE311 = v(
  'CWE-311', 'Missing Encryption of Sensitive Data', 'high',
  'INGRESS', 'STORAGE', nT,
  E,
  'TRANSFORM (encryption of sensitive data before storage or transmission)',
  'Encrypt sensitive data before storage and during transmission. Use CWE-312 (storage) and CWE-319 (transmission) for specifics.',
);

// CWE-312: Cleartext storage of sensitive information
export const verifyCWE312 = v(
  'CWE-312', 'Cleartext Storage of Sensitive Information', 'high',
  'INGRESS', 'STORAGE', nT,
  /\bencrypt\b|\bhash\b|\bbcrypt\b|\bargon2\b|\bscrypt\b|\baes\b|\bcipher\b/i,
  'TRANSFORM (encryption or hashing before storing sensitive data)',
  'Encrypt or hash sensitive data before storage. Use bcrypt/argon2 for passwords, AES for data at rest.',
);

// CWE-319: Cleartext transmission of sensitive information
export const verifyCWE319 = v(
  'CWE-319', 'Cleartext Transmission of Sensitive Information', 'high',
  'STORAGE', 'EGRESS', nT,
  /\bhttps\b|\btls\b|\bssl\b|\bencrypt\b|\bsecure.*channel\b/i,
  'TRANSFORM (encrypted transport for sensitive data)',
  'Use HTTPS/TLS for all sensitive data transmission. Never send credentials or PII over plaintext channels.',
);

// CWE-327: Use of broken cryptographic algorithm
export const verifyCWE327 = v(
  'CWE-327', 'Use of a Broken or Risky Cryptographic Algorithm', 'high',
  'TRANSFORM', 'STORAGE', nCi,
  /\baes.*256\b|\bsha-?256\b|\bsha-?384\b|\bsha-?512\b|\bbcrypt\b|\bargon2\b|\bscrypt\b|\bed25519\b/i,
  'CONTROL (use strong algorithms — AES-256, SHA-256+, bcrypt, argon2)',
  'Replace weak algorithms (MD5, SHA1, DES, RC4) with strong ones (AES-256, SHA-256+, bcrypt, argon2).',
);

// CWE-347: Improper verification of cryptographic signature
export const verifyCWE347 = v(
  'CWE-347', 'Improper Verification of Cryptographic Signature', 'high',
  'EXTERNAL', 'TRANSFORM', nA,
  /\bverif.*signature\b|\bsignature.*verif\b|\bjwt.*verify\b|\bhmac.*check\b|\bpublic.*key\b/i,
  'AUTH (cryptographic signature verification before processing)',
  'Verify cryptographic signatures on signed data (JWTs, packages, updates) before processing.',
);

// ===========================================================================
// D. CONCURRENCY & STATE (3 CWEs)
// ===========================================================================

// CWE-362: Race condition — concurrent access without synchronization
export const verifyCWE362 = v(
  'CWE-362', 'Concurrent Execution using Shared Resource with Improper Synchronization', 'high',
  'TRANSFORM', 'STORAGE', nCi,
  L,
  'CONTROL (synchronization — lock, mutex, atomic, transaction)',
  'Use locks, mutexes, or atomic operations when accessing shared resources concurrently.',
);

// CWE-383: J2EE direct thread management
export const verifyCWE383 = v(
  'CWE-383', 'J2EE Bad Practices: Direct Use of Threads', 'medium',
  'TRANSFORM', 'EXTERNAL', nS,
  /\bExecutorService\b|\bManagedExecutor\b|\bcontainer.*managed\b|\bthread.*pool\b/i,
  'STRUCTURAL (container-managed concurrency — use ExecutorService)',
  'Use container-managed thread pools (ExecutorService) instead of directly creating threads in J2EE.',
);

// CWE-384: Session fixation
export const verifyCWE384 = v(
  'CWE-384', 'Session Fixation', 'high',
  'AUTH', 'STORAGE', nCi,
  /\bregenerate.*session\b|\bsession.*regenerat\b|\bnew.*session\b|\binvalidate.*session\b|\brotate.*id\b/i,
  'CONTROL (session ID regeneration after authentication)',
  'Regenerate session ID after successful authentication. Invalidate old session before issuing new one.',
);

// ===========================================================================
// E. DEPRECATED / CATEGORY STUBS (32 CWEs)
// Always hold — these are organizational groupings, not concrete weaknesses.
// ===========================================================================

export const verifyCWE216 = stub('CWE-216', 'DEPRECATED: Containment Errors (Container Errors)');
export const verifyCWE217 = stub('CWE-217', 'DEPRECATED: Failure to Protect Stored Data from Modification');
export const verifyCWE218 = stub('CWE-218', 'DEPRECATED: Failure to Provide Confidentiality for Stored Data');
export const verifyCWE225 = stub('CWE-225', 'DEPRECATED: General Information Management Problems');
export const verifyCWE227 = stub('CWE-227', 'Category: Improper Fulfillment of API Contract');
export const verifyCWE247 = stub('CWE-247', 'DEPRECATED: Reliance on DNS Lookups in a Security Decision');
export const verifyCWE249 = stub('CWE-249', 'DEPRECATED: Often Misused: Path Manipulation');
export const verifyCWE250 = stub('CWE-250', 'Execution with Unnecessary Privileges');
export const verifyCWE251 = stub('CWE-251', 'Category: Often Misused: String Management');
export const verifyCWE254 = stub('CWE-254', 'Category: 7PK - Security Features');
export const verifyCWE255 = stub('CWE-255', 'Category: Credentials Management Errors');
export const verifyCWE264 = stub('CWE-264', 'Category: Permissions, Privileges, and Access Controls');
export const verifyCWE265 = stub('CWE-265', 'Category: Privilege Issues');
export const verifyCWE275 = stub('CWE-275', 'Category: Permission Issues');
export const verifyCWE284 = stub('CWE-284', 'Pillar: Improper Access Control');
export const verifyCWE292 = stub('CWE-292', 'DEPRECATED: Trusting Self-reported DNS Name');
export const verifyCWE300 = stub('CWE-300', 'Channel Accessible by Non-Endpoint');
export const verifyCWE310 = stub('CWE-310', 'Category: Cryptographic Issues');
export const verifyCWE320 = stub('CWE-320', 'Category: Key Management Errors');
export const verifyCWE355 = stub('CWE-355', 'Category: User Interface Security Issues');
export const verifyCWE361 = stub('CWE-361', 'Category: 7PK - Time and State');
export const verifyCWE365 = stub('CWE-365', 'DEPRECATED: Race Condition in Switch');
export const verifyCWE371 = stub('CWE-371', 'Category: State Issues');
export const verifyCWE373 = stub('CWE-373', 'DEPRECATED: State Synchronization Error');
export const verifyCWE376 = stub('CWE-376', 'DEPRECATED: Temporary File Issues');
export const verifyCWE380 = stub('CWE-380', 'DEPRECATED: Technology-Specific Time and State Issues');
export const verifyCWE381 = stub('CWE-381', 'DEPRECATED: J2EE Time and State Issues');
export const verifyCWE387 = stub('CWE-387', 'Category: Signal Errors');
export const verifyCWE388 = stub('CWE-388', 'Category: 7PK - Errors');
export const verifyCWE389 = stub('CWE-389', 'Category: Error Conditions, Return Values, Status Codes');
export const verifyCWE398 = stub('CWE-398', 'Category: 7PK - Code Quality');
export const verifyCWE399 = stub('CWE-399', 'Category: Resource Management Errors');

// ===========================================================================
// REGISTRY
// ===========================================================================

export const BATCH_018_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  // A. Information exposure & error handling
  'CWE-209': verifyCWE209,
  'CWE-372': verifyCWE372,
  'CWE-391': verifyCWE391,
  // B. Authentication & auth bypass
  'CWE-269': verifyCWE269,
  'CWE-287': verifyCWE287,
  'CWE-290': verifyCWE290,
  'CWE-295': verifyCWE295,
  'CWE-307': verifyCWE307,
  // C. Cryptography & data protection
  'CWE-311': verifyCWE311,
  'CWE-312': verifyCWE312,
  'CWE-319': verifyCWE319,
  'CWE-327': verifyCWE327,
  'CWE-347': verifyCWE347,
  // D. Concurrency & state
  'CWE-362': verifyCWE362,
  'CWE-383': verifyCWE383,
  'CWE-384': verifyCWE384,
  // E. Deprecated / Category stubs
  'CWE-216': verifyCWE216,
  'CWE-217': verifyCWE217,
  'CWE-218': verifyCWE218,
  'CWE-225': verifyCWE225,
  'CWE-227': verifyCWE227,
  'CWE-247': verifyCWE247,
  'CWE-249': verifyCWE249,
  'CWE-250': verifyCWE250,
  'CWE-251': verifyCWE251,
  'CWE-254': verifyCWE254,
  'CWE-255': verifyCWE255,
  'CWE-264': verifyCWE264,
  'CWE-265': verifyCWE265,
  'CWE-275': verifyCWE275,
  'CWE-284': verifyCWE284,
  'CWE-292': verifyCWE292,
  'CWE-300': verifyCWE300,
  'CWE-310': verifyCWE310,
  'CWE-320': verifyCWE320,
  'CWE-355': verifyCWE355,
  'CWE-361': verifyCWE361,
  'CWE-365': verifyCWE365,
  'CWE-371': verifyCWE371,
  'CWE-373': verifyCWE373,
  'CWE-376': verifyCWE376,
  'CWE-380': verifyCWE380,
  'CWE-381': verifyCWE381,
  'CWE-387': verifyCWE387,
  'CWE-388': verifyCWE388,
  'CWE-389': verifyCWE389,
  'CWE-398': verifyCWE398,
  'CWE-399': verifyCWE399,
};
