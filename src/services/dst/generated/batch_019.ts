/**
 * DST Generated Verifiers — Batch 019
 * Fills remaining CWE gaps in the 400–599 range (37 CWEs).
 *
 * Sub-groups:
 *   A. Real verifiers (5 CWEs) — CWE-400, CWE-434, CWE-476, CWE-522, CWE-525
 *   B. Deprecated / Category / Pillar stubs (32 CWEs) — always pass (no real weakness)
 *
 * The deprecated/category entries are included so the registry count
 * reflects full 400–599 coverage. Each stub documents WHY it is a
 * pass-through (deprecated, category, or pillar — mapping prohibited).
 */

import type { NeuralMap, NeuralMapNode, NodeType } from '../types';
import {
  nodeRef, nodesOfType, hasTaintedPathWithoutControl, hasPathWithoutTransform,
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
              description: `${sourceType} at ${src.label} \u2192 ${sinkType} at ${sink.label} without controls. Vulnerable to ${cweName}.`,
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
const nT: BfsCheck = hasPathWithoutTransform;
const nTi: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'TRANSFORM');
const nA: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'AUTH');

// ---------------------------------------------------------------------------
// Stub factory for deprecated / category / pillar CWEs
// These always hold (no findings) because mapping to them is prohibited.
// ---------------------------------------------------------------------------

function stub(cweId: string, cweName: string, reason: string): (map: NeuralMap) => VerificationResult {
  return (_map: NeuralMap): VerificationResult => ({
    cwe: cweId,
    name: `${cweName} [${reason}]`,
    holds: true,
    findings: [],
  });
}

// ===========================================================================
// A. REAL VERIFIERS (5 CWEs)
// ===========================================================================

/**
 * CWE-400: Uncontrolled Resource Consumption
 * INGRESS triggers resource allocation without throttle/limit CONTROL.
 * Allows DoS via memory, CPU, connections, or file descriptor exhaustion.
 */
export const verifyCWE400 = v(
  'CWE-400', 'Uncontrolled Resource Consumption', 'high',
  'INGRESS', 'TRANSFORM', nC,
  /\bthrottle\b|\brate.*limit\b|\bquota\b|\btimeout\b|\bmax.*pool\b|\bsetLimit\b/i,
  'CONTROL (resource limits — rate limiting, quotas, timeouts)',
  'Apply rate limiting, connection quotas, and timeouts to all user-triggered resource allocations. Use middleware like express-rate-limit or equivalent.',
);

/**
 * CWE-434: Unrestricted Upload of File with Dangerous Type
 * INGRESS[file_upload] reaches STORAGE without file-type validation CONTROL.
 * Enables remote code execution via uploaded .php/.asp/.jsp etc.
 */
export const verifyCWE434 = (map: NeuralMap): VerificationResult => {
  const findings: Finding[] = [];
  const sources = nodesOfType(map, 'INGRESS').filter(n =>
    n.node_subtype.includes('upload') || n.node_subtype.includes('file') ||
    n.attack_surface.includes('file_upload') ||
    n.code_snapshot.match(/\b(multer|formidable|busboy|upload|multipart)\b/i) !== null
  );
  const sinks = nodesOfType(map, 'STORAGE').filter(n =>
    n.node_subtype.includes('file') || n.node_subtype.includes('fs') ||
    n.node_subtype.includes('disk') || n.attack_surface.includes('file_access') ||
    n.code_snapshot.match(/\b(writeFile|createWriteStream|save|mv|pipe)\b/i) !== null
  );

  const safePattern = /\b(allowlist|whitelist|mime.*check|magic.*bytes|file.*type.*valid|extension.*check|content.*type.*valid)\b/i;

  for (const src of sources) {
    for (const sink of sinks) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (!safePattern.test(sink.code_snapshot) && !safePattern.test(src.code_snapshot)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (file type validation — allowlist of permitted extensions/MIME types)',
            severity: 'critical',
            description: `File upload at ${src.label} reaches storage at ${sink.label} without file type validation. ` +
              `Attackers can upload executable files (.php, .asp, .jsp) for remote code execution.`,
            fix: 'Validate uploaded file types against an allowlist of safe extensions AND MIME types. ' +
              'Check magic bytes, not just extensions. Store uploads outside web-accessible directories.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-434', name: 'Unrestricted Upload of File with Dangerous Type', holds: findings.length === 0, findings };
};

/**
 * CWE-476: NULL Pointer Dereference
 * A nullable return from EXTERNAL/TRANSFORM reaches dereference without null check CONTROL.
 * Causes crashes (DoS) or, in privileged contexts, unauthorized memory access.
 */
export const verifyCWE476 = (map: NeuralMap): VerificationResult => {
  const findings: Finding[] = [];

  // Sources: nodes that can return nullable values
  const sources = map.nodes.filter(n =>
    (n.node_type === 'EXTERNAL' || n.node_type === 'TRANSFORM') &&
    (n.node_subtype.includes('nullable') || n.node_subtype.includes('optional') ||
     n.code_snapshot.match(
       /\b(find|get|query|fetch|lookup|search|match|exec|pop|shift|querySelector)\b/i
     ) !== null)
  );

  // Sinks: nodes that dereference values (member access, method calls, array indexing)
  const sinks = nodesOfType(map, 'TRANSFORM').filter(n =>
    n.code_snapshot.match(
      /\.\w+\s*[\([]|\.length\b|\.toString\b|\.valueOf\b|\[\s*\d+\s*\]/i
    ) !== null
  );

  const safePattern = /\bnull.*check\b|\bif\s*\(\s*\w+\s*[!=]==?\s*null\b|\btypeof\b|\?\.\b|\?\?\b|\bassert\b/i;

  for (const src of sources) {
    for (const sink of sinks) {
      if (src.id === sink.id) continue;
      if (hasPathWithoutIntermediateType(map, src.id, sink.id, 'CONTROL')) {
        if (!safePattern.test(sink.code_snapshot) && !safePattern.test(src.code_snapshot)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (null check before dereference)',
            severity: 'medium',
            description: `Potentially-null value from ${src.label} is dereferenced at ${sink.label} without a null check. ` +
              `NULL pointer dereference causes crashes or undefined behavior.`,
            fix: 'Add null/undefined check before dereferencing. Use optional chaining (?.), nullish coalescing (??), ' +
              'or explicit null guards. Consider TypeScript strict null checks.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-476', name: 'NULL Pointer Dereference', holds: findings.length === 0, findings };
};

/**
 * CWE-522: Insufficiently Protected Credentials
 * Credentials flow from INGRESS/TRANSFORM to STORAGE/EGRESS without
 * TRANSFORM[hash|encryption] — plaintext credential exposure.
 */
export const verifyCWE522 = (map: NeuralMap): VerificationResult => {
  const findings: Finding[] = [];

  const sources = map.nodes.filter(n =>
    (n.node_type === 'INGRESS' || n.node_type === 'TRANSFORM') &&
    (n.node_subtype.includes('credential') || n.node_subtype.includes('password') ||
     n.node_subtype.includes('secret') || n.node_subtype.includes('auth') ||
     n.attack_surface.includes('credentials') ||
     n.code_snapshot.match(
       /\b(password|passwd|secret|api[_-]?key|token|credential|private[_-]?key)\b/i
     ) !== null)
  );

  const sinks = map.nodes.filter(n =>
    n.node_type === 'STORAGE' || n.node_type === 'EGRESS'
  );

  const safePattern = /\bbcrypt\b|\bargon2\b|\bscrypt\b|\bpbkdf2\b|\bhash\b|\bencrypt\b|\bcipher\b|\btls\b|\bhttps\b|\bAES\b/i;

  for (const src of sources) {
    for (const sink of sinks) {
      if (src.id === sink.id) continue;
      if (hasPathWithoutTransform(map, src.id, sink.id)) {
        if (!safePattern.test(sink.code_snapshot) && !safePattern.test(src.code_snapshot)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'TRANSFORM (strong hash or encryption — bcrypt, Argon2, AES)',
            severity: 'high',
            description: `Credentials from ${src.label} reach ${sink.label} without cryptographic protection. ` +
              `Plaintext credentials are exposed to interception or retrieval.`,
            fix: 'Hash passwords with bcrypt/Argon2/scrypt before storage. Encrypt API keys and tokens at rest. ' +
              'Transmit credentials only over TLS. Never store plaintext credentials.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-522', name: 'Insufficiently Protected Credentials', holds: findings.length === 0, findings };
};

/**
 * CWE-525: Use of Web Browser Cache Containing Sensitive Information
 * EGRESS sending sensitive response data without cache-control headers.
 * Browsers may cache passwords, credit card numbers accessible to other users.
 */
export const verifyCWE525 = v(
  'CWE-525', 'Use of Web Browser Cache Containing Sensitive Information', 'medium',
  'TRANSFORM', 'EGRESS', nC,
  /\bCache-Control\b|\bno-store\b|\bno-cache\b|\bPragma\b|\bExpires\b/i,
  'CONTROL (cache-control headers — Cache-Control: no-store for sensitive responses)',
  'Set Cache-Control: no-store, no-cache, must-revalidate on responses containing sensitive data. ' +
  'Add Pragma: no-cache and Expires: 0 for HTTP/1.0 compatibility.',
);

// ===========================================================================
// B. DEPRECATED / CATEGORY / PILLAR STUBS (32 CWEs)
// Each documents the reason it is a pass-through.
// ===========================================================================

// Category-level CWEs (mapping prohibited)
export const verifyCWE411 = stub('CWE-411', 'Resource Locking Problems', 'category — use CWE-412/413/414/833');
export const verifyCWE417 = stub('CWE-417', 'Communication Channel Errors', 'category — use CWE-419/420/425/918');
export const verifyCWE429 = stub('CWE-429', 'Handler Errors', 'category — mapping prohibited');
export const verifyCWE438 = stub('CWE-438', 'Behavioral Problems', 'category — mapping prohibited');
export const verifyCWE452 = stub('CWE-452', 'Initialization and Cleanup Errors', 'category — use CWE-454/455/459');
export const verifyCWE465 = stub('CWE-465', 'Pointer Issues', 'category — use CWE-476/468');
export const verifyCWE485 = stub('CWE-485', '7PK - Encapsulation', 'category — mapping prohibited');
export const verifyCWE557 = stub('CWE-557', 'Concurrency Issues', 'category — use CWE-362/366/367');
export const verifyCWE569 = stub('CWE-569', 'Expression Issues', 'category — use CWE-480/481/483');

// Pillar-level CWE (mapping discouraged)
export const verifyCWE435 = stub('CWE-435', 'Improper Interaction Between Multiple Correctly-Behaving Entities', 'pillar — use specific descendants');

// Deprecated CWEs (duplicates, removed, or superseded)
export const verifyCWE418 = stub('CWE-418', 'DEPRECATED: Channel Errors', 'deprecated — duplicate of CWE-417');
export const verifyCWE423 = stub('CWE-423', 'DEPRECATED: Proxied Trusted Channel', 'deprecated — duplicate of CWE-441');
export const verifyCWE442 = stub('CWE-442', 'DEPRECATED: Web Problems', 'deprecated — removed');
export const verifyCWE443 = stub('CWE-443', 'DEPRECATED: HTTP Response Splitting', 'deprecated — duplicate of CWE-113');
export const verifyCWE445 = stub('CWE-445', 'DEPRECATED: User Interface Errors', 'deprecated — duplicate of CWE-355');
export const verifyCWE458 = stub('CWE-458', 'DEPRECATED: Incorrect Initialization', 'deprecated — use CWE-665');
export const verifyCWE461 = stub('CWE-461', 'DEPRECATED: Data Structure Issues', 'deprecated — removed');
export const verifyCWE490 = stub('CWE-490', 'DEPRECATED: Mobile Code Issues', 'deprecated — removed');
export const verifyCWE503 = stub('CWE-503', 'DEPRECATED: Byte/Object Code', 'deprecated — removed');
export const verifyCWE504 = stub('CWE-504', 'DEPRECATED: Motivation/Intent', 'deprecated — removed');
export const verifyCWE505 = stub('CWE-505', 'DEPRECATED: Intentionally Introduced Weakness', 'deprecated — removed');
export const verifyCWE513 = stub('CWE-513', 'DEPRECATED: Intentionally Introduced Nonmalicious Weakness', 'deprecated — removed');
export const verifyCWE516 = stub('CWE-516', 'DEPRECATED: Covert Timing Channel', 'deprecated — use CWE-385');
export const verifyCWE517 = stub('CWE-517', 'DEPRECATED: Other Intentional Nonmalicious Weakness', 'deprecated — removed');
export const verifyCWE518 = stub('CWE-518', 'DEPRECATED: Inadvertently Introduced Weakness', 'deprecated — removed');
export const verifyCWE519 = stub('CWE-519', 'DEPRECATED: .NET Environment Issues', 'deprecated — removed');
export const verifyCWE533 = stub('CWE-533', 'DEPRECATED: Information Exposure Through Server Log Files', 'deprecated — use CWE-532');
export const verifyCWE534 = stub('CWE-534', 'DEPRECATED: Information Exposure Through Debug Log Files', 'deprecated — use CWE-532');
export const verifyCWE542 = stub('CWE-542', 'DEPRECATED: Information Exposure Through Cleanup Log Files', 'deprecated — use CWE-532');
export const verifyCWE545 = stub('CWE-545', 'DEPRECATED: Use of Dynamic Class Loading', 'deprecated — use CWE-470');
export const verifyCWE559 = stub('CWE-559', 'DEPRECATED: Often Misused: Arguments and Parameters', 'deprecated — removed');
export const verifyCWE592 = stub('CWE-592', 'DEPRECATED: Authentication Bypass Issues', 'deprecated — use CWE-287');
export const verifyCWE596 = stub('CWE-596', 'DEPRECATED: Incorrect Semantic Object Comparison', 'deprecated — use CWE-1023');

// ===========================================================================
// REGISTRY
// ===========================================================================

export const BATCH_019_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  // Real verifiers
  'CWE-400': verifyCWE400,
  'CWE-434': verifyCWE434,
  'CWE-476': verifyCWE476,
  'CWE-522': verifyCWE522,
  'CWE-525': verifyCWE525,
  // Category stubs
  'CWE-411': verifyCWE411,
  'CWE-417': verifyCWE417,
  'CWE-429': verifyCWE429,
  'CWE-438': verifyCWE438,
  'CWE-452': verifyCWE452,
  'CWE-465': verifyCWE465,
  'CWE-485': verifyCWE485,
  'CWE-557': verifyCWE557,
  'CWE-569': verifyCWE569,
  // Pillar stub
  'CWE-435': verifyCWE435,
  // Deprecated stubs
  'CWE-418': verifyCWE418,
  'CWE-423': verifyCWE423,
  'CWE-442': verifyCWE442,
  'CWE-443': verifyCWE443,
  'CWE-445': verifyCWE445,
  'CWE-458': verifyCWE458,
  'CWE-461': verifyCWE461,
  'CWE-490': verifyCWE490,
  'CWE-503': verifyCWE503,
  'CWE-504': verifyCWE504,
  'CWE-505': verifyCWE505,
  'CWE-513': verifyCWE513,
  'CWE-516': verifyCWE516,
  'CWE-517': verifyCWE517,
  'CWE-518': verifyCWE518,
  'CWE-519': verifyCWE519,
  'CWE-533': verifyCWE533,
  'CWE-534': verifyCWE534,
  'CWE-542': verifyCWE542,
  'CWE-545': verifyCWE545,
  'CWE-559': verifyCWE559,
  'CWE-592': verifyCWE592,
  'CWE-596': verifyCWE596,
};
