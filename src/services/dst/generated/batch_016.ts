/**
 * DST Generated Verifiers — Batch 016 (FINAL)
 * All remaining pattern shapes (153 CWEs).
 *
 * Covers ~55 small shapes (1-4 CWEs each): miscellaneous combinations of
 * all 9 node types across all mediator types.
 */

import type { NeuralMap, NeuralMapNode, NodeType } from '../types';
import {
  nodeRef, nodesOfType, hasTaintedPathWithoutControl, hasPathWithoutTransform,
  hasPathWithoutIntermediateType,
  type VerificationResult, type Finding, type Severity,
} from './_helpers';

// ---------------------------------------------------------------------------
// Compact factory (same as batch_015)
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

// BFS shortcuts
const nC: BfsCheck = hasTaintedPathWithoutControl;
const nT: BfsCheck = hasPathWithoutTransform;
const nCi: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'CONTROL');
const nTi: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'TRANSFORM');
const nA: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'AUTH');
const nM: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'META');
const nS: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'STRUCTURAL');
const nE: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'EXTERNAL');
const nEg: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'EGRESS');
const nSt: BfsCheck = (m, s, d) => hasPathWithoutIntermediateType(m, s, d, 'STORAGE');

// Safe patterns
const V = /\bvalidate\b|\bcheck\b|\bverif\b|\bassert\b|\bguard\b|\bensure\b/i;
const S = /\bsanitize\b|\bescape\b|\bencode\b|\bfilter\b|\bstrip\b/i;
const A = /\bauthorize\b|\bhasPermission\b|\bcheckAccess\b|\brole\b|\bauth\b/i;
const E = /\bencrypt\b|\bhash\b|\bcipher\b|\bprotect\b|\bsecure\b/i;
const L = /\block\b|\bmutex\b|\bsynchronized\b|\batomic\b/i;
const R = /\brelease\b|\bclose\b|\bdispose\b|\bfinally\b|\bcleanup\b/i;
const I = /\bimmutable\b|\bfreeze\b|\breadonly\b|\bconst\b|\bseal\b/i;
const D = /\bdebug.*off\b|\bproduction\b|\bNODE_ENV\b/i;
const CR = /\bcrypto\.random\b|\brandomBytes\b|\bCSPRNG\b|\bgetRandomValues\b/i;

// ===========================================================================
// 4-CWE SHAPES
// ===========================================================================

// EXTERNAL→TRANSFORM without AUTH (4)
export const verifyCWE322 = v('CWE-322', 'Key Exchange without Entity Authentication', 'high', 'EXTERNAL', 'TRANSFORM', nA, /\bauthenticat\b|\bcertificate\b|\bverif.*identity\b/i, 'AUTH (entity authentication during key exchange)', 'Authenticate parties during key exchange. Use authenticated key exchange protocols.');
export const verifyCWE494 = v('CWE-494', 'Download of Code Without Integrity Check', 'high', 'EXTERNAL', 'TRANSFORM', nA, /\bhash\b|\bsignature\b|\bintegrity\b|\bchecksum\b|\bSRI\b/i, 'AUTH (code integrity verification before execution)', 'Verify downloaded code integrity (hash, signature) before execution.');
export const verifyCWE618 = v('CWE-618', 'Exposed Unsafe ActiveX Method', 'high', 'EXTERNAL', 'TRANSFORM', nA, /\bsafe\b|\brestrict\b|\bdisable\b/i, 'AUTH (restrict unsafe ActiveX methods)', 'Do not expose unsafe ActiveX methods. Restrict scriptable interfaces.');
export const verifyCWE749 = v('CWE-749', 'Exposed Dangerous Method or Function', 'high', 'EXTERNAL', 'TRANSFORM', nA, A, 'AUTH (access control on dangerous methods)', 'Restrict access to dangerous methods. Require authentication for sensitive operations.');

// TRANSFORM→EXTERNAL without CONTROL (4)
export const verifyCWE437 = v('CWE-437', 'Incomplete Model of Endpoint Features', 'medium', 'TRANSFORM', 'EXTERNAL', nC, V, 'CONTROL (complete endpoint feature model)', 'Account for all endpoint features. Incomplete models allow bypasses.');
export const verifyCWE475 = v('CWE-475', 'Undefined Behavior for Input to API', 'medium', 'TRANSFORM', 'EXTERNAL', nC, V, 'CONTROL (API input validation)', 'Validate all inputs to APIs. Handle undefined behavior cases explicitly.');
export const verifyCWE593 = v('CWE-593', 'Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects are Created', 'high', 'TRANSFORM', 'EXTERNAL', nC, /\bfreeze\b|\bimmutable\b|\bno.*modif\b/i, 'CONTROL (SSL context immutability after object creation)', 'Do not modify SSL contexts after creating SSL objects. Changes may not propagate.');
export const verifyCWE605 = v('CWE-605', 'Multiple Binds to the Same Port', 'medium', 'TRANSFORM', 'EXTERNAL', nC, /\bSO_REUSEADDR\b|\bexclusive\b|\bcheck.*port\b/i, 'CONTROL (exclusive port binding)', 'Use exclusive port binding. Check for existing listeners before binding.');

// STORAGE→TRANSFORM without TRANSFORM (4)
export const verifyCWE665 = v('CWE-665', 'Improper Initialization', 'medium', 'STORAGE', 'TRANSFORM', nTi, /\binit\b|\bdefault\b|\bconstructor\b/i, 'TRANSFORM (proper initialization before use)', 'Initialize all variables and resources before use. Set safe defaults.');
export const verifyCWE908 = v('CWE-908', 'Use of Uninitialized Resource', 'high', 'STORAGE', 'TRANSFORM', nTi, /\binit\b|\bdefault\b|\b=\s/i, 'TRANSFORM (resource initialization before use)', 'Initialize all resources before use. Uninitialized memory may contain sensitive data.');
export const verifyCWE909 = v('CWE-909', 'Missing Initialization of Resource', 'medium', 'STORAGE', 'TRANSFORM', nTi, /\binit\b|\bconstructor\b|\bfactory\b/i, 'TRANSFORM (explicit resource initialization)', 'Explicitly initialize all resources. Do not rely on default values for security-critical state.');
export const verifyCWE910 = v('CWE-910', 'Use of Expired File Descriptor', 'high', 'STORAGE', 'TRANSFORM', nTi, /\bcheck.*fd\b|\bvalid\b|\bclose.*null\b/i, 'TRANSFORM (file descriptor validity check)', 'Check file descriptor validity before use. Invalidate after close.');

// TRANSFORM→TRANSFORM without META (4)
export const verifyCWE683 = v('CWE-683', 'Function Call With Incorrect Order of Arguments', 'medium', 'TRANSFORM', 'TRANSFORM', nM, /\btype.*check\b|\bnamed.*param\b|\btypescript\b/i, 'META (type safety / named parameters to prevent argument order errors)', 'Use named parameters or TypeScript for argument safety. Review call sites for argument order.');
export const verifyCWE685 = v('CWE-685', 'Function Call With Incorrect Number of Arguments', 'medium', 'TRANSFORM', 'TRANSFORM', nM, /\barity\b|\blength.*check\b|\btypescript\b|\bstrict\b/i, 'META (function arity enforcement)', 'Use TypeScript strict mode. Check argument counts. Enable strict arity checking.');
export const verifyCWE686 = v('CWE-686', 'Function Call With Incorrect Argument Type', 'medium', 'TRANSFORM', 'TRANSFORM', nM, /\btypeof\b|\binstanceof\b|\btypescript\b|\btype.*check\b/i, 'META (type checking on function arguments)', 'Use TypeScript or runtime type checks. Validate argument types before use.');
export const verifyCWE688 = v('CWE-688', 'Function Call With Incorrect Variable or Reference as Argument', 'medium', 'TRANSFORM', 'TRANSFORM', nM, /\bconst\b|\blet\b|\bname.*check\b|\blint\b/i, 'META (correct variable reference in function calls)', 'Use linting to catch wrong variable references. Use const for immutable bindings.');

// ===========================================================================
// 3-CWE SHAPES
// ===========================================================================

// AUTH→EGRESS without TRANSFORM (3)
export const verifyCWE204 = v('CWE-204', 'Observable Response Discrepancy', 'medium', 'AUTH', 'EGRESS', nT, /\bgeneric.*error\b|\bsame.*response\b|\buniform\b/i, 'TRANSFORM (uniform responses for auth success/failure)', 'Return identical response shape for valid/invalid credentials to prevent user enumeration.');
export const verifyCWE206 = v('CWE-206', 'Observable Internal Behavioral Discrepancy', 'medium', 'AUTH', 'EGRESS', nT, /\bconstant.*time\b|\buniform\b|\bsame.*behavior\b/i, 'TRANSFORM (uniform internal behavior regardless of input validity)', 'Ensure consistent timing and behavior regardless of auth input validity.');
export const verifyCWE208 = v('CWE-208', 'Observable Timing Discrepancy', 'medium', 'AUTH', 'EGRESS', nT, /\btimingSafe\b|\bconstant.*time\b|\bcrypto\.timingSafeEqual\b/i, 'TRANSFORM (constant-time comparison for auth)', 'Use crypto.timingSafeEqual for secret comparison. Timing differences leak information.');

// STRUCTURAL→EGRESS without TRANSFORM (3)
export const verifyCWE207 = v('CWE-207', 'Observable Behavioral Discrepancy With Equivalent Error', 'low', 'STRUCTURAL', 'EGRESS', nT, /\bgeneric.*error\b|\buniform\b/i, 'TRANSFORM (uniform error responses)', 'Return consistent error responses regardless of failure reason.');
export const verifyCWE210 = v('CWE-210', 'Self-generated Error Message Containing Sensitive Information', 'medium', 'STRUCTURAL', 'EGRESS', nT, /\bgeneric\b|\bredact\b|\bsanitize\b/i, 'TRANSFORM (sanitize error messages — no sensitive details)', 'Sanitize error messages. Do not include stack traces, paths, or SQL in responses.');
export const verifyCWE459 = v('CWE-459', 'Incomplete Cleanup', 'medium', 'STRUCTURAL', 'EGRESS', nT, R, 'TRANSFORM (complete resource cleanup)', 'Clean up all resources: temporary files, credentials in memory, session data.');

// EXTERNAL→EGRESS without CONTROL (3)
export const verifyCWE211 = v('CWE-211', 'Externally-Generated Error Message Containing Sensitive Information', 'medium', 'EXTERNAL', 'EGRESS', nC, /\bgeneric\b|\bfilter\b|\bredact\b/i, 'CONTROL (filter external error messages)', 'Filter error messages from external systems. Do not pass them directly to users.');
export const verifyCWE573 = v('CWE-573', 'Improper Following of Specification by Caller', 'medium', 'EXTERNAL', 'EGRESS', nC, V, 'CONTROL (API specification compliance)', 'Follow API specifications. Validate responses match expected format.');
export const verifyCWE589 = v('CWE-589', 'Call to Non-ubiquitous API', 'low', 'EXTERNAL', 'EGRESS', nC, /\bpolyfill\b|\bfeature.*detect\b|\bcompat\b/i, 'CONTROL (API availability check / polyfill)', 'Check API availability before use. Use polyfills for non-ubiquitous APIs.');

// STORAGE→EXTERNAL without TRANSFORM (3)
export const verifyCWE226 = v('CWE-226', 'Sensitive Information in Resource Not Removed Before Reuse', 'high', 'STORAGE', 'EXTERNAL', nT, /\bclear\b|\bwipe\b|\bzero\b|\bscrub\b/i, 'TRANSFORM (scrub sensitive data before resource reuse)', 'Clear sensitive data from resources before reusing or sharing.');
export const verifyCWE374 = v('CWE-374', 'Passing Mutable Objects to an Untrusted Method', 'medium', 'STORAGE', 'EXTERNAL', nT, /\bclone\b|\bcopy\b|\bfreeze\b|\bimmutable\b/i, 'TRANSFORM (defensive copy before passing to untrusted code)', 'Pass defensive copies to untrusted methods. Do not share mutable internal state.');
export const verifyCWE590 = v('CWE-590', 'Free of Memory not on the Heap', 'critical', 'STORAGE', 'EXTERNAL', nT, /\bheap.*check\b|\bmalloc.*match\b|\bvalid.*pointer\b/i, 'TRANSFORM (heap validation before free)', 'Only free heap-allocated memory. Never free stack or static variables.');

// STRUCTURAL→STORAGE without CONTROL (3)
export const verifyCWE243 = v('CWE-243', 'Creation of chroot Jail Without Changing Working Directory', 'medium', 'STRUCTURAL', 'STORAGE', nC, /\bchdir\b.*\bchroot\b|\bchroot\b.*\bchdir\b/i, 'CONTROL (chdir to / after chroot)', 'Call chdir("/") after chroot(). Without it, relative paths escape the jail.');
export const verifyCWE276 = v('CWE-276', 'Incorrect Default Permissions', 'medium', 'STRUCTURAL', 'STORAGE', nC, /\bumask\b|\bchmod\b|\b0[67]00\b|\brestrictive\b/i, 'CONTROL (restrictive default permissions)', 'Set restrictive default permissions (0600 for files, 0700 for dirs). Use umask.');
export const verifyCWE277 = v('CWE-277', 'Insecure Inherited Permissions', 'medium', 'STRUCTURAL', 'STORAGE', nC, /\bexplicit.*permission\b|\bno.*inherit\b|\bumask\b/i, 'CONTROL (explicit permissions, not inherited)', 'Set explicit permissions instead of inheriting from parent. Inherited permissions may be too broad.');

// STRUCTURAL→EXTERNAL without STRUCTURAL (3)
export const verifyCWE245 = v('CWE-245', 'J2EE Bad Practices: Direct Management of Connections', 'medium', 'STRUCTURAL', 'EXTERNAL', nS, /\bpool\b|\bmanaged\b|\bDataSource\b/i, 'STRUCTURAL (managed connections — use connection pools)', 'Use managed connection pools. Do not directly manage database/network connections in J2EE.');
export const verifyCWE246 = v('CWE-246', 'J2EE Bad Practices: Direct Use of Sockets', 'medium', 'STRUCTURAL', 'EXTERNAL', nS, /\bpool\b|\bmanaged\b|\bJMS\b/i, 'STRUCTURAL (managed communication — use container services)', 'Use container-managed services instead of raw sockets in J2EE.');
export const verifyCWE586 = v('CWE-586', 'Explicit Call to Finalize()', 'low', 'STRUCTURAL', 'EXTERNAL', nS, /\bno.*finalize\b|\bautoCloseable\b|\btry.*resources\b/i, 'STRUCTURAL (no explicit finalize — use try-with-resources)', 'Do not call finalize() explicitly. Use try-with-resources for cleanup.');

// ===========================================================================
// 2-CWE SHAPES
// ===========================================================================

// META→TRANSFORM without CONTROL (2)
export const verifyCWE6 = v('CWE-6', 'J2EE Misconfiguration: Insufficient Session-ID Length', 'medium', 'META', 'TRANSFORM', nC, /\b128\b|\b256\b|\blong.*session\b|\brandom\b/i, 'CONTROL (sufficient session ID length — 128+ bits)', 'Configure session IDs to 128+ bits. Short IDs are brute-forceable.');
export const verifyCWE109 = v('CWE-109', 'Struts: Validator Turned Off', 'medium', 'META', 'TRANSFORM', nC, V, 'CONTROL (validation framework enabled)', 'Ensure validation framework is enabled in configuration. Do not disable validators.');

// STORAGE→STORAGE without CONTROL (2)
export const verifyCWE120 = v('CWE-120', 'Buffer Copy without Checking Size of Input (Classic Buffer Overflow)', 'critical', 'STORAGE', 'STORAGE', nCi, /\blength\b.*check|\bsizeof\b|\bstrncpy\b|\bsnprintf\b|\bbounds\b/i, 'CONTROL (size check before buffer copy)', 'Check source size before copying to destination buffer. Use strncpy/snprintf.');
export const verifyCWE806 = v('CWE-806', 'Buffer Access Using Size of Source Buffer', 'high', 'STORAGE', 'STORAGE', nCi, /\bdestination.*size\b|\btarget.*length\b|\bmin\b.*\bsize\b/i, 'CONTROL (use destination buffer size, not source)', 'Use destination buffer size for bounds checking, not source buffer size.');

// INGRESS→STRUCTURAL without TRANSFORM (2)
export const verifyCWE188 = v('CWE-188', 'Reliance on Data/Memory Layout', 'medium', 'INGRESS', 'STRUCTURAL', nT, /\bportable\b|\boffsetof\b|\bpacked\b.*\bstruct\b/i, 'TRANSFORM (portable data handling — no layout assumptions)', 'Do not assume specific memory layout. Use offsetof, packed structs, or serialization.');
export const verifyCWE431 = v('CWE-431', 'Missing Handler', 'medium', 'INGRESS', 'STRUCTURAL', nT, /\bdefault.*handler\b|\bfallback\b|\bcatch.*all\b/i, 'TRANSFORM (default handler for unmatched requests)', 'Add default handlers for unmatched routes/events. Return 404 or appropriate errors.');

// STORAGE→EGRESS without META (2)
export const verifyCWE213 = v('CWE-213', 'Exposure of Sensitive Information Due to Incompatible Policies', 'medium', 'STORAGE', 'EGRESS', nM, /\bpolicy\b|\bconsistent\b|\bclassification\b/i, 'META (consistent data classification policy)', 'Align data classification policies across all components. Inconsistent policies leak sensitive data.');
export const verifyCWE512 = v('CWE-512', 'Spyware', 'critical', 'STORAGE', 'EGRESS', nM, /\baudit\b|\breview\b|\bno.*track\b|\bprivacy\b/i, 'META (code audit for unauthorized data collection)', 'Audit for unauthorized data collection. Review third-party SDKs for spyware behavior.');

// INGRESS→STRUCTURAL without CONTROL (2)
export const verifyCWE242 = v('CWE-242', 'Use of Inherently Dangerous Function', 'medium', 'INGRESS', 'STRUCTURAL', nC, /\bsafe.*alternative\b|\bban\b|\bdeprecated\b/i, 'CONTROL (ban dangerous functions — use safe alternatives)', 'Ban inherently dangerous functions (gets, strcpy). Use safe alternatives (fgets, strncpy).');
export const verifyCWE410 = v('CWE-410', 'Insufficient Resource Pool', 'medium', 'INGRESS', 'STRUCTURAL', nC, /\bpool\b|\bmax\b|\blimit\b|\bscale\b/i, 'CONTROL (adequate resource pool sizing)', 'Size resource pools for expected load. Implement autoscaling. Set maximum limits.');

// AUTH→STORAGE without TRANSFORM (2)
export const verifyCWE256 = v('CWE-256', 'Plaintext Storage of a Password', 'critical', 'AUTH', 'STORAGE', nT, E, 'TRANSFORM (hash passwords before storage)', 'Hash passwords with bcrypt/scrypt/Argon2 before storage. Never store plaintext passwords.');
export const verifyCWE257 = v('CWE-257', 'Storing Passwords in a Recoverable Format', 'high', 'AUTH', 'STORAGE', nT, /\bbcrypt\b|\bscrypt\b|\bargon2\b|\bone.*way\b/i, 'TRANSFORM (one-way hash — not reversible encryption)', 'Use one-way hashes for passwords. Encrypted passwords can be decrypted — hashed ones cannot.');

// AUTH→STORAGE without CONTROL (2)
export const verifyCWE261 = v('CWE-261', 'Weak Encoding for Password', 'high', 'AUTH', 'STORAGE', nCi, /\bbcrypt\b|\bscrypt\b|\bargon2\b/i, 'CONTROL (strong password hashing — not encoding)', 'Use adaptive hashing (bcrypt/scrypt/Argon2), not encoding (base64) for passwords.');
export const verifyCWE842 = v('CWE-842', 'Placement of User into Incorrect Group', 'high', 'AUTH', 'STORAGE', nCi, /\bvalidate.*group\b|\bcheck.*role\b|\bverif.*assign\b/i, 'CONTROL (group assignment verification)', 'Verify group/role assignments. Incorrect group placement grants unauthorized access.');

// AUTH→STORAGE without META (2)
export const verifyCWE262 = v('CWE-262', 'Not Using Password Aging', 'low', 'AUTH', 'STORAGE', nM, /\bexpir\b|\bage\b|\brotate\b|\bmax.*days\b/i, 'META (password aging policy)', 'Implement password aging policies. Require periodic password changes.');
export const verifyCWE671 = v('CWE-671', 'Lack of Administrator Control over Security', 'medium', 'AUTH', 'STORAGE', nM, /\badmin\b|\bconfig\b|\bpolicy\b|\bmanage\b/i, 'META (administrator security controls)', 'Provide administrators with security controls: password policies, session timeouts, access rules.');

// META→AUTH without CONTROL (2)
export const verifyCWE263 = v('CWE-263', 'Password Aging with Long Expiration', 'low', 'META', 'AUTH', nC, /\bmax.*age\b|\b90\b.*\bdays?\b|\bshort.*expir\b/i, 'CONTROL (reasonable password expiration — 90 days or less)', 'Set password expiration to 90 days or less. Long expiration increases exposure window.');
export const verifyCWE556 = v('CWE-556', 'ASP.NET Misconfiguration: Use of Identity Impersonation', 'medium', 'META', 'AUTH', nC, /\bimpersonat.*false\b|\bdisable.*impersonat\b/i, 'CONTROL (disable unnecessary identity impersonation)', 'Disable ASP.NET identity impersonation unless specifically required.');

// EXTERNAL→STRUCTURAL without CONTROL (2)
export const verifyCWE282 = v('CWE-282', 'Improper Ownership Management', 'medium', 'EXTERNAL', 'STRUCTURAL', nC, /\bowner\b|\bchown\b|\bownership.*check\b/i, 'CONTROL (ownership validation)', 'Validate resource ownership. Prevent unauthorized ownership transfers.');
export const verifyCWE283 = v('CWE-283', 'Unverified Ownership', 'medium', 'EXTERNAL', 'STRUCTURAL', nC, /\bverif.*owner\b|\bownership.*check\b|\bbelongsTo\b/i, 'CONTROL (ownership verification before access)', 'Verify ownership before allowing operations on resources.');

// EXTERNAL→CONTROL without CONTROL (2)
export const verifyCWE394 = v('CWE-394', 'Unexpected Status Code or Return Value', 'medium', 'EXTERNAL', 'CONTROL', nCi, V, 'CONTROL (status code validation from external systems)', 'Validate status codes from external systems. Handle unexpected values securely.');
export const verifyCWE440 = v('CWE-440', 'Expected Behavior Violation', 'medium', 'EXTERNAL', 'CONTROL', nCi, V, 'CONTROL (behavior verification for external components)', 'Verify external component behavior matches expectations. Handle violations gracefully.');

// INGRESS→EXTERNAL without AUTH (2)
export const verifyCWE441 = v('CWE-441', 'Unintended Proxy or Intermediary (Confused Deputy)', 'high', 'INGRESS', 'EXTERNAL', nA, A, 'AUTH (deputy privilege check — verify authority for forwarded requests)', 'Verify the requester has authority for the operations being proxied. Prevent confused deputy attacks.');
export const verifyCWE566 = v('CWE-566', 'Authorization Bypass Through User-Controlled SQL Primary Key', 'high', 'INGRESS', 'EXTERNAL', nA, /\bisOwner\b|\bownership\b|\bscoped\b/i, 'AUTH (object-level authorization for SQL primary keys)', 'Verify user authorization for the specific record identified by the primary key.');

// STORAGE→CONTROL without TRANSFORM (2)
export const verifyCWE453 = v('CWE-453', 'Insecure Default Variable Initialization', 'medium', 'STORAGE', 'CONTROL', nT, /\bsafe.*default\b|\bfalse\b|\b0\b|\bnull\b|\bexplicit.*init\b/i, 'TRANSFORM (secure default initialization)', 'Initialize security-critical variables to safe defaults (deny by default).');
export const verifyCWE456 = v('CWE-456', 'Missing Initialization of a Variable', 'medium', 'STORAGE', 'CONTROL', nT, /\binit\b|\bdefault\b|\b=\s/i, 'TRANSFORM (explicit variable initialization)', 'Initialize all variables before use in control flow.');

// TRANSFORM→EXTERNAL without STRUCTURAL (2)
export const verifyCWE477 = v('CWE-477', 'Use of Obsolete Function', 'low', 'TRANSFORM', 'EXTERNAL', nS, /\bdeprecated\b|\bobsolete\b|\bupdated\b|\breplacement\b/i, 'STRUCTURAL (use current API versions)', 'Replace obsolete functions with current alternatives. Obsolete APIs may have known vulnerabilities.');
export const verifyCWE695 = v('CWE-695', 'Use of Low-Level Functionality', 'medium', 'TRANSFORM', 'EXTERNAL', nS, /\bhigh.*level\b|\babstraction\b|\bframework\b|\bAPI\b/i, 'STRUCTURAL (use high-level abstractions)', 'Use high-level APIs instead of low-level system calls where possible.');

// CONTROL→STRUCTURAL without CONTROL (2)
export const verifyCWE484 = v('CWE-484', 'Omitted Break Statement in Switch', 'medium', 'CONTROL', 'STRUCTURAL', nCi, /\bbreak\b|\breturn\b|\bfall.*through\b.*\bintentional\b/i, 'CONTROL (explicit break or documented fallthrough)', 'Add break statements to switch cases. Document intentional fallthrough.');
export const verifyCWE543 = v('CWE-543', 'Use of Singleton Pattern Without Synchronized Access', 'medium', 'CONTROL', 'STRUCTURAL', nCi, L, 'CONTROL (synchronized singleton access)', 'Synchronize singleton access in multithreaded contexts. Use double-checked locking with volatile.');

// EXTERNAL→STRUCTURAL without AUTH (2)
export const verifyCWE553 = v('CWE-553', 'Command Shell in Externally Accessible Directory', 'high', 'EXTERNAL', 'STRUCTURAL', nA, /\bremove\b|\brestrict\b|\bdeny\b|\bblock\b/i, 'AUTH (remove/restrict shells in accessible directories)', 'Remove command shells from web-accessible directories. Block execution of uploads.');
export const verifyCWE673 = v('CWE-673', 'External Influence of Sphere Definition', 'high', 'EXTERNAL', 'STRUCTURAL', nA, V, 'AUTH (prevent external influence on trust sphere boundaries)', 'Do not let external input define trust boundaries. Define spheres in server-side configuration.');

// CONTROL→STRUCTURAL without INGRESS (2)
export const verifyCWE561 = v('CWE-561', 'Dead Code', 'low', 'CONTROL', 'STRUCTURAL', nCi, /\bremove\b|\bclean\b|\bno.*dead.*code\b|\blint\b/i, 'CONTROL (dead code removal)', 'Remove dead code. It increases attack surface and maintenance burden.');
export const verifyCWE570 = v('CWE-570', 'Expression is Always False', 'low', 'CONTROL', 'STRUCTURAL', nCi, /\blint\b|\bstatic.*analysis\b|\bcorrect\b/i, 'CONTROL (correct conditional expressions)', 'Fix always-false expressions. They indicate logic errors.');

// STRUCTURAL→EXTERNAL without EXTERNAL (2)
export const verifyCWE572 = v('CWE-572', 'Call to Thread run() instead of start()', 'medium', 'STRUCTURAL', 'EXTERNAL', nE, /\bstart\b|\bThread\.start\b/i, 'EXTERNAL (Thread.start() not run())', 'Call Thread.start() to create a new thread. Thread.run() executes synchronously.');
export const verifyCWE576 = v('CWE-576', 'EJB Bad Practices: Use of Java I/O', 'low', 'STRUCTURAL', 'EXTERNAL', nE, /\bmanaged\b|\bJNDI\b|\bcontainer\b/i, 'EXTERNAL (container-managed I/O)', 'Use container-managed resources. Direct Java I/O in EJBs bypasses container services.');

// STRUCTURAL→EXTERNAL without AUTH (2)
export const verifyCWE578 = v('CWE-578', 'EJB Bad Practices: Use of Class Loader', 'medium', 'STRUCTURAL', 'EXTERNAL', nA, /\bno.*classLoader\b|\bcontainer.*managed\b/i, 'AUTH (no custom class loaders in managed environments)', 'Do not use custom class loaders in EJBs. Container manages class loading.');
export const verifyCWE766 = v('CWE-766', 'Critical Data Element Declared Public', 'medium', 'STRUCTURAL', 'EXTERNAL', nA, /\bprivate\b|\bprotected\b|\bencapsulat\b/i, 'AUTH (encapsulate critical data — private, not public)', 'Make critical data elements private with controlled accessors.');

// CONTROL→EGRESS without CONTROL (2)
export const verifyCWE584 = v('CWE-584', 'Return Inside Finally Block', 'medium', 'CONTROL', 'EGRESS', nCi, /\bno.*return.*finally\b|\blint\b|\bno-unsafe-finally\b/i, 'CONTROL (no return in finally — masks exceptions)', 'Do not return from finally blocks. It masks exceptions from try/catch.');
export const verifyCWE698 = v('CWE-698', 'Execution After Redirect', 'medium', 'CONTROL', 'EGRESS', nCi, /\breturn\b.*\bredirect\b|\bexit\b|\bdie\b/i, 'CONTROL (return/exit after redirect)', 'Always return/exit after sending a redirect. Code after redirect still executes.');

// STRUCTURAL→STRUCTURAL without CONTROL (2)
export const verifyCWE628 = v('CWE-628', 'Function Call with Incorrectly Specified Arguments', 'medium', 'STRUCTURAL', 'STRUCTURAL', nCi, /\btypescript\b|\btype.*check\b|\blint\b/i, 'CONTROL (type-safe function calls)', 'Use TypeScript or linting to catch incorrect arguments at compile time.');
export const verifyCWE653 = v('CWE-653', 'Improper Isolation or Compartmentalization', 'medium', 'STRUCTURAL', 'STRUCTURAL', nCi, /\bisolat\b|\bsandbox\b|\bcompartment\b|\bmodule\b/i, 'CONTROL (proper isolation between components)', 'Isolate security domains. Use separate processes or sandboxes for untrusted code.');

// TRANSFORM→TRANSFORM without TRANSFORM (2)
export const verifyCWE666 = v('CWE-666', 'Operation on Resource in Wrong Phase of Lifetime', 'medium', 'TRANSFORM', 'TRANSFORM', nTi, /\bstate.*check\b|\bphase\b|\blifecycle\b|\binit.*before.*use\b/i, 'TRANSFORM (lifecycle phase validation)', 'Verify resource is in correct lifecycle phase before operations. Init before use, release after.');
export const verifyCWE761 = v('CWE-761', 'Free of Pointer not at Start of Buffer', 'critical', 'TRANSFORM', 'TRANSFORM', nTi, /\boriginal.*ptr\b|\bbase.*ptr\b|\bstart.*buffer\b/i, 'TRANSFORM (free original pointer, not offset)', 'Only free pointers returned by allocation functions. Never free offset pointers.');

// META→STORAGE without CONTROL (2)
export const verifyCWE8 = v('CWE-8', 'J2EE Misconfiguration: Entity Bean Declared Remote', 'medium', 'META', 'STORAGE', nC, /\blocal\b|\bnot.*remote\b/i, 'CONTROL (entity beans should be local, not remote)', 'Declare entity beans as local. Remote entity beans have performance and security issues.');
export const verifyCWE831 = v('CWE-831', 'Signal Handler Function Associated with Multiple Signals', 'medium', 'META', 'STORAGE', nC, /\bseparate.*handler\b|\bdedicated\b|\bper.*signal\b/i, 'CONTROL (dedicated handlers per signal)', 'Use dedicated signal handlers for each signal. Shared handlers have race conditions.');

// ===========================================================================
// 1-CWE SHAPES (singletons)
// ===========================================================================

export const verifyCWE102 = v('CWE-102', 'Struts: Duplicate Validation Forms', 'medium', 'META', 'INGRESS', nC, /\bunique\b|\bno.*duplicate\b|\bdedup\b/i, 'CONTROL (unique validation form names)', 'Ensure unique names for Struts validation forms.');
export const verifyCWE12 = v('CWE-12', 'ASP.NET Misconfiguration: Missing Custom Error Page', 'low', 'META', 'EGRESS', nM, D, 'META (custom error pages configured)', 'Configure custom error pages. Default pages expose server details.');
export const verifyCWE15 = v('CWE-15', 'External Control of System or Configuration Setting', 'high', 'INGRESS', 'META', nC, V, 'CONTROL (configuration modification restriction)', 'Do not allow external input to modify system configuration.');
export const verifyCWE221 = v('CWE-221', 'Information Loss or Omission', 'medium', 'CONTROL', 'EGRESS', nSt, /\bcomplete\b|\bfull\b|\bno.*omit\b/i, 'STORAGE (complete information in audit/security events)', 'Include complete context in security events. Omissions prevent incident analysis.');
export const verifyCWE223 = v('CWE-223', 'Omission of Security-relevant Information', 'medium', 'AUTH', 'EGRESS', nSt, /\baudit\b|\blog\b|\brecord\b/i, 'STORAGE (security event logging)', 'Log all security-relevant events: auth failures, access denials, privilege changes.');
export const verifyCWE258 = v('CWE-258', 'Empty Password in Configuration File', 'high', 'STORAGE', 'AUTH', nC, /\brequired\b|\bmin.*length\b|\breject.*empty\b/i, 'CONTROL (reject empty passwords)', 'Reject empty passwords in configuration. Require minimum password length.');
export const verifyCWE259 = v('CWE-259', 'Use of Hard-coded Password', 'critical', 'STRUCTURAL', 'AUTH', nC, /\benv\b|\bvault\b|\bsecret.*manager\b/i, 'CONTROL (no hard-coded passwords — use env/vault)', 'Never hard-code passwords. Use environment variables or secret managers.');
export const verifyCWE286 = v('CWE-286', 'Incorrect User Management', 'high', 'STRUCTURAL', 'AUTH', nA, A, 'AUTH (correct user management — proper provisioning/deprovisioning)', 'Implement proper user lifecycle management. Deactivate unused accounts.');
export const verifyCWE303 = v('CWE-303', 'Incorrect Implementation of Authentication Algorithm', 'critical', 'AUTH', 'CONTROL', nM, /\bstandard\b|\bproven\b|\bNIST\b|\bOAuth\b|\bOIDC\b/i, 'META (use standard authentication algorithms)', 'Use proven auth algorithms (OAuth2, OIDC). Do not implement custom authentication.');
export const verifyCWE321 = v('CWE-321', 'Use of Hard-coded Cryptographic Key', 'critical', 'META', 'TRANSFORM', nE, /\benv\b|\bvault\b|\bKMS\b|\bsecret.*manager\b/i, 'EXTERNAL (key management service — no hard-coded keys)', 'Never hard-code crypto keys. Use KMS, vault, or environment variables.');
export const verifyCWE335 = v('CWE-335', 'Incorrect Usage of Seeds in PRNG', 'high', 'INGRESS', 'TRANSFORM', nE, CR, 'EXTERNAL (CSPRNG / hardware entropy source)', 'Use system CSPRNG for seeding. Do not derive seeds from user input.');
export const verifyCWE336 = v('CWE-336', 'Same Seed in PRNG', 'high', 'STORAGE', 'TRANSFORM', nE, /\bunique.*seed\b|\bper.*instance\b|\brandom.*seed\b/i, 'EXTERNAL (unique seed per instance from CSPRNG)', 'Use unique seeds per PRNG instance. Same seeds produce same output.');
export const verifyCWE338 = v('CWE-338', 'Use of Cryptographically Weak PRNG', 'high', 'TRANSFORM', 'AUTH', nE, CR, 'EXTERNAL (CSPRNG for security-critical values)', 'Use crypto.randomBytes or getRandomValues for security. Math.random is not cryptographically secure.');
export const verifyCWE341 = v('CWE-341', 'Predictable from Observable State', 'high', 'EXTERNAL', 'AUTH', nT, CR, 'TRANSFORM (CSPRNG — not derived from observable state)', 'Do not derive security values from observable state (PID, time, counters). Use CSPRNG.');
export const verifyCWE344 = v('CWE-344', 'Use of Invariant Value in Dynamically Changing Context', 'medium', 'INGRESS', 'AUTH', nE, /\bdynamic\b|\bfresh\b|\brotate\b|\bper.*request\b/i, 'EXTERNAL (dynamic values from secure source)', 'Use fresh, dynamic values for each context. Do not reuse tokens across sessions.');
export const verifyCWE348 = v('CWE-348', 'Use of Less Trusted Source', 'medium', 'INGRESS', 'AUTH', nM, /\btrusted.*source\b|\bverif.*origin\b|\bprimary\b/i, 'META (trust source verification)', 'Use the most trusted source for security decisions. Verify source reliability.');
export const verifyCWE356 = v('CWE-356', 'Product UI does not Warn User of Unsafe Actions', 'medium', 'INGRESS', 'CONTROL', nM, /\bwarn\b|\bconfirm\b|\bdialog\b|\bprompt\b/i, 'META (user warning for unsafe actions)', 'Warn users before destructive or irreversible actions. Require confirmation.');
export const verifyCWE357 = v('CWE-357', 'Insufficient UI Warning of Dangerous Operations', 'medium', 'META', 'CONTROL', nM, /\bwarn\b|\bconfirm\b|\bhighlight\b/i, 'META (clear danger warnings in UI)', 'Clearly indicate dangerous operations in the UI. Use confirmation dialogs.');
export const verifyCWE370 = v('CWE-370', 'Missing Check for Certificate Revocation after Initial Check', 'high', 'AUTH', 'CONTROL', nA, /\bOCSP\b|\bCRL\b|\bperiodic.*check\b|\bstapl\b/i, 'AUTH (periodic certificate revocation checking)', 'Re-check certificate revocation periodically, not just at initial connection.');
export const verifyCWE397 = v('CWE-397', 'Declaration of Throws for Generic Exception', 'low', 'TRANSFORM', 'EGRESS', nEg, /\bspecific.*exception\b|\btyped.*error\b/i, 'EGRESS (specific exception types in throws declarations)', 'Declare specific exception types. Generic throws hides failure modes.');
export const verifyCWE403 = v('CWE-403', 'Exposure of File Descriptor to Unintended Control Sphere (Descriptor Leak)', 'medium', 'STORAGE', 'EXTERNAL', nC, /\bclose.*exec\b|\bFD_CLOEXEC\b|\bO_CLOEXEC\b/i, 'CONTROL (close-on-exec flag for file descriptors)', 'Set FD_CLOEXEC/O_CLOEXEC on file descriptors. Prevents leaking to child processes.');
export const verifyCWE414 = v('CWE-414', 'Missing Lock Check', 'medium', 'STRUCTURAL', 'TRANSFORM', nC, L, 'CONTROL (lock status check before critical operations)', 'Check lock status before critical operations.');
export const verifyCWE419 = v('CWE-419', 'Unprotected Primary Channel', 'high', 'INGRESS', 'AUTH', nS, /\bTLS\b|\bhttps\b|\bencrypt\b/i, 'STRUCTURAL (encrypted primary channel)', 'Protect primary communication channels with TLS/HTTPS.');
export const verifyCWE421 = v('CWE-421', 'Race Condition During Access to Alternate Channel', 'medium', 'STRUCTURAL', 'INGRESS', nC, L, 'CONTROL (synchronized alternate channel access)', 'Synchronize access to alternate channels. Prevent race conditions between channels.');
export const verifyCWE446 = v('CWE-446', 'UI Discrepancy for Security Feature', 'medium', 'EGRESS', 'CONTROL', nT, /\bconsistent.*ui\b|\baccurate.*display\b/i, 'TRANSFORM (accurate UI representation of security state)', 'Ensure UI accurately represents security state. Discrepancies mislead users.');
export const verifyCWE447 = v('CWE-447', 'Unimplemented or Unsupported Feature in UI', 'medium', 'EGRESS', 'CONTROL', nS, /\bdisable\b|\bhide\b|\bremove\b/i, 'STRUCTURAL (remove/disable unimplemented security features from UI)', 'Remove UI elements for unimplemented features. Fake security controls are dangerous.');
export const verifyCWE448 = v('CWE-448', 'Obsolete Feature in UI', 'low', 'EGRESS', 'STRUCTURAL', nM, /\bremove\b|\bdeprecate\b|\bupdate\b/i, 'META (remove obsolete UI features)', 'Remove obsolete features from the UI.');
export const verifyCWE450 = v('CWE-450', 'Multiple Interpretations of UI Input', 'medium', 'INGRESS', 'CONTROL', nEg, V, 'EGRESS (unambiguous input interpretation)', 'Ensure inputs have only one interpretation. Ambiguity enables injection.');
export const verifyCWE455 = v('CWE-455', 'Non-exit on Failed Initialization', 'medium', 'STRUCTURAL', 'CONTROL', nCi, /\bexit\b|\bfail.*fast\b|\babort\b|\bthrow\b/i, 'CONTROL (exit/abort on failed initialization)', 'Exit on initialization failure. Running in partially initialized state is dangerous.');
export const verifyCWE480 = v('CWE-480', 'Use of Incorrect Operator', 'medium', 'TRANSFORM', 'CONTROL', nM, /\blint\b|\bstatic.*analysis\b|\b===\b/i, 'META (linting for operator errors)', 'Use linting to catch operator errors (= vs ==, & vs &&, | vs ||).');
export const verifyCWE481 = v('CWE-481', 'Assigning instead of Comparing', 'medium', 'TRANSFORM', 'CONTROL', nTi, /\b===\b|\blint\b|\bno-cond-assign\b/i, 'TRANSFORM (comparison, not assignment, in conditions)', 'Use === in conditions, not =. Enable no-cond-assign lint rule.');
export const verifyCWE483 = v('CWE-483', 'Incorrect Block Delimitation', 'medium', 'CONTROL', 'STRUCTURAL', nS, /\b\{\b|\bbraces\b|\bcurly\b|\blint\b/i, 'STRUCTURAL (explicit block delimiters — always use braces)', 'Always use braces for control flow blocks. Incorrect delimitation causes logic errors.');
export const verifyCWE486 = v('CWE-486', 'Comparison of Classes by Name', 'medium', 'EXTERNAL', 'CONTROL', nA, /\binstanceof\b|\bgetClass\b|\btype.*check\b/i, 'AUTH (use instanceof, not class name comparison)', 'Use instanceof for class comparison. Name comparison can be spoofed.');
export const verifyCWE5 = v('CWE-5', 'J2EE Misconfiguration: Data Transmission Without Encryption', 'high', 'STORAGE', 'EGRESS', nE, E, 'EXTERNAL (encrypted data transmission)', 'Encrypt all data in transit. Configure transport-guarantee CONFIDENTIAL.');
export const verifyCWE511 = v('CWE-511', 'Logic/Time Bomb', 'critical', 'CONTROL', 'TRANSFORM', nM, /\baudit\b|\breview\b|\bno.*time.*bomb\b/i, 'META (code audit for logic/time bombs)', 'Audit for time-triggered or condition-triggered malicious code.');
export const verifyCWE531 = v('CWE-531', 'Inclusion of Sensitive Information in Test Code', 'medium', 'STRUCTURAL', 'EGRESS', nM, /\bno.*secret.*test\b|\bmock\b|\benv\b/i, 'META (no real credentials in test code)', 'Use mock credentials in tests. Never commit real secrets in test files.');
export const verifyCWE540 = v('CWE-540', 'Inclusion of Sensitive Information in Source Code', 'medium', 'META', 'EGRESS', nA, /\benv\b|\bvault\b|\bno.*hardcode\b/i, 'AUTH (no sensitive data in source code)', 'Move sensitive data to environment variables or secret managers.');
export const verifyCWE544 = v('CWE-544', 'Missing Standardized Error Handling Mechanism', 'medium', 'CONTROL', 'EGRESS', nS, /\btry\b|\bcatch\b|\berror.*handler\b|\bmiddleware\b/i, 'STRUCTURAL (standardized error handling mechanism)', 'Implement a centralized error handling mechanism. Use error middleware.');
export const verifyCWE546 = v('CWE-546', 'Suspicious Comment', 'low', 'META', 'STRUCTURAL', nC, /\bno.*todo.*security\b|\breview\b|\baudit\b/i, 'CONTROL (review suspicious TODO/FIXME/HACK comments)', 'Review and resolve security-related TODO/FIXME/HACK comments before release.');
export const verifyCWE547 = v('CWE-547', 'Use of Hard-coded, Security-relevant Constants', 'medium', 'META', 'AUTH', nSt, /\bconfig\b|\benv\b|\bconfigurable\b/i, 'STORAGE (configurable security constants — not hard-coded)', 'Make security constants configurable. Hard-coded values cannot be updated without redeployment.');
export const verifyCWE563 = v('CWE-563', 'Assignment to Variable without Use', 'low', 'TRANSFORM', 'STORAGE', nEg, /\bused\b|\blint\b|\bno-unused\b/i, 'EGRESS (remove unused variable assignments)', 'Remove unused assignments. They may indicate logic errors or incomplete implementation.');
export const verifyCWE571 = v('CWE-571', 'Expression is Always True', 'low', 'CONTROL', 'STRUCTURAL', nCi, /\blint\b|\bstatic.*analysis\b|\bcorrect\b/i, 'CONTROL (correct conditional expressions)', 'Fix always-true expressions. They indicate logic errors or dead branches.');
export const verifyCWE574 = v('CWE-574', 'EJB Bad Practices: Use of Synchronization Primitives', 'medium', 'STRUCTURAL', 'CONTROL', nE, /\bcontainer.*managed\b|\bno.*sync.*ejb\b/i, 'EXTERNAL (container-managed concurrency)', 'Do not use synchronization primitives in EJBs. Container manages concurrency.');
export const verifyCWE579 = v('CWE-579', 'J2EE Bad Practices: Non-serializable Object Stored in Session', 'medium', 'TRANSFORM', 'STORAGE', nS, /\bSerializable\b|\bjson\b|\bserializ\b/i, 'STRUCTURAL (serializable session objects)', 'Ensure all session objects implement Serializable for J2EE session replication.');
export const verifyCWE580 = v('CWE-580', 'clone() Method Without super.clone()', 'low', 'STRUCTURAL', 'TRANSFORM', nE, /\bsuper\.clone\b/i, 'EXTERNAL (call super.clone() in clone implementations)', 'Always call super.clone() in clone() overrides.');
export const verifyCWE581 = v('CWE-581', 'Object Model Violation: Just One of Equals and Hashcode Defined', 'medium', 'STRUCTURAL', 'TRANSFORM', nTi, /\bequals\b.*\bhashCode\b|\bboth\b|\bpair\b/i, 'TRANSFORM (implement both equals and hashCode)', 'Override both equals() and hashCode() together. Violating this contract breaks collections.');
export const verifyCWE585 = v('CWE-585', 'Empty Synchronized Block', 'low', 'CONTROL', 'STRUCTURAL', nT, /\bno.*empty.*sync\b|\blint\b/i, 'TRANSFORM (meaningful synchronized block content)', 'Do not use empty synchronized blocks. They do not guarantee happens-before ordering as expected.');
export const verifyCWE591 = v('CWE-591', 'Sensitive Data Storage in Improperly Locked Memory', 'high', 'STORAGE', 'STRUCTURAL', nC, /\bmlock\b|\bVirtualLock\b|\bpinned\b/i, 'CONTROL (memory locking for sensitive data — mlock/VirtualLock)', 'Lock memory pages containing secrets to prevent swapping to disk.');
export const verifyCWE599 = v('CWE-599', 'Missing Validation of OpenSSL Certificate', 'critical', 'EXTERNAL', 'INGRESS', nA, /\brejectUnauthorized\b|\bverif.*cert\b|\bca\b.*\bcert\b/i, 'AUTH (SSL certificate validation — rejectUnauthorized: true)', 'Enable certificate validation. Set rejectUnauthorized: true. Never disable in production.');
export const verifyCWE612 = v('CWE-612', 'Improper Authorization of Index Containing Sensitive Information', 'medium', 'INGRESS', 'EGRESS', nA, A, 'AUTH (authorization for search indexes containing sensitive data)', 'Apply access controls to search indexes. Index contents inherit the sensitivity of source data.');
export const verifyCWE636 = v('CWE-636', 'Not Failing Securely (Fail Open)', 'high', 'CONTROL', 'EGRESS', nA, /\bfail.*close\b|\bfail.*secure\b|\bdeny.*default\b/i, 'AUTH (fail-secure — deny by default on error)', 'Fail securely: deny access on error, not grant. Default-deny policy.');
export const verifyCWE637 = v('CWE-637', 'Unnecessary Complexity in Protection Mechanism', 'medium', 'STRUCTURAL', 'AUTH', nM, /\bsimple\b|\bminimal\b|\bwell.*tested\b/i, 'META (simple, well-tested security mechanisms)', 'Keep security mechanisms simple. Complex mechanisms have more bugs.');
export const verifyCWE651 = v('CWE-651', 'Exposure of WSDL File Containing Sensitive Information', 'medium', 'STRUCTURAL', 'EGRESS', nA, /\brestrict\b|\bblock\b|\bno.*public.*wsdl\b/i, 'AUTH (restrict WSDL access)', 'Restrict access to WSDL files. They expose API structure to attackers.');
export const verifyCWE672 = v('CWE-672', 'Operation on a Resource after Expiration or Release', 'high', 'CONTROL', 'TRANSFORM', nTi, /\bvalid\b|\bexpir\b|\breleased\b.*\bcheck\b/i, 'TRANSFORM (resource validity check before operation)', 'Check resource validity before use. Released/expired resources cause undefined behavior.');
export const verifyCWE684 = v('CWE-684', 'Failure to Provide Specified Functionality', 'medium', 'TRANSFORM', 'EGRESS', nM, /\bspec\b|\bcontract\b|\btest\b|\bverif\b/i, 'META (specification compliance verification)', 'Verify implementation matches specification. Test all specified functionality.');
export const verifyCWE7 = v('CWE-7', 'J2EE Misconfiguration: Missing Custom Error Handling', 'low', 'CONTROL', 'EGRESS', nM, /\bcustom.*error\b|\berror.*page\b|\berror.*handler\b/i, 'META (custom error handling configuration)', 'Configure custom error handlers. Default error pages leak information.');
export const verifyCWE708 = v('CWE-708', 'Incorrect Ownership Assignment', 'medium', 'CONTROL', 'EXTERNAL', nCi, /\bowner\b|\bchown\b|\bcorrect.*ownership\b/i, 'CONTROL (correct ownership assignment)', 'Verify ownership assignments. Incorrect ownership grants unauthorized access.');
export const verifyCWE763 = v('CWE-763', 'Release of Invalid Pointer or Reference', 'critical', 'TRANSFORM', 'STORAGE', nTi, /\bvalid.*ptr\b|\bnull.*check\b|\bheap.*check\b/i, 'TRANSFORM (pointer validity check before release)', 'Validate pointers before freeing. Never free invalid, stack, or static pointers.');
export const verifyCWE783 = v('CWE-783', 'Operator Precedence Logic Error', 'medium', 'CONTROL', 'AUTH', nCi, /\bparenthes\b|\bexplicit.*group\b|\blint\b/i, 'CONTROL (explicit parentheses in security expressions)', 'Use explicit parentheses in security-relevant expressions. Precedence errors cause auth bypasses.');
export const verifyCWE798_gen = v('CWE-798', 'Use of Hard-coded Credentials (structural)', 'critical', 'STRUCTURAL', 'AUTH', nSt, /\benv\b|\bvault\b|\bsecret.*manager\b/i, 'STORAGE (credentials in secret storage, not source)', 'Move credentials to vault/env. Never commit to source control.');
export const verifyCWE824_gen = v('CWE-824', 'Access of Uninitialized Pointer', 'critical', 'STRUCTURAL', 'STORAGE', nT, /\binit\b|\bnull\b|\b=\s/i, 'TRANSFORM (pointer initialization before use)', 'Initialize all pointers before use. Null-initialize if no value is available yet.');
export const verifyCWE832 = v('CWE-832', 'Unlock of a Resource that is not Locked', 'medium', 'CONTROL', 'STORAGE', nCi, /\block.*state\b|\bis.*locked\b|\bbalanced\b/i, 'CONTROL (lock state tracking — only unlock what was locked)', 'Track lock state. Only unlock resources you hold the lock for.');
export const verifyCWE9 = v('CWE-9', 'J2EE Misconfiguration: Weak Access Permissions for EJB Methods', 'medium', 'META', 'EXTERNAL', nC, /\brestrict\b|\bdeny\b|\brole.*based\b/i, 'CONTROL (restrictive EJB method permissions)', 'Set restrictive permissions on EJB methods. Do not leave methods unprotected.');
export const verifyCWE923 = v('CWE-923', 'Improper Restriction of Communication Channel to Intended Endpoints', 'high', 'EGRESS', 'EXTERNAL', nA, /\ballowlist\b|\bwhitelist\b|\bendpoint.*valid\b/i, 'AUTH (endpoint restriction — allowlist of permitted destinations)', 'Restrict outbound communication to allowlisted endpoints. Prevent data exfiltration.');
export const verifyCWE926 = v('CWE-926', 'Improper Export of Android Application Components', 'high', 'STRUCTURAL', 'INGRESS', nA, /\bexported.*false\b|\bpermission\b|\bintent.*filter\b.*\brestrict\b/i, 'AUTH (restrict exported Android components)', 'Set android:exported=false for internal components. Require permissions for exported ones.');

// ===========================================================================
// REGISTRY
// ===========================================================================

export const BATCH_016_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  // 4-CWE shapes
  'CWE-322': verifyCWE322, 'CWE-494': verifyCWE494, 'CWE-618': verifyCWE618, 'CWE-749': verifyCWE749,
  'CWE-437': verifyCWE437, 'CWE-475': verifyCWE475, 'CWE-593': verifyCWE593, 'CWE-605': verifyCWE605,
  'CWE-665': verifyCWE665, 'CWE-908': verifyCWE908, 'CWE-909': verifyCWE909, 'CWE-910': verifyCWE910,
  'CWE-683': verifyCWE683, 'CWE-685': verifyCWE685, 'CWE-686': verifyCWE686, 'CWE-688': verifyCWE688,
  // 3-CWE shapes
  'CWE-204': verifyCWE204, 'CWE-206': verifyCWE206, 'CWE-208': verifyCWE208,
  'CWE-207': verifyCWE207, 'CWE-210': verifyCWE210, 'CWE-459': verifyCWE459,
  'CWE-211': verifyCWE211, 'CWE-573': verifyCWE573, 'CWE-589': verifyCWE589,
  'CWE-226': verifyCWE226, 'CWE-374': verifyCWE374, 'CWE-590': verifyCWE590,
  'CWE-243': verifyCWE243, 'CWE-276': verifyCWE276, 'CWE-277': verifyCWE277,
  'CWE-245': verifyCWE245, 'CWE-246': verifyCWE246, 'CWE-586': verifyCWE586,
  // 2-CWE shapes
  'CWE-6': verifyCWE6, 'CWE-109': verifyCWE109, 'CWE-120': verifyCWE120, 'CWE-806': verifyCWE806,
  'CWE-188': verifyCWE188, 'CWE-431': verifyCWE431, 'CWE-213': verifyCWE213, 'CWE-512': verifyCWE512,
  'CWE-242': verifyCWE242, 'CWE-410': verifyCWE410, 'CWE-256': verifyCWE256, 'CWE-257': verifyCWE257,
  'CWE-261': verifyCWE261, 'CWE-842': verifyCWE842, 'CWE-262': verifyCWE262, 'CWE-671': verifyCWE671,
  'CWE-263': verifyCWE263, 'CWE-556': verifyCWE556, 'CWE-282': verifyCWE282, 'CWE-283': verifyCWE283,
  'CWE-394': verifyCWE394, 'CWE-440': verifyCWE440, 'CWE-441': verifyCWE441, 'CWE-566': verifyCWE566,
  'CWE-453': verifyCWE453, 'CWE-456': verifyCWE456, 'CWE-477': verifyCWE477, 'CWE-695': verifyCWE695,
  'CWE-484': verifyCWE484, 'CWE-543': verifyCWE543, 'CWE-553': verifyCWE553, 'CWE-673': verifyCWE673,
  'CWE-561': verifyCWE561, 'CWE-570': verifyCWE570, 'CWE-572': verifyCWE572, 'CWE-576': verifyCWE576,
  'CWE-578': verifyCWE578, 'CWE-766': verifyCWE766, 'CWE-584': verifyCWE584, 'CWE-698': verifyCWE698,
  'CWE-628': verifyCWE628, 'CWE-653': verifyCWE653, 'CWE-666': verifyCWE666, 'CWE-761': verifyCWE761,
  'CWE-8': verifyCWE8, 'CWE-831': verifyCWE831,
  // 1-CWE singletons
  'CWE-102': verifyCWE102, 'CWE-12': verifyCWE12, 'CWE-15': verifyCWE15, 'CWE-221': verifyCWE221,
  'CWE-223': verifyCWE223, 'CWE-258': verifyCWE258, 'CWE-259': verifyCWE259, 'CWE-286': verifyCWE286,
  'CWE-303': verifyCWE303, 'CWE-321': verifyCWE321, 'CWE-335': verifyCWE335, 'CWE-336': verifyCWE336,
  'CWE-338': verifyCWE338, 'CWE-341': verifyCWE341, 'CWE-344': verifyCWE344, 'CWE-348': verifyCWE348,
  'CWE-356': verifyCWE356, 'CWE-357': verifyCWE357, 'CWE-370': verifyCWE370, 'CWE-397': verifyCWE397,
  'CWE-403': verifyCWE403, 'CWE-414': verifyCWE414, 'CWE-419': verifyCWE419, 'CWE-421': verifyCWE421,
  'CWE-446': verifyCWE446, 'CWE-447': verifyCWE447, 'CWE-448': verifyCWE448, 'CWE-450': verifyCWE450,
  'CWE-455': verifyCWE455, 'CWE-480': verifyCWE480, 'CWE-481': verifyCWE481, 'CWE-483': verifyCWE483,
  'CWE-486': verifyCWE486, 'CWE-5': verifyCWE5, 'CWE-511': verifyCWE511, 'CWE-531': verifyCWE531,
  'CWE-540': verifyCWE540, 'CWE-544': verifyCWE544, 'CWE-546': verifyCWE546, 'CWE-547': verifyCWE547,
  'CWE-563': verifyCWE563, 'CWE-571': verifyCWE571, 'CWE-574': verifyCWE574, 'CWE-579': verifyCWE579,
  'CWE-580': verifyCWE580, 'CWE-581': verifyCWE581, 'CWE-585': verifyCWE585, 'CWE-591': verifyCWE591,
  'CWE-599': verifyCWE599, 'CWE-612': verifyCWE612, 'CWE-636': verifyCWE636, 'CWE-637': verifyCWE637,
  'CWE-651': verifyCWE651, 'CWE-672': verifyCWE672, 'CWE-684': verifyCWE684, 'CWE-7': verifyCWE7,
  'CWE-708': verifyCWE708, 'CWE-763': verifyCWE763, 'CWE-783': verifyCWE783,
  'CWE-798': verifyCWE798_gen, 'CWE-824': verifyCWE824_gen, 'CWE-832': verifyCWE832,
  'CWE-9': verifyCWE9, 'CWE-923': verifyCWE923, 'CWE-926': verifyCWE926,
};
