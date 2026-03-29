/**
 * DST Generated Verifiers — Batch 007
 * Pattern shape: TRANSFORM→TRANSFORM without CONTROL
 * 18 CWEs: memory management, error handling, crypto, type safety.
 *
 * One transform's output feeds another transform without a CONTROL
 * node validating the intermediate value. These are internal logic
 * errors — buffer size miscalculations, use-after-free, type confusion.
 */

import type { NeuralMap, NeuralMapNode } from '../types';
import {
  nodeRef, nodesOfType, hasTaintedPathWithoutControl,
  type VerificationResult, type Finding, type Severity,
} from './_helpers';

// ---------------------------------------------------------------------------
// Sink/source filters — TRANSFORM nodes by category
// ---------------------------------------------------------------------------

function memoryTransformNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('memory') || n.node_subtype.includes('alloc') ||
     n.node_subtype.includes('free') || n.node_subtype.includes('pointer') ||
     n.node_subtype.includes('buffer') || n.attack_surface.includes('memory') ||
     n.code_snapshot.match(
       /\b(malloc|calloc|realloc|free|delete|new\s|sizeof|memcpy|memmove|Buffer\.(alloc|from)|slice|subarray)\b/i
     ) !== null)
  );
}

function computeTransformNodes(map: NeuralMap): NeuralMapNode[] {
  return map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('compute') || n.node_subtype.includes('calculate') ||
     n.node_subtype.includes('arithmetic') || n.node_subtype.includes('call') ||
     n.code_snapshot.match(
       /\b(Math\.|parseInt|parseFloat|Number\(|\.length|\*|\+|\/|%|<<|>>)\b/i
     ) !== null)
  );
}

// ---------------------------------------------------------------------------
// Safe pattern constants
// ---------------------------------------------------------------------------

const SIZE_CHECK_SAFE = /\bsizeof\b.*\bcheck\b|\blength\b.*[<>]=?|\bbounds\b|\bvalidate.*size\b|\bMath\.min\b|\bclamp\b|\bSIZE_MAX\b/i;
const NULL_TERM_SAFE = /\b\\0\b|\bnull.*terminat\b|\bstrlen\b.*\+\s*1|\b\+ 1\b.*\bnull\b|\bstrlcpy\b|\bsnprintf\b/i;
const PTR_VALID_SAFE = /\bnull\b.*check|\b!==?\s*null\b|\bif\s*\(\s*\w+\s*\)|\bptr.*valid\b|\bweakRef\b/i;
const DOUBLE_FREE_SAFE = /\bnull\b.*after.*free|\bptr\s*=\s*null|\bdelete.*null|\bpointer.*invalidat\b|\bonce\b/i;
const RECURSION_SAFE = /\bdepth\b|\bmax.*recurs\b|\bbase.*case\b|\bstack.*limit\b|\btail.*call\b|\biterative\b/i;
const RETURN_CHECK_SAFE = /\bif\s*\(\s*\w+\s*[!=]==?\s*null\b|\berror\b.*check|\breturn.*check|\bthrow\b|\bassert\b|\b!==?\s*undefined\b/i;
const TYPE_CHECK_SAFE = /\btypeof\b|\binstanceof\b|\btype.*check\b|\btype.*guard\b|\bass?ert.*type\b|\btype.*valid\b/i;
const IV_SAFE = /\bcrypto\.random\b|\brandomBytes\b|\bgetRandomValues\b|\bCSPRNG\b|\bnonce.*random\b|\biv.*random\b/i;
const EXCEPTION_SAFE = /\btry\b|\bcatch\b|\bfinally\b|\bthrow\b|\berror\b.*handl|\bcheck.*condition\b|\bassert\b/i;

// ---------------------------------------------------------------------------
// Factory: TRANSFORM→TRANSFORM without CONTROL
// ---------------------------------------------------------------------------

function createTransformTransformVerifier(
  cweId: string, cweName: string, severity: Severity,
  sourceFilter: (map: NeuralMap) => NeuralMapNode[],
  sinkFilter: (map: NeuralMap) => NeuralMapNode[],
  safePattern: RegExp,
  missingDesc: string,
  fixDesc: string,
): (map: NeuralMap) => VerificationResult {
  return (map: NeuralMap): VerificationResult => {
    const findings: Finding[] = [];
    const sources = sourceFilter(map);
    const sinks = sinkFilter(map);

    for (const src of sources) {
      for (const sink of sinks) {
        if (src.id === sink.id) continue;
        if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
          if (!safePattern.test(sink.code_snapshot) && !safePattern.test(src.code_snapshot)) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: missingDesc,
              severity,
              description: `Operation at ${src.label} feeds ${sink.label} without validation. ` +
                `Vulnerable to ${cweName}.`,
              fix: fixDesc,
            });
          }
        }
      }
    }

    return { cwe: cweId, name: cweName, holds: findings.length === 0, findings };
  };
}

// ===========================================================================
// MEMORY/POINTER (10 CWEs)
// ===========================================================================

export const verifyCWE131 = createTransformTransformVerifier(
  'CWE-131', 'Incorrect Calculation of Buffer Size', 'critical',
  computeTransformNodes, memoryTransformNodes, SIZE_CHECK_SAFE,
  'CONTROL (buffer size validation — account for null terminator, encoding expansion, overflow)',
  'Validate calculated buffer sizes: account for null terminators (+1), multi-byte encoding expansion, ' +
    'and check for integer overflow in size * count. Use checked arithmetic.',
);

export const verifyCWE170 = createTransformTransformVerifier(
  'CWE-170', 'Improper Null Termination', 'high',
  memoryTransformNodes, memoryTransformNodes, NULL_TERM_SAFE,
  'CONTROL (null terminator validation — ensure strings are properly terminated)',
  'Always allocate space for and set the null terminator. Use strncpy with explicit termination. ' +
    'Prefer strlcpy/snprintf which guarantee null termination.',
);

export const verifyCWE415 = createTransformTransformVerifier(
  'CWE-415', 'Double Free', 'critical',
  memoryTransformNodes, memoryTransformNodes, DOUBLE_FREE_SAFE,
  'CONTROL (free-once enforcement — nullify pointer after free)',
  'Set pointers to NULL after freeing. Check for NULL before free. ' +
    'Use RAII/smart pointers to automate lifetime management.',
);

export const verifyCWE416 = createTransformTransformVerifier(
  'CWE-416', 'Use After Free', 'critical',
  memoryTransformNodes, memoryTransformNodes, PTR_VALID_SAFE,
  'CONTROL (pointer validity check — no dereference after free)',
  'Nullify pointers after freeing. Check validity before dereference. ' +
    'Use smart pointers (unique_ptr, shared_ptr) to prevent use-after-free.',
);

export const verifyCWE466 = createTransformTransformVerifier(
  'CWE-466', 'Return of Pointer Value Outside of Expected Range', 'high',
  memoryTransformNodes, computeTransformNodes, PTR_VALID_SAFE,
  'CONTROL (pointer range validation)',
  'Validate returned pointer values are within expected buffer bounds. ' +
    'Check that pointer arithmetic results stay within [buffer_start, buffer_end).',
);

export const verifyCWE467 = createTransformTransformVerifier(
  'CWE-467', 'Use of sizeof() on a Pointer Type', 'medium',
  computeTransformNodes, memoryTransformNodes,
  /\bsizeof\b.*\b\*\b|\bsizeof\b.*\barray\b|\bsizeof\b.*\bstruct\b|\bARRAY_SIZE\b|\bstd::size\b/i,
  'CONTROL (sizeof applied to correct type — array, not pointer)',
  'Use sizeof on the array/struct, not on a pointer. sizeof(ptr) returns pointer size (4/8), ' +
    'not the buffer size. Use ARRAY_SIZE macro or std::size for arrays.',
);

export const verifyCWE468 = createTransformTransformVerifier(
  'CWE-468', 'Incorrect Pointer Scaling', 'high',
  computeTransformNodes, memoryTransformNodes,
  /\bsizeof\b.*\belement\b|\bbyte.*offset\b|\bchar\s*\*.*\barithmetic\b|\bvoid\s*\*\b.*\bcast\b/i,
  'CONTROL (explicit element-size accounting in pointer arithmetic)',
  'Remember that pointer arithmetic auto-scales by element size. ' +
    'Cast to char* for byte-level offsets. Do not manually multiply by sizeof.',
);

export const verifyCWE469 = createTransformTransformVerifier(
  'CWE-469', 'Use of Pointer Subtraction to Determine Size', 'medium',
  computeTransformNodes, memoryTransformNodes,
  /\bptrdiff_t\b|\bsame.*array\b|\bvalidate.*pointer\b|\boffsetof\b/i,
  'CONTROL (pointer subtraction validity — same allocation block)',
  'Only subtract pointers within the same allocation block. The result of subtracting ' +
    'pointers from different allocations is undefined behavior. Use ptrdiff_t for the result type.',
);

export const verifyCWE680 = createTransformTransformVerifier(
  'CWE-680', 'Integer Overflow to Buffer Overflow', 'critical',
  computeTransformNodes, memoryTransformNodes,
  /\bchecked.*multiply\b|\boverflow.*check\b|\bSIZE_MAX\b|\bsafe.*mul\b|\bMath\.min\b.*\bMAX\b/i,
  'CONTROL (integer overflow check before using result as buffer size)',
  'Check for integer overflow before using arithmetic results as allocation sizes. ' +
    'Use checked multiplication: if (a > SIZE_MAX / b) reject. Use safe_mul helpers.',
);

export const verifyCWE762 = createTransformTransformVerifier(
  'CWE-762', 'Mismatched Memory Management Routines', 'high',
  memoryTransformNodes, memoryTransformNodes,
  /\bmalloc\b.*\bfree\b|\bnew\b.*\bdelete\b|\bnew\[\]\b.*\bdelete\[\]\b|\bmatched\b|\bpaired\b/i,
  'CONTROL (matched allocation/deallocation pairs)',
  'Match allocation and deallocation routines: malloc↔free, new↔delete, new[]↔delete[]. ' +
    'Mixing them (e.g., free on new\'d memory) causes undefined behavior.',
);

// ===========================================================================
// ERROR/LOGIC (5 CWEs)
// ===========================================================================

export const verifyCWE674 = createTransformTransformVerifier(
  'CWE-674', 'Uncontrolled Recursion', 'medium',
  computeTransformNodes, computeTransformNodes, RECURSION_SAFE,
  'CONTROL (recursion depth limit / base case)',
  'Enforce maximum recursion depth. Ensure all recursive paths have a base case. ' +
    'Consider iterative alternatives for deep recursion. Set stack size limits.',
);

export const verifyCWE675 = createTransformTransformVerifier(
  'CWE-675', 'Multiple Operations on Resource in Single-Operation Context', 'medium',
  memoryTransformNodes, memoryTransformNodes,
  /\bonce\b|\bsingle\b|\bidempoten\b|\block\b|\batomic\b|\bguard\b/i,
  'CONTROL (single-operation enforcement — prevent double operations)',
  'Ensure operations that should happen exactly once are not repeated. ' +
    'Use guards, locks, or idempotency checks.',
);

export const verifyCWE687 = createTransformTransformVerifier(
  'CWE-687', 'Function Call With Incorrectly Specified Argument Value', 'medium',
  computeTransformNodes, computeTransformNodes,
  /\bvalidate.*arg\b|\bcheck.*param\b|\bassert\b|\btypeof\b|\bschema\b/i,
  'CONTROL (argument validation before function call)',
  'Validate argument values before passing to functions. Check types, ranges, and constraints. ' +
    'Use TypeScript strict mode and runtime validation for critical function calls.',
);

export const verifyCWE690 = createTransformTransformVerifier(
  'CWE-690', 'Unchecked Return Value to NULL Pointer Dereference', 'high',
  computeTransformNodes, memoryTransformNodes, RETURN_CHECK_SAFE,
  'CONTROL (null check on return values before dereference)',
  'Always check return values for NULL/undefined before dereferencing. ' +
    'Functions like malloc, find, querySelector can return null — handle the null case.',
);

export const verifyCWE754 = createTransformTransformVerifier(
  'CWE-754', 'Improper Check for Unusual or Exceptional Conditions', 'medium',
  computeTransformNodes, computeTransformNodes, EXCEPTION_SAFE,
  'CONTROL (exceptional condition handling — errors, edge cases, failures)',
  'Check for and handle unusual conditions: NaN, Infinity, empty arrays, null returns, ' +
    'disk full, network timeouts. Do not assume operations always succeed.',
);

// ===========================================================================
// CRYPTO (1 CWE)
// ===========================================================================

/** CWE-329: Generation of Predictable IV/Nonce */
export function verifyCWE329(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const transforms = nodesOfType(map, 'TRANSFORM');
  const cryptoSinks = transforms.filter(n =>
    n.node_subtype.includes('encrypt') || n.node_subtype.includes('cipher') ||
    n.code_snapshot.match(/\b(createCipher|AES|CBC|encrypt|cipher|iv|nonce)\b/i) !== null
  );

  for (const src of transforms) {
    for (const sink of cryptoSinks) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (!IV_SAFE.test(src.code_snapshot) && !IV_SAFE.test(sink.code_snapshot)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (random IV/nonce generation — use CSPRNG)',
            severity: 'high',
            description: `IV/nonce at ${sink.label} may be predictable (sourced from ${src.label}). ` +
              `Predictable IVs in CBC mode enable chosen-plaintext attacks.`,
            fix: 'Generate IVs/nonces using crypto.randomBytes() or getRandomValues(). ' +
              'Never reuse IVs. Never derive IVs from predictable values. Prefer GCM over CBC.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-329', name: 'Generation of Predictable IV/Nonce', holds: findings.length === 0, findings };
}

// ===========================================================================
// TYPE SAFETY (2 CWEs)
// ===========================================================================

export const verifyCWE758 = createTransformTransformVerifier(
  'CWE-758', 'Reliance on Undefined, Unspecified, or Implementation-Defined Behavior', 'medium',
  computeTransformNodes, computeTransformNodes,
  /\bdefined\b.*\bbehavior\b|\bstandard.*compliant\b|\bportable\b|\b-Wall\b|\b-Wundefined\b|\bstrict\b/i,
  'CONTROL (defined behavior enforcement — avoid UB)',
  'Avoid operations with undefined behavior: signed overflow, null dereference, ' +
    'out-of-bounds access, use-after-free. Enable compiler warnings (-Wall -Wextra). Use sanitizers.',
);

export const verifyCWE843 = createTransformTransformVerifier(
  'CWE-843', 'Type Confusion', 'high',
  computeTransformNodes, memoryTransformNodes, TYPE_CHECK_SAFE,
  'CONTROL (type validation before type-dependent access)',
  'Validate type compatibility before casting or type-dependent access. ' +
    'Use typeof/instanceof guards. In C/C++, use safe downcasting (dynamic_cast).',
);

// ===========================================================================
// REGISTRY
// ===========================================================================

export const BATCH_007_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  // Memory/Pointer (10)
  'CWE-131': verifyCWE131,
  'CWE-170': verifyCWE170,
  'CWE-415': verifyCWE415,
  'CWE-416': verifyCWE416,
  'CWE-466': verifyCWE466,
  'CWE-467': verifyCWE467,
  'CWE-468': verifyCWE468,
  'CWE-469': verifyCWE469,
  'CWE-680': verifyCWE680,
  'CWE-762': verifyCWE762,
  // Error/Logic (5)
  'CWE-674': verifyCWE674,
  'CWE-675': verifyCWE675,
  'CWE-687': verifyCWE687,
  'CWE-690': verifyCWE690,
  'CWE-754': verifyCWE754,
  // Crypto (1)
  'CWE-329': verifyCWE329,
  // Type Safety (2)
  'CWE-758': verifyCWE758,
  'CWE-843': verifyCWE843,
};
