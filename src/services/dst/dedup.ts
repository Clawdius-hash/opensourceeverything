/**
 * CWE Deduplication — Layer 2 (Source-Sink) + Layer 3 (Family)
 *
 * LAYER 2 — Source-Sink Dedup:
 * Problem: A single CWE verifier can fire on the same (source, sink) pair
 * multiple times via different traversal paths, producing duplicate findings.
 *
 * Solution: Group findings by (CWE, source.id, sink.id, missingCategory).
 * Within each group, keep the finding with highest severity. The CWE is part
 * of the key so that different CWEs are never collapsed into each other --
 * CWE-336 (Same Seed) and CWE-338 (Weak PRNG) are distinct vulnerabilities
 * even when they fire on the same source/sink pair. Cross-CWE collapsing
 * was causing false-negative regressions on NIST Juliet benchmarks.
 *
 * LAYER 3 — Family Dedup:
 * Problem: CWE families (e.g., CWE-22 through CWE-38 for path traversal)
 * share identical detection logic. One real finding produces 10-20 duplicate
 * findings from sibling CWEs in the same family.
 *
 * Solution: When multiple members of a CWE family fire on the SAME
 * (source.id, sink.id, missingCategory), keep only the parent CWE (or the
 * lowest-numbered child if the parent didn't fire). Suppressed siblings are
 * recorded in collapsed_cwes on the surviving finding.
 *
 * CRITICAL: If only one family member fires, it is always preserved. Family
 * dedup only collapses when 2+ family members fire on the same evidence.
 *
 * Exclusions:
 *   - EFFECTIVE_CONTROL findings (second-pass) are never collapsed
 *   - Different missing categories are never collapsed (CONTROL vs TRANSFORM vs AUTH)
 *
 * Deterministic: same input always produces the same output.
 */

import type { VerificationResult, Finding } from './verifier';

// ---------------------------------------------------------------------------
// Severity ordering — higher number = higher severity
// ---------------------------------------------------------------------------

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

// ---------------------------------------------------------------------------
// Missing category extraction
// ---------------------------------------------------------------------------

/**
 * Extract the top-level category from a `missing` field.
 *
 * Examples:
 *   "CONTROL (input validation or parameterized query)" → "CONTROL"
 *   "TRANSFORM (encryption before storage)"             → "TRANSFORM"
 *   "AUTH (authentication check before sensitive op)"    → "AUTH"
 *   "META (external secret reference)"                  → "META"
 *   "RESOURCE (release/close on all code paths)"        → "RESOURCE"
 *   "EFFECTIVE_CONTROL (the control is vulnerable)"     → "EFFECTIVE_CONTROL"
 */
export function extractMissingCategory(missing: string): string {
  const match = missing.match(/^(\w+)/);
  return match ? match[1] : 'UNKNOWN';
}

// ---------------------------------------------------------------------------
// Dedup key
// ---------------------------------------------------------------------------

/**
 * Build a deterministic grouping key for a finding within a CWE result.
 * Findings with the same key are candidates for collapse.
 *
 * The CWE is included in the key so that different CWEs are NEVER collapsed
 * into each other. Only duplicate findings of the SAME CWE on the SAME
 * source/sink/category are collapsed. This prevents cross-CWE absorption
 * that caused 7 false-negative regressions on NIST Juliet (CWE-338 absorbed
 * by CWE-336, CWE-397 by CWE-248, CWE-470 by CWE-88, etc.).
 */
function dedupKey(finding: Finding, cwe: string): string {
  const category = extractMissingCategory(finding.missing);
  return `${cwe}::${finding.source.id}::${finding.sink.id}::${category}`;
}

// ---------------------------------------------------------------------------
// CWE number extraction (for tie-breaking)
// ---------------------------------------------------------------------------

function cweNumber(cwe: string): number {
  const match = cwe.match(/\d+/);
  return match ? parseInt(match[0], 10) : Infinity;
}

// ---------------------------------------------------------------------------
// Main dedup function
// ---------------------------------------------------------------------------

export interface DedupStats {
  /** Number of findings before dedup */
  before: number;
  /** Number of findings after dedup */
  after: number;
  /** Number of distinct dedup groups that had collapses */
  groupsCollapsed: number;
}

/**
 * Deduplicate verification results by (CWE, source, sink, missingCategory).
 *
 * Algorithm:
 * 1. Collect all findings from all VerificationResults where holds === false
 * 2. Exclude EFFECTIVE_CONTROL findings from dedup (different finding class)
 * 3. Group by dedupKey: CWE :: source.id :: sink.id :: missingCategory
 * 4. Within each group (same CWE only), keep highest severity
 * 5. Remove duplicate findings within the same CWE
 *
 * Different CWEs are NEVER collapsed — each CWE represents a distinct
 * vulnerability type that must be independently reportable.
 *
 * Returns a new array of VerificationResults. Does not mutate the input.
 */
export function deduplicateResults(results: VerificationResult[]): { results: VerificationResult[]; stats: DedupStats } {
  // Deep-clone results so we never mutate the input
  const out: VerificationResult[] = results.map(r => ({
    cwe: r.cwe,
    name: r.name,
    holds: r.holds,
    findings: r.findings.map(f => ({ ...f })),
  }));

  // Step 1: Collect all (cwe, finding) pairs from failed results
  interface TaggedFinding {
    cwe: string;
    cweName: string;
    finding: Finding;
    resultIndex: number;
    findingIndex: number;
  }

  const tagged: TaggedFinding[] = [];
  for (let ri = 0; ri < out.length; ri++) {
    const r = out[ri];
    if (r.holds) continue;
    for (let fi = 0; fi < r.findings.length; fi++) {
      const f = r.findings[fi];
      // Exclude EFFECTIVE_CONTROL findings from dedup
      if (extractMissingCategory(f.missing) === 'EFFECTIVE_CONTROL') continue;
      tagged.push({
        cwe: r.cwe,
        cweName: r.name,
        finding: f,
        resultIndex: ri,
        findingIndex: fi,
      });
    }
  }

  const beforeCount = tagged.length;

  // Step 2: Group by dedup key (includes CWE — no cross-CWE collapse)
  const groups = new Map<string, TaggedFinding[]>();
  for (const t of tagged) {
    const key = dedupKey(t.finding, t.cwe);
    let group = groups.get(key);
    if (!group) {
      group = [];
      groups.set(key, group);
    }
    group.push(t);
  }

  // Step 3: Within each group, pick the winner
  // Winner = highest severity, then lowest CWE number (deterministic)
  const collapsedCWEsSet = new Set<string>(); // CWEs whose findings were absorbed
  let groupsCollapsed = 0;

  // Track which (resultIndex, findingIndex) pairs to remove
  const removals = new Set<string>();
  // Track which winners get collapsed_cwes
  const winnerCollapsed = new Map<string, string[]>(); // "ri:fi" -> collapsed CWE list

  for (const [_key, group] of groups) {
    if (group.length <= 1) continue; // nothing to collapse

    groupsCollapsed++;

    // Sort: highest severity first, then lowest CWE number
    group.sort((a, b) => {
      const sevDiff = (SEVERITY_RANK[b.finding.severity] ?? 0) - (SEVERITY_RANK[a.finding.severity] ?? 0);
      if (sevDiff !== 0) return sevDiff;
      return cweNumber(a.cwe) - cweNumber(b.cwe);
    });

    const winner = group[0];
    const winnerKey = `${winner.resultIndex}:${winner.findingIndex}`;
    const collapsedCwes: string[] = [];

    for (let i = 1; i < group.length; i++) {
      const loser = group[i];
      collapsedCwes.push(loser.cwe);
      collapsedCWEsSet.add(loser.cwe);
      // Mark this finding for removal
      removals.add(`${loser.resultIndex}:${loser.findingIndex}`);
    }

    // Sort collapsed CWEs for determinism
    collapsedCwes.sort((a, b) => cweNumber(a) - cweNumber(b));

    // Merge with any existing collapsed_cwes on the winner
    const existing = winnerCollapsed.get(winnerKey) ?? [];
    winnerCollapsed.set(winnerKey, [...existing, ...collapsedCwes]);
  }

  // Step 4: Apply collapsed_cwes to winners
  for (const [key, cwes] of winnerCollapsed) {
    const [ri, fi] = key.split(':').map(Number);
    const finding = out[ri].findings[fi];
    const existingCollapsed = (finding as Finding & { collapsed_cwes?: string[] }).collapsed_cwes ?? [];
    (finding as Finding & { collapsed_cwes?: string[] }).collapsed_cwes = [...existingCollapsed, ...cwes];
  }

  // Step 5: Remove collapsed findings (iterate in reverse to preserve indices)
  // First, group removals by resultIndex
  const removalsByResult = new Map<number, Set<number>>();
  for (const key of removals) {
    const [ri, fi] = key.split(':').map(Number);
    let s = removalsByResult.get(ri);
    if (!s) {
      s = new Set();
      removalsByResult.set(ri, s);
    }
    s.add(fi);
  }

  for (const [ri, findingIndices] of removalsByResult) {
    const r = out[ri];
    r.findings = r.findings.filter((_f, i) => !findingIndices.has(i));
    // If all findings in this result were collapsed, mark holds=true
    if (r.findings.length === 0) {
      r.holds = true;
    }
  }

  const afterCount = out.reduce((sum, r) => {
    if (r.holds) return sum;
    return sum + r.findings.filter(f => extractMissingCategory(f.missing) !== 'EFFECTIVE_CONTROL').length;
  }, 0);

  // Also count EFFECTIVE_CONTROL findings that we skipped
  const effectiveControlCount = out.reduce((sum, r) => {
    if (r.holds) return sum;
    return sum + r.findings.filter(f => extractMissingCategory(f.missing) === 'EFFECTIVE_CONTROL').length;
  }, 0);

  return {
    results: out,
    stats: {
      before: beforeCount + effectiveControlCount,
      after: afterCount + effectiveControlCount,
      groupsCollapsed,
    },
  };
}

// ===========================================================================
// LAYER 3 — CWE Family Dedup
// ===========================================================================

/**
 * CWE family definitions.
 *
 * Each family has a parent CWE and a set of children. When multiple members
 * of the same family fire on the same (source, sink, missingCategory), only
 * the parent survives. If the parent didn't fire, the lowest-numbered child
 * is kept.
 *
 * Families are derived from MITRE CWE hierarchy:
 * - Path Traversal: CWE-22 is the parent, CWE-23..38 + filesystem variants
 * - XSS: CWE-79 is the parent, CWE-80..87 are output-context variants
 * - Input Handling: CWE-20 is the parent, CWE-228..240 are structural variants
 * - Filtering: CWE-790 is the parent, CWE-791..797 are filtering-mode variants
 * - Link Following: CWE-59 is the parent, CWE-61/62/64/65 are OS-specific variants
 */

interface CWEFamily {
  parent: string;
  children: Set<string>;
  /** All members (parent + children) for fast lookup */
  all: Set<string>;
}

const CWE_FAMILIES: CWEFamily[] = [];

function defineFamily(parent: string, childNumbers: number[]): void {
  const children = new Set(childNumbers.map(n => `CWE-${n}`));
  const all = new Set([parent, ...children]);
  CWE_FAMILIES.push({ parent, children, all });
}

// Path Traversal family: CWE-22 parent, CWE-23..40 + filesystem variants
defineFamily('CWE-22', [
  23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
  39, 40,  // Windows drive letter / UNC variants
  56,      // Path Equivalence wildcard
  66,      // Virtual resource handling
  67,      // Windows device names
  69,      // Windows ::DATA ADS
  72,      // Apple HFS+ ADS
  73,      // External control of file name or path
]);

// Link Following family: CWE-59 parent, OS-specific link variants
defineFamily('CWE-59', [61, 62, 64, 65]);

// XSS family: CWE-79 parent, CWE-80..87 are context variants
defineFamily('CWE-79', [80, 81, 82, 83, 84, 85, 86, 87]);

// Input Handling family: CWE-20 parent, structural/value handling children
defineFamily('CWE-20', [
  228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240,
]);

// Filtering family: CWE-790 parent, filtering-mode variants
defineFamily('CWE-790', [791, 792, 793, 794, 795, 796, 797]);

// Build a reverse-lookup: CWE -> family it belongs to
const CWE_TO_FAMILY = new Map<string, CWEFamily>();
for (const fam of CWE_FAMILIES) {
  for (const cwe of fam.all) {
    CWE_TO_FAMILY.set(cwe, fam);
  }
}

/** Exported for testing */
export function getFamilyForCWE(cwe: string): CWEFamily | undefined {
  return CWE_TO_FAMILY.get(cwe);
}

/** Exported for testing */
export { CWE_FAMILIES };

/**
 * Family-level dedup stats.
 */
export interface FamilyDedupStats {
  /** Number of CWE results before family dedup */
  before: number;
  /** Number of CWE results after family dedup */
  after: number;
  /** Number of family groups that had collapses */
  familiesCollapsed: number;
}

/**
 * Deduplicate CWE family siblings.
 *
 * When multiple members of the same CWE family fire on the same
 * (source.id, sink.id, missingCategory) evidence, collapse them
 * under the parent (or lowest-numbered member that fired).
 *
 * Algorithm:
 * 1. Collect all failed findings with their CWE
 * 2. Group by: family :: source.id :: sink.id :: missingCategory
 * 3. Within each group, keep the parent if present, else lowest CWE number
 * 4. Suppress siblings, record them in collapsed_cwes
 *
 * CRITICAL: CWEs that are NOT in any family pass through untouched.
 * CWEs where only one family member fires also pass through untouched.
 *
 * Returns a new array. Does not mutate the input.
 */
export function familyDedup(results: VerificationResult[]): { results: VerificationResult[]; stats: FamilyDedupStats } {
  // Deep-clone
  const out: VerificationResult[] = results.map(r => ({
    cwe: r.cwe,
    name: r.name,
    holds: r.holds,
    findings: r.findings.map(f => ({ ...f })),
  }));

  const beforeCount = out.filter(r => !r.holds).length;

  // Step 1: For each finding across all failed results, build family groups
  // Key: "familyParent :: source.id :: sink.id :: missingCategory"
  // Value: list of (resultIndex, findingIndex, cwe)
  interface FamilyTagged {
    cwe: string;
    family: CWEFamily;
    resultIndex: number;
    findingIndex: number;
    finding: Finding;
  }

  const familyGroups = new Map<string, FamilyTagged[]>();

  for (let ri = 0; ri < out.length; ri++) {
    const r = out[ri];
    if (r.holds) continue;

    const family = CWE_TO_FAMILY.get(r.cwe);
    if (!family) continue; // Not in any family — skip

    for (let fi = 0; fi < r.findings.length; fi++) {
      const f = r.findings[fi];
      // Exclude EFFECTIVE_CONTROL from family dedup too
      if (extractMissingCategory(f.missing) === 'EFFECTIVE_CONTROL') continue;

      const category = extractMissingCategory(f.missing);
      const key = `${family.parent}::${f.source.id}::${f.sink.id}::${category}`;

      let group = familyGroups.get(key);
      if (!group) {
        group = [];
        familyGroups.set(key, group);
      }
      group.push({ cwe: r.cwe, family, resultIndex: ri, findingIndex: fi, finding: f });
    }
  }

  // Step 2: For each family group with 2+ members, pick the winner
  const removals = new Set<string>(); // "ri:fi" pairs to remove
  const winnerCollapsedCWEs = new Map<string, string[]>(); // "ri:fi" -> collapsed CWE list
  let familiesCollapsed = 0;

  for (const [_key, group] of familyGroups) {
    // Need at least 2 different CWEs to collapse
    const distinctCWEs = new Set(group.map(g => g.cwe));
    if (distinctCWEs.size <= 1) continue;

    familiesCollapsed++;

    // Sort: parent first, then by CWE number ascending (deterministic)
    const parentCWE = group[0].family.parent;
    group.sort((a, b) => {
      // Parent always wins
      if (a.cwe === parentCWE && b.cwe !== parentCWE) return -1;
      if (b.cwe === parentCWE && a.cwe !== parentCWE) return 1;
      // Then by severity (highest first)
      const sevDiff = (SEVERITY_RANK[b.finding.severity] ?? 0) - (SEVERITY_RANK[a.finding.severity] ?? 0);
      if (sevDiff !== 0) return sevDiff;
      // Then by CWE number (lowest first)
      return cweNumber(a.cwe) - cweNumber(b.cwe);
    });

    const winner = group[0];
    const winnerKey = `${winner.resultIndex}:${winner.findingIndex}`;
    const collapsedCwes: string[] = [];

    // Track which CWEs have already contributed a winner — only collapse
    // findings from the SAME CWE that the winner already covers
    const winnerCWE = winner.cwe;
    const suppressedCWEs = new Set<string>();

    for (let i = 1; i < group.length; i++) {
      const sibling = group[i];
      // Only suppress if this CWE is different from the winner
      // (same-CWE duplicates were handled by Layer 2)
      if (sibling.cwe !== winnerCWE) {
        suppressedCWEs.add(sibling.cwe);
      }
      removals.add(`${sibling.resultIndex}:${sibling.findingIndex}`);
      if (sibling.cwe !== winnerCWE && !collapsedCwes.includes(sibling.cwe)) {
        collapsedCwes.push(sibling.cwe);
      }
    }

    // Sort for determinism
    collapsedCwes.sort((a, b) => cweNumber(a) - cweNumber(b));

    const existing = winnerCollapsedCWEs.get(winnerKey) ?? [];
    winnerCollapsedCWEs.set(winnerKey, [...existing, ...collapsedCwes]);
  }

  // Step 3: Apply collapsed_cwes to winners
  for (const [key, cwes] of winnerCollapsedCWEs) {
    const [ri, fi] = key.split(':').map(Number);
    const finding = out[ri].findings[fi];
    const existingCollapsed = (finding as Finding & { collapsed_cwes?: string[] }).collapsed_cwes ?? [];
    // Deduplicate: some CWEs may already be in collapsed_cwes from Layer 2
    const merged = [...existingCollapsed, ...cwes.filter(c => !existingCollapsed.includes(c))];
    merged.sort((a, b) => cweNumber(a) - cweNumber(b));
    (finding as Finding & { collapsed_cwes?: string[] }).collapsed_cwes = merged;
  }

  // Step 4: Remove suppressed findings
  const removalsByResult = new Map<number, Set<number>>();
  for (const key of removals) {
    const [ri, fi] = key.split(':').map(Number);
    let s = removalsByResult.get(ri);
    if (!s) {
      s = new Set();
      removalsByResult.set(ri, s);
    }
    s.add(fi);
  }

  for (const [ri, findingIndices] of removalsByResult) {
    const r = out[ri];
    r.findings = r.findings.filter((_f, i) => !findingIndices.has(i));
    if (r.findings.length === 0) {
      r.holds = true;
    }
  }

  const afterCount = out.filter(r => !r.holds).length;

  return {
    results: out,
    stats: {
      before: beforeCount,
      after: afterCount,
      familiesCollapsed,
    },
  };
}
