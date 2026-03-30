/**
 * CWE Source-Sink Deduplication (Layer 2)
 *
 * Problem: Multiple CWE verifiers fire on the same (source, sink) pair because
 * the CWE taxonomy has deep parent-child hierarchies where children are
 * SPECIALIZATIONS of parents. Our verifiers can't distinguish sub-variants
 * (CWE-80 "Basic XSS" vs CWE-82 "IMG tag XSS") because that requires runtime
 * context. So 1 real XSS bug produces 9 findings.
 *
 * Solution: Group findings by (source.id, sink.id, missingCategory). Within
 * each group, keep the finding with highest severity and lowest CWE number.
 * Record all other CWEs in `collapsed_cwes` on the surviving finding.
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
 */
function dedupKey(finding: Finding): string {
  const category = extractMissingCategory(finding.missing);
  return `${finding.source.id}::${finding.sink.id}::${category}`;
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
 * Deduplicate verification results by (source, sink, missingCategory).
 *
 * Algorithm:
 * 1. Collect all findings from all VerificationResults where holds === false
 * 2. Exclude EFFECTIVE_CONTROL findings from dedup (different finding class)
 * 3. Group by dedupKey: source.id :: sink.id :: missingCategory
 * 4. Within each group, keep highest severity, lowest CWE number as tiebreaker
 * 5. Attach collapsed_cwes to the surviving finding
 * 6. Mark collapsed CWEs' VerificationResults: set holds=true (represented by parent)
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

  // Step 2: Group by dedup key
  const groups = new Map<string, TaggedFinding[]>();
  for (const t of tagged) {
    const key = dedupKey(t.finding);
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
