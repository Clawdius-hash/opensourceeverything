/**
 * CWE Source-Sink Dedup Tests
 *
 * Tests Layer 2 dedup: collapsing duplicate findings within the SAME CWE
 * that share (source.id, sink.id, missingCategory).
 *
 * Different CWEs are NEVER collapsed — they represent distinct vulnerability
 * types. This prevents false-negative regressions where e.g. CWE-338 (Weak
 * PRNG) was absorbed by CWE-336 (Same Seed) just because both fired on the
 * same source/sink pair.
 */

import { describe, it, expect } from 'vitest';
import { deduplicateResults, extractMissingCategory } from './dedup';
import type { VerificationResult, Finding, NodeRef } from './verifier';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

function makeNodeRef(id: string, label?: string, line?: number): NodeRef {
  return {
    id,
    label: label ?? id,
    line: line ?? 1,
    code: `// ${id}`,
  };
}

function makeFinding(opts: {
  sourceId: string;
  sinkId: string;
  missing: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}): Finding {
  return {
    source: makeNodeRef(opts.sourceId, `src_${opts.sourceId}`),
    sink: makeNodeRef(opts.sinkId, `sink_${opts.sinkId}`),
    missing: opts.missing,
    severity: opts.severity,
    description: `Finding for ${opts.missing}`,
    fix: `Fix for ${opts.missing}`,
  };
}

function makeResult(cwe: string, name: string, findings: Finding[]): VerificationResult {
  return {
    cwe,
    name,
    holds: findings.length === 0,
    findings,
  };
}

// ---------------------------------------------------------------------------
// extractMissingCategory tests
// ---------------------------------------------------------------------------

describe('extractMissingCategory', () => {
  it('extracts CONTROL from typical missing string', () => {
    expect(extractMissingCategory('CONTROL (input validation or parameterized query)')).toBe('CONTROL');
  });

  it('extracts TRANSFORM', () => {
    expect(extractMissingCategory('TRANSFORM (encryption before storage)')).toBe('TRANSFORM');
  });

  it('extracts AUTH', () => {
    expect(extractMissingCategory('AUTH (authentication check before sensitive operation)')).toBe('AUTH');
  });

  it('extracts META', () => {
    expect(extractMissingCategory('META (external secret reference)')).toBe('META');
  });

  it('extracts RESOURCE', () => {
    expect(extractMissingCategory('RESOURCE (release/close on all code paths)')).toBe('RESOURCE');
  });

  it('extracts EFFECTIVE_CONTROL', () => {
    expect(extractMissingCategory('EFFECTIVE_CONTROL (the control on this path is itself vulnerable)')).toBe('EFFECTIVE_CONTROL');
  });

  it('returns UNKNOWN for empty string', () => {
    expect(extractMissingCategory('')).toBe('UNKNOWN');
  });
});

// ---------------------------------------------------------------------------
// Core dedup behavior
// ---------------------------------------------------------------------------

describe('deduplicateResults', () => {
  it('does NOT collapse different CWEs even with same source, sink, and missing category', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-80', 'Basic XSS', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (output encoding)', severity: 'high' }),
      ]),
      makeResult('CWE-81', 'Script in Error Message', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (output encoding)', severity: 'high' }),
      ]),
      makeResult('CWE-82', 'Script in IMG Attributes', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (output encoding)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = deduplicateResults(results);

    // All three CWEs are distinct — none should be collapsed
    const failed = deduped.filter(r => !r.holds);
    expect(failed.length).toBe(3);
    expect(failed.some(r => r.cwe === 'CWE-80')).toBe(true);
    expect(failed.some(r => r.cwe === 'CWE-81')).toBe(true);
    expect(failed.some(r => r.cwe === 'CWE-82')).toBe(true);
  });

  it('collapses duplicate findings within the SAME CWE on same source/sink', () => {
    // CWE-89 fires twice on the same source/sink (e.g., two traversal paths)
    const results: VerificationResult[] = [
      makeResult('CWE-89', 'SQL Injection', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (parameterized query)', severity: 'critical' }),
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (different path)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = deduplicateResults(results);
    const cwe89 = deduped.find(r => r.cwe === 'CWE-89')!;

    // Both findings have same source/sink/category, so one should be deduped
    // But since the missing parenthetical differs, the full missing strings differ
    // and dedupKey includes the category prefix only — so same CONTROL category
    // means they collapse within the same CWE.
    expect(cwe89.holds).toBe(false);
    expect(cwe89.findings.length).toBe(1);
    expect(cwe89.findings[0].severity).toBe('critical'); // highest severity wins
  });

  it('does NOT collapse findings with different source IDs (even same CWE)', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-89', 'SQL Injection', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (parameterized query)', severity: 'critical' }),
        makeFinding({ sourceId: 'SRC2', sinkId: 'SINK1', missing: 'CONTROL (parameterized query)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = deduplicateResults(results);
    const cwe89 = deduped.find(r => r.cwe === 'CWE-89')!;

    // Different sources — both findings survive
    expect(cwe89.findings.length).toBe(2);
  });

  it('does NOT collapse findings with different sink IDs (even same CWE)', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-89', 'SQL Injection', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (parameterized query)', severity: 'critical' }),
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK2', missing: 'CONTROL (parameterized query)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = deduplicateResults(results);
    const cwe89 = deduped.find(r => r.cwe === 'CWE-89')!;

    // Different sinks — both findings survive
    expect(cwe89.findings.length).toBe(2);
  });

  it('does NOT collapse findings with different missing categories', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-80', 'Basic XSS', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (output encoding)', severity: 'high' }),
      ]),
      makeResult('CWE-134', 'Format String', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'TRANSFORM (format string neutralization)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = deduplicateResults(results);
    const failed = deduped.filter(r => !r.holds);

    // Both survive — CONTROL vs TRANSFORM are different categories + different CWEs
    expect(failed.length).toBe(2);
  });

  it('excludes EFFECTIVE_CONTROL findings from dedup', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-79', 'XSS', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'EFFECTIVE_CONTROL (the control on this path is itself vulnerable)', severity: 'high' }),
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'EFFECTIVE_CONTROL (another weak control)', severity: 'medium' }),
      ]),
    ];

    const { results: deduped } = deduplicateResults(results);

    // EFFECTIVE_CONTROL findings are excluded from dedup entirely
    const cwe79 = deduped.find(r => r.cwe === 'CWE-79');
    expect(cwe79?.holds).toBe(false);
    expect(cwe79!.findings.length).toBe(2); // both survive
  });

  it('handles results that already hold (no findings)', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-89', 'SQL Injection', []),
      makeResult('CWE-80', 'Basic XSS', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (encoding)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = deduplicateResults(results);

    const cwe89 = deduped.find(r => r.cwe === 'CWE-89');
    expect(cwe89?.holds).toBe(true);

    const cwe80 = deduped.find(r => r.cwe === 'CWE-80');
    expect(cwe80?.holds).toBe(false);
  });

  it('is deterministic — same input produces same output', () => {
    const makeInput = (): VerificationResult[] => [
      makeResult('CWE-89', 'SQL Injection', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (parameterized query)', severity: 'critical' }),
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (alternative path)', severity: 'high' }),
        makeFinding({ sourceId: 'SRC2', sinkId: 'SINK2', missing: 'CONTROL (parameterized query)', severity: 'high' }),
      ]),
    ];

    const run1 = deduplicateResults(makeInput());
    const run2 = deduplicateResults(makeInput());

    // Same results
    const failed1 = run1.results.filter(r => !r.holds);
    const failed2 = run2.results.filter(r => !r.holds);
    expect(failed1.length).toBe(failed2.length);
    expect(failed1[0].cwe).toBe(failed2[0].cwe);
    expect(failed1[0].findings.length).toBe(failed2[0].findings.length);
  });

  it('does not mutate the input array', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-89', 'SQL Injection', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (parameterized query)', severity: 'critical' }),
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (alternative path)', severity: 'high' }),
      ]),
    ];

    // Snapshot before
    const findingsLenBefore = results[0].findings.length;

    deduplicateResults(results);

    // Input should be unchanged
    expect(results[0].findings.length).toBe(findingsLenBefore);
  });

  it('handles empty results', () => {
    const { results: deduped, stats } = deduplicateResults([]);
    expect(deduped).toEqual([]);
    expect(stats.before).toBe(0);
    expect(stats.after).toBe(0);
  });

  it('handles results with no failures', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-89', 'SQL Injection', []),
      makeResult('CWE-80', 'Basic XSS', []),
    ];

    const { results: deduped, stats } = deduplicateResults(results);
    expect(deduped.every(r => r.holds)).toBe(true);
    expect(stats.before).toBe(0);
    expect(stats.after).toBe(0);
  });

  it('preserves all CWEs independently even in large families', () => {
    const cwes = ['CWE-23', 'CWE-24', 'CWE-25', 'CWE-26', 'CWE-27', 'CWE-28', 'CWE-29', 'CWE-30'];
    const results: VerificationResult[] = cwes.map(cwe =>
      makeResult(cwe, `Path Traversal variant ${cwe}`, [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (path validation)', severity: 'high' }),
      ])
    );

    const { results: deduped } = deduplicateResults(results);
    const failed = deduped.filter(r => !r.holds);

    // All 8 CWEs survive independently — no cross-CWE collapse
    expect(failed.length).toBe(8);
  });

  it('handles multiple distinct source-sink groups independently', () => {
    const results: VerificationResult[] = [
      // Group 1: SRC1 -> SINK1
      makeResult('CWE-80', 'Basic XSS', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (encoding)', severity: 'high' }),
      ]),
      makeResult('CWE-81', 'Script in Error', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (encoding)', severity: 'high' }),
      ]),
      // Group 2: SRC2 -> SINK2
      makeResult('CWE-89', 'SQL Injection', [
        makeFinding({ sourceId: 'SRC2', sinkId: 'SINK2', missing: 'CONTROL (parameterized query)', severity: 'critical' }),
      ]),
      makeResult('CWE-564', 'SQL Injection Hibernate', [
        makeFinding({ sourceId: 'SRC2', sinkId: 'SINK2', missing: 'CONTROL (parameterized query)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = deduplicateResults(results);
    const failed = deduped.filter(r => !r.holds);

    // All 4 CWEs survive — no cross-CWE collapse
    expect(failed.length).toBe(4);
    expect(failed.some(r => r.cwe === 'CWE-80')).toBe(true);
    expect(failed.some(r => r.cwe === 'CWE-81')).toBe(true);
    expect(failed.some(r => r.cwe === 'CWE-89')).toBe(true);
    expect(failed.some(r => r.cwe === 'CWE-564')).toBe(true);
  });

  it('handles a CWE with multiple findings across different groups', () => {
    // CWE-80 fires on two different source-sink pairs
    const results: VerificationResult[] = [
      makeResult('CWE-80', 'Basic XSS', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (encoding)', severity: 'high' }),
        makeFinding({ sourceId: 'SRC2', sinkId: 'SINK2', missing: 'CONTROL (encoding)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = deduplicateResults(results);
    const cwe80 = deduped.find(r => r.cwe === 'CWE-80')!;

    // Both findings survive — different source-sink pairs
    expect(cwe80.holds).toBe(false);
    expect(cwe80.findings.length).toBe(2);
  });

  it('AUTH vs CONTROL findings on same source-sink are NOT collapsed', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-306', 'Missing Authentication', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'AUTH (authentication required)', severity: 'critical' }),
      ]),
      makeResult('CWE-862', 'Missing Authorization', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (authorization check)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = deduplicateResults(results);
    const failed = deduped.filter(r => !r.holds);

    expect(failed.length).toBe(2); // Different CWEs AND different categories
  });

  it('collapses within-CWE duplicates and preserves collapsed_cwes', () => {
    // Same CWE has duplicate finding on same source/sink
    const results: VerificationResult[] = [
      makeResult('CWE-89', 'SQL Injection', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (parameterized query)', severity: 'critical' }),
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (prepared statement)', severity: 'high' }),
      ]),
    ];

    const { results: deduped, stats } = deduplicateResults(results);
    const cwe89 = deduped.find(r => r.cwe === 'CWE-89')!;

    // Within-CWE dedup: both CONTROL category on same source/sink → collapse
    expect(cwe89.findings.length).toBe(1);
    expect(cwe89.findings[0].severity).toBe('critical'); // highest severity wins
    expect(stats.groupsCollapsed).toBeGreaterThanOrEqual(1);
  });
});
