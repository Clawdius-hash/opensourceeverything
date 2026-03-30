/**
 * CWE Source-Sink Dedup Tests
 *
 * Tests Layer 2 dedup: collapsing duplicate findings that share
 * (source.id, sink.id, missingCategory) across different CWEs.
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
  it('collapses duplicate findings with same source, sink, and missing category', () => {
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

    const { results: deduped, stats } = deduplicateResults(results);

    // Only one finding should survive
    const failed = deduped.filter(r => !r.holds);
    expect(failed.length).toBe(1);
    expect(failed[0].cwe).toBe('CWE-80'); // lowest CWE number wins

    // collapsed_cwes should list the absorbed CWEs
    expect(failed[0].findings[0].collapsed_cwes).toBeDefined();
    expect(failed[0].findings[0].collapsed_cwes).toContain('CWE-81');
    expect(failed[0].findings[0].collapsed_cwes).toContain('CWE-82');

    // CWE-81 and CWE-82 should now be holds=true
    const cwe81 = deduped.find(r => r.cwe === 'CWE-81');
    const cwe82 = deduped.find(r => r.cwe === 'CWE-82');
    expect(cwe81?.holds).toBe(true);
    expect(cwe82?.holds).toBe(true);

    // Stats
    expect(stats.before).toBe(3);
    expect(stats.after).toBe(1);
    expect(stats.groupsCollapsed).toBe(1);
  });

  it('keeps highest severity finding as winner', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-80', 'Basic XSS', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (encoding)', severity: 'medium' }),
      ]),
      makeResult('CWE-79', 'Cross-Site Scripting', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (encoding)', severity: 'critical' }),
      ]),
    ];

    const { results: deduped } = deduplicateResults(results);
    const failed = deduped.filter(r => !r.holds);

    expect(failed.length).toBe(1);
    // CWE-79 wins because it has critical severity (even though CWE-80 has lower number)
    expect(failed[0].cwe).toBe('CWE-79');
    expect(failed[0].findings[0].severity).toBe('critical');
    expect(failed[0].findings[0].collapsed_cwes).toContain('CWE-80');
  });

  it('uses lowest CWE number as tiebreaker when severity is equal', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-85', 'Doubled Character XSS', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (encoding)', severity: 'high' }),
      ]),
      makeResult('CWE-80', 'Basic XSS', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (encoding)', severity: 'high' }),
      ]),
      makeResult('CWE-83', 'Script in Attributes', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (encoding)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = deduplicateResults(results);
    const failed = deduped.filter(r => !r.holds);

    expect(failed.length).toBe(1);
    expect(failed[0].cwe).toBe('CWE-80'); // lowest number
    expect(failed[0].findings[0].collapsed_cwes).toEqual(['CWE-83', 'CWE-85']);
  });

  it('does NOT collapse findings with different source IDs', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-80', 'Basic XSS', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (encoding)', severity: 'high' }),
      ]),
      makeResult('CWE-81', 'Script in Error Message', [
        makeFinding({ sourceId: 'SRC2', sinkId: 'SINK1', missing: 'CONTROL (encoding)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = deduplicateResults(results);
    const failed = deduped.filter(r => !r.holds);

    // Both should survive — different sources
    expect(failed.length).toBe(2);
  });

  it('does NOT collapse findings with different sink IDs', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-80', 'Basic XSS', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (encoding)', severity: 'high' }),
      ]),
      makeResult('CWE-81', 'Script in Error Message', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK2', missing: 'CONTROL (encoding)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = deduplicateResults(results);
    const failed = deduped.filter(r => !r.holds);

    expect(failed.length).toBe(2);
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

    // Both survive — CONTROL vs TRANSFORM are different categories
    expect(failed.length).toBe(2);
  });

  it('excludes EFFECTIVE_CONTROL findings from dedup', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-80', 'Basic XSS', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (output encoding)', severity: 'high' }),
      ]),
      makeResult('CWE-81', 'Script in Error Message', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (output encoding)', severity: 'high' }),
      ]),
      makeResult('CWE-79', 'XSS', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'EFFECTIVE_CONTROL (the control on this path is itself vulnerable)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = deduplicateResults(results);

    // CWE-80 and CWE-81 collapse. CWE-79 with EFFECTIVE_CONTROL survives independently.
    const failed = deduped.filter(r => !r.holds);
    expect(failed.length).toBe(2); // CWE-80 (with CWE-81 collapsed) + CWE-79 (EFFECTIVE_CONTROL)

    const cwe79 = failed.find(r => r.cwe === 'CWE-79');
    expect(cwe79).toBeDefined();
    expect(cwe79!.findings[0].missing).toContain('EFFECTIVE_CONTROL');

    const cwe80 = failed.find(r => r.cwe === 'CWE-80');
    expect(cwe80).toBeDefined();
    expect(cwe80!.findings[0].collapsed_cwes).toContain('CWE-81');
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
      makeResult('CWE-85', 'Doubled Character XSS', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (encoding)', severity: 'high' }),
      ]),
      makeResult('CWE-80', 'Basic XSS', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (encoding)', severity: 'high' }),
      ]),
      makeResult('CWE-83', 'Script in Attributes', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (encoding)', severity: 'high' }),
      ]),
      makeResult('CWE-82', 'Script in IMG', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (encoding)', severity: 'high' }),
      ]),
    ];

    const run1 = deduplicateResults(makeInput());
    const run2 = deduplicateResults(makeInput());

    // Same winner
    const failed1 = run1.results.filter(r => !r.holds);
    const failed2 = run2.results.filter(r => !r.holds);
    expect(failed1.length).toBe(failed2.length);
    expect(failed1[0].cwe).toBe(failed2[0].cwe);
    expect(failed1[0].findings[0].collapsed_cwes).toEqual(failed2[0].findings[0].collapsed_cwes);
  });

  it('does not mutate the input array', () => {
    const results: VerificationResult[] = [
      makeResult('CWE-80', 'Basic XSS', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (encoding)', severity: 'high' }),
      ]),
      makeResult('CWE-81', 'Script in Error Message', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (encoding)', severity: 'high' }),
      ]),
    ];

    // Snapshot before
    const cwe81HoldsBefore = results[1].holds;
    const cwe81FindingsLenBefore = results[1].findings.length;

    deduplicateResults(results);

    // Input should be unchanged
    expect(results[1].holds).toBe(cwe81HoldsBefore);
    expect(results[1].findings.length).toBe(cwe81FindingsLenBefore);
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

  it('collapses a large family (path traversal: 8 CWEs)', () => {
    const cwes = ['CWE-23', 'CWE-24', 'CWE-25', 'CWE-26', 'CWE-27', 'CWE-28', 'CWE-29', 'CWE-30'];
    const results: VerificationResult[] = cwes.map(cwe =>
      makeResult(cwe, `Path Traversal variant ${cwe}`, [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (path validation)', severity: 'high' }),
      ])
    );

    const { results: deduped, stats } = deduplicateResults(results);
    const failed = deduped.filter(r => !r.holds);

    expect(failed.length).toBe(1);
    expect(failed[0].cwe).toBe('CWE-23'); // lowest
    expect(failed[0].findings[0].collapsed_cwes!.length).toBe(7);
    expect(stats.before).toBe(8);
    expect(stats.after).toBe(1);
  });

  it('handles multiple distinct source-sink groups independently', () => {
    const results: VerificationResult[] = [
      // Group 1: SRC1 -> SINK1 (XSS family)
      makeResult('CWE-80', 'Basic XSS', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (encoding)', severity: 'high' }),
      ]),
      makeResult('CWE-81', 'Script in Error', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (encoding)', severity: 'high' }),
      ]),
      // Group 2: SRC2 -> SINK2 (SQL injection family)
      makeResult('CWE-89', 'SQL Injection', [
        makeFinding({ sourceId: 'SRC2', sinkId: 'SINK2', missing: 'CONTROL (parameterized query)', severity: 'critical' }),
      ]),
      makeResult('CWE-564', 'SQL Injection Hibernate', [
        makeFinding({ sourceId: 'SRC2', sinkId: 'SINK2', missing: 'CONTROL (parameterized query)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = deduplicateResults(results);
    const failed = deduped.filter(r => !r.holds);

    expect(failed.length).toBe(2);
    // Group 1 winner: CWE-80 (both high, CWE-80 < CWE-81)
    expect(failed.some(r => r.cwe === 'CWE-80')).toBe(true);
    // Group 2 winner: CWE-89 (critical > high)
    expect(failed.some(r => r.cwe === 'CWE-89')).toBe(true);

    const cwe89 = failed.find(r => r.cwe === 'CWE-89')!;
    expect(cwe89.findings[0].collapsed_cwes).toContain('CWE-564');
  });

  it('handles a CWE with multiple findings across different groups', () => {
    // CWE-80 fires on two different source-sink pairs
    const results: VerificationResult[] = [
      makeResult('CWE-80', 'Basic XSS', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (encoding)', severity: 'high' }),
        makeFinding({ sourceId: 'SRC2', sinkId: 'SINK2', missing: 'CONTROL (encoding)', severity: 'high' }),
      ]),
      makeResult('CWE-81', 'Script in Error', [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (encoding)', severity: 'high' }),
      ]),
    ];

    const { results: deduped } = deduplicateResults(results);
    const cwe80 = deduped.find(r => r.cwe === 'CWE-80')!;

    // CWE-80 should keep the SRC2->SINK2 finding (no overlap) and win the SRC1->SINK1 group
    expect(cwe80.holds).toBe(false);
    expect(cwe80.findings.length).toBe(2);

    // The SRC1->SINK1 finding should have collapsed_cwes
    const src1Finding = cwe80.findings.find(f => f.source.id === 'SRC1');
    expect(src1Finding?.collapsed_cwes).toContain('CWE-81');

    // The SRC2->SINK2 finding should NOT have collapsed_cwes
    const src2Finding = cwe80.findings.find(f => f.source.id === 'SRC2');
    expect(src2Finding?.collapsed_cwes).toBeUndefined();
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

    expect(failed.length).toBe(2); // AUTH != CONTROL, no collapse
  });

  it('collapsed_cwes are sorted by CWE number', () => {
    const cwes = ['CWE-87', 'CWE-82', 'CWE-85', 'CWE-80', 'CWE-84', 'CWE-86', 'CWE-83', 'CWE-81'];
    const results: VerificationResult[] = cwes.map(cwe =>
      makeResult(cwe, `XSS variant ${cwe}`, [
        makeFinding({ sourceId: 'SRC1', sinkId: 'SINK1', missing: 'CONTROL (encoding)', severity: 'high' }),
      ])
    );

    const { results: deduped } = deduplicateResults(results);
    const failed = deduped.filter(r => !r.holds);

    expect(failed.length).toBe(1);
    expect(failed[0].cwe).toBe('CWE-80');

    const collapsed = failed[0].findings[0].collapsed_cwes!;
    // Should be sorted: 81, 82, 83, 84, 85, 86, 87
    for (let i = 1; i < collapsed.length; i++) {
      const prev = parseInt(collapsed[i - 1].replace('CWE-', ''), 10);
      const curr = parseInt(collapsed[i].replace('CWE-', ''), 10);
      expect(curr).toBeGreaterThan(prev);
    }
  });
});
