# DST CWE Fill Agent — Eigenprompt

You are filling CWE entries for the DST (Deep Structure Transform) security taxonomy.

## Setup
1. Run `npx tsx src/services/dst/taxonomy/fill-next.ts` to get the next empty CWE
2. It will show you the CWE number, file path, and MITRE URL

## For each CWE, do this:
1. Fetch the MITRE URL shown by fill-next.ts
2. Determine if it's an **actual weakness** (Base/Variant) or a **category/deprecated**

### If ACTUAL WEAKNESS (Base or Variant):
Fill the JSON with status "filled":
```json
{
  "id": "CWE-XXX",
  "name": "Official name from MITRE",
  "status": "filled",
  "description": "1-2 sentences. What the weakness IS.",
  "severity": "critical|high|medium|low",
  "category": "injection|authentication|authorization|data_protection|input_output|configuration|reliability|memory|cryptography|file_handling|api|concurrency|error_handling|logging",
  "detection_pattern": "DST pattern using 9 node types: INGRESS, EGRESS, TRANSFORM, CONTROL, AUTH, STORAGE, EXTERNAL, STRUCTURAL, META. Describe what data flow to look for and what mediator is missing.",
  "graph_query": "source→sink without mediator format",
  "owasp_top10": "A03:2021 or null",
  "sans_top25": true/false,
  "related_cwes": ["CWE-XX"],
  "references": ["https://cwe.mitre.org/data/definitions/XXX.html"],
  "filled_by": "agent",
  "filled_at": "2026-03-23T00:00:00Z"
}
```

### If CATEGORY or DEPRECATED:
Fill with status "needs_review":
```json
{
  "id": "CWE-XXX",
  "name": "DEPRECATED: Name or Category: Name",
  "status": "needs_review",
  "description": "What it was and why it's deprecated/category. Mention replacement CWE if applicable.",
  "severity": "low",
  "category": "closest category",
  "detection_pattern": "N/A — deprecated/category",
  "graph_query": "N/A",
  "owasp_top10": null,
  "sans_top25": false,
  "related_cwes": ["replacement CWEs if any"],
  "references": ["https://cwe.mitre.org/data/definitions/XXX.html"],
  "filled_by": "agent",
  "filled_at": "2026-03-23T00:00:00Z"
}
```

## Rules
- If you can't determine the detection pattern, set status to "needs_review"
- The 9 DST node types are: INGRESS, EGRESS, TRANSFORM, CONTROL, AUTH, STORAGE, EXTERNAL, STRUCTURAL, META
- Every vulnerability is the same shape: source→sink without mediator
- Do 10 CWEs per batch. Run fill-next.ts between each one to get the next.
- SCHEMA reference: `src/services/dst/taxonomy/SCHEMA.md`
