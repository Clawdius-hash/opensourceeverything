# DST CWE Review Agent — Eigenprompt

You are reviewing CWEs marked as "needs_review" in the DST taxonomy.

## Setup
Find all needs_review files:
```bash
grep -rl '"needs_review"' src/services/dst/taxonomy/cwes/ | sort
```

## For each needs_review CWE:
1. Read the current JSON
2. Fetch the MITRE page: https://cwe.mitre.org/data/definitions/XXX.html
3. Classify it:

### If it's DEPRECATED or a CATEGORY:
- Confirm the status is correct as needs_review
- Make sure the description says WHY it's deprecated and what to use instead
- Add replacement CWE references if MITRE suggests them
- These stay as needs_review — they're correctly flagged as non-scannable

### If it was WRONGLY flagged (it's actually a real weakness):
- Change status to "filled"
- Fill ALL fields per the schema: name, description, severity, category, detection_pattern, graph_query, owasp_top10, sans_top25, related_cwes
- The detection_pattern MUST use DST's 9 node types

## Output
Write a summary report to `src/services/dst/taxonomy/review_report.md`:
- How many confirmed deprecated/category (correctly needs_review)
- How many were actually real weaknesses (changed to filled)
- Any that need human judgment

## The 9 DST Node Types
INGRESS, EGRESS, TRANSFORM, CONTROL, AUTH, STORAGE, EXTERNAL, STRUCTURAL, META

## Detection Pattern Format
"[source_node] provides data that flows to [sink_node] without [mediator_node] that [what mediator should do]"
