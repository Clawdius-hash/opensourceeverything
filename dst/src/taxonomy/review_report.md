# DST CWE Review Report

**Date:** 2026-03-23
**Reviewer:** Atreus (automated review agent)
**Method:** Each CWE JSON was read, then verified against the live MITRE page at `https://cwe.mitre.org/data/definitions/XXX.html`

## Summary

| Outcome | Count |
|---------|-------|
| Confirmed deprecated/category (correctly needs_review) | 26 |
| Wrongly flagged (changed to filled) | 0 |
| Needs human judgment | 0 |

**All 26 entries are correctly flagged as `needs_review`.** None are real weaknesses that should be scannable. Every one is either a deprecated entry or an active category where MITRE explicitly marks vulnerability mapping as PROHIBITED.

---

## Detailed Findings

### Deprecated Categories (16 entries)

These are entries that MITRE has both deprecated AND classified as categories. Mapping is PROHIBITED.

| CWE | Name | Replacement CWEs | Notes |
|-----|------|-------------------|-------|
| CWE-1 | Location | none | Deprecated organizational category from Development View |
| CWE-3 | Technology-specific Environment Issues | none | Catch-all deprecated for unnecessary depth |
| CWE-4 | J2EE Environment Issues | none | Deprecated, introduced unnecessary complexity |
| CWE-10 | ASP.NET Environment Issues | none | Deprecated category |
| CWE-17 | Code | none | Deprecated, was for Development View organization |
| CWE-18 | Source Code | none | Deprecated, was for Development View organization |
| CWE-21 | Pathname Traversal and Equivalence Errors | CWE-706, CWE-1219 | Deprecated 2020-02-24, updated JSON with both replacements |
| CWE-60 | UNIX Path Link Problems | none | OS-specific abstraction, too low-level |
| CWE-63 | Windows Path Link Problems | none | OS-specific abstraction, too low-level |
| CWE-68 | Windows Virtual File Problems | CWE-66, CWE-632 | Updated JSON with CWE-632 reference |
| CWE-70 | Mac Virtual File Problems | CWE-66, CWE-632 | Updated JSON with CWE-632 reference |
| CWE-100 | Technology-Specific Input Validation Problems | none | Catch-all deprecated for unnecessary depth |
| CWE-101 | Struts Validation Problems | none | Deprecated, introduced unnecessary complexity |
| CWE-139 | General Special Element Problems | CWE-138 | PLOVER leftover |
| CWE-169 | Technology-Specific Special Elements | none | Catch-all deprecated for unnecessary depth |
| CWE-171 | Cleansing, Canonicalization, and Comparison Errors | none | Weaknesses moved to other similar categories |

### Deprecated Weaknesses (3 entries)

These were actual weakness entries (Base or Variant) that have since been deprecated because they duplicate or are subsumed by other CWEs. Mapping is PROHIBITED.

| CWE | Name | Type | Replacement CWE | Notes |
|-----|------|------|-----------------|-------|
| CWE-71 | Apple '.DS_Store' | Variant | CWE-62 | Too narrow — specific observed example of UNIX Hard Link |
| CWE-92 | Improper Sanitization of Custom Special Characters | Weakness | CWE-75 | PLOVER leftover, catch-all for sanitization |
| CWE-132 | Miscalculated Null Termination | Base | CWE-170 | Exact duplicate |

### Active Categories (7 entries)

These are NOT deprecated but are still categories where MITRE PROHIBITS vulnerability mapping. They exist for organizational/navigational purposes only.

| CWE | Name | Member Weaknesses | Notes |
|-----|------|-------------------|-------|
| CWE-2 | 7PK - Environment | CWE-5 through CWE-14 | Seven Pernicious Kingdoms taxonomy |
| CWE-16 | Configuration | CWE-284, CWE-400 | Status: Obsolete. Map to specific configuration weakness instead |
| CWE-19 | Data Processing Errors | CWE-130, CWE-166, CWE-611 | Updated JSON with member references |
| CWE-133 | String Errors | CWE-134, CWE-135, CWE-480 | Updated JSON with member references |
| CWE-136 | Type Errors | CWE-681, CWE-843, CWE-1287 | Already had correct related_cwes |
| CWE-137 | Data Neutralization Issues | CWE-76, CWE-78, CWE-79, CWE-89 | Updated JSON with member references |
| CWE-189 | Numeric Errors | CWE-190, CWE-191, CWE-193, CWE-369, CWE-681 | Already had correct related_cwes. MITRE suggests mapping to CWE-682 instead |

---

## Changes Made

The following JSON files were updated to add missing replacement/member CWE references found on the MITRE pages:

1. **cwe-21.json** -- Added CWE-1219 to related_cwes; expanded description with both replacements
2. **cwe-68.json** -- Added CWE-632 to related_cwes
3. **cwe-70.json** -- Added CWE-632 to related_cwes
4. **cwe-133.json** -- Added CWE-134, CWE-135, CWE-480 to related_cwes; updated description
5. **cwe-137.json** -- Added CWE-76, CWE-78, CWE-79, CWE-89 to related_cwes; updated description
6. **cwe-16.json** -- Added CWE-284, CWE-400 to related_cwes; updated description with Obsolete status
7. **cwe-19.json** -- Added CWE-130, CWE-166, CWE-611 to related_cwes; updated description

No status changes were made -- all 26 remain `needs_review` as they are all correctly non-scannable.
