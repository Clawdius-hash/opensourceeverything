# Phoneme Expansion Agent v2 — Read This First

∂ℳ/∂t ≠ 0. You have full autonomy and agency. Build, test, wire, question, explore.

## What you're doing

You are expanding DST's phoneme dictionaries — the function-to-node-type mappings that tell the scanner what code DOES. You are also WIRING your entries into the live dictionaries so they work immediately.

## The 10 node types

| Type | What it names |
|------|--------------|
| INGRESS | User input entering the system |
| EGRESS | Data leaving the system |
| TRANSFORM | Data modification |
| CONTROL | Logic that validates/sanitizes |
| AUTH | Identity/permission checks |
| STORAGE | Data at rest |
| EXTERNAL | Third-party/dangerous calls |
| STRUCTURAL | System topology |
| META | Metadata/config |
| RESOURCE | Finite capacity |

## Your job (3 steps)

### Step 1: Write your phoneme entries
You will be given a LANGUAGE and SCOPE. Write up to 10 entries.
Save to: `src/services/dst/phoneme-expansion/{language}_{scope}.ts`

### Step 2: Wire them into the live dictionary
The language dictionaries live at:
- JS: `src/services/dst/calleePatterns.ts` (DIRECT_CALLS and MEMBER_CALLS maps)
- Python: `src/services/dst/languages/python.ts`
- Go: `src/services/dst/languages/go.ts`
- Rust: `src/services/dst/languages/rust.ts`
- Java: `src/services/dst/languages/java.ts`
- PHP: `src/services/dst/languages/php.ts`
- C#: `src/services/dst/languages/csharp.ts`
- Ruby: `src/services/dst/languages/ruby.ts`
- Kotlin: `src/services/dst/languages/kotlin.ts`
- Swift: `src/services/dst/languages/swift.ts`

Read the target dictionary first. Understand the format. Add your entries in the correct format matching what's already there. Don't duplicate existing entries.

### Step 3: Run tests
Run: `cd C:/Users/pizza/generic-api-wrapper && npx vitest run src/services/dst/`
All tests must pass. If adding entries breaks something, fix it or don't add that entry.

## Quality bar

Each entry must be:
- A REAL function from a REAL framework (not invented)
- Correctly typed (INGRESS for user input, STORAGE for databases, etc.)
- Not a duplicate of an existing entry
- Something that matters for security

## Be curious

- If you find a function that doesn't fit the 10 types, say so
- If existing entries are WRONG, fix them and note what you fixed
- If you discover a pattern nobody talks about, flag it
- Send exciting finds to Nate: `cd C:/Users/pizza/vigil && python telegram.py --send "message"` (no underscores)

## Rules

- MAX 10 new entries per agent
- Read existing dictionary FIRST — no duplicates
- WIRE your entries into the live dictionary — don't just write a file
- Run tests AFTER wiring
- If tests break, fix or revert
- Have fun. The work matters. Every entry you add is a vulnerability DST can catch that it couldn't before.
