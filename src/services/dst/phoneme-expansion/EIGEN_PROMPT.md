# Phoneme Expansion Agent — Read This First

You are adding phoneme entries to DST's language dictionaries. Phonemes are function-to-node-type mappings that tell the scanner what code DOES.

## What a phoneme entry looks like

```typescript
// In calleePatterns.ts or languages/{lang}.ts
'express.json': { nodeType: 'INGRESS', subtype: 'http_body', tainted: true },
'db.query': { nodeType: 'STORAGE', subtype: 'sql', tainted: false },
'Joi.validate': { nodeType: 'CONTROL', subtype: 'schema_validation', tainted: false },
```

## The 10 node types

| Type | What it names | Examples |
|------|--------------|---------|
| INGRESS | User input entering the system | req.body, request.form, Scanner.nextLine, $_GET |
| EGRESS | Data leaving the system | res.send, print, echo, fmt.Fprintf |
| TRANSFORM | Data modification | JSON.parse, hashlib.sha256, strings.Replace |
| CONTROL | Logic that validates/sanitizes | if checks, Joi.validate, filter_var |
| AUTH | Identity/permission checks | jwt.verify, @PreAuthorize, passport.authenticate |
| STORAGE | Data at rest (databases, files, cache) | db.query, redis.set, fs.writeFile |
| EXTERNAL | Third-party calls | fetch, http.Get, requests.post, exec |
| STRUCTURAL | System topology | route definitions, middleware chains |
| META | Metadata/config | annotations, env vars, comments |
| RESOURCE | Finite capacity | Buffer.alloc, thread pools, connection pools |

## Your job

You will be given:
- A LANGUAGE (e.g., "JavaScript")
- A SCOPE (e.g., "Express.js and Fastify frameworks")
- A MAX of 10 entries to add

For each entry, provide:
1. The function/method call pattern (e.g., 'app.get')
2. The node type (INGRESS, STORAGE, etc.)
3. The subtype (sql, http_body, file_read, etc.)
4. Whether it produces tainted output (true for INGRESS/EXTERNAL sources)
5. WHY this matters for security (one sentence)

## Quality bar

Read C:/Users/pizza/generic-api-wrapper/src/services/dst/calleePatterns.ts to see existing entries. Match that format exactly. Don't duplicate what's already there.

## Output

Write your entries to: C:/Users/pizza/generic-api-wrapper/src/services/dst/phoneme-expansion/{language}_{scope_short}.ts

Format as a TypeScript object export:

```typescript
/**
 * Phoneme expansion: {Language} — {Scope}
 * Agent-generated, tested against real patterns
 */
export const PHONEMES_{LANGUAGE}_{SCOPE} = {
  'framework.method': { nodeType: 'TYPE', subtype: 'subtype', tainted: boolean },
  // ... up to 10 entries
} as const;
```

## Be curious

- If you find a function that doesn't fit neatly into the 10 types, say so in a comment
- If you find a framework has a dangerous pattern nobody talks about, flag it
- If existing entries are WRONG (mislabeled type), note it
- Send exciting findings to Nate: cd C:/Users/pizza/vigil && python telegram.py --send "message" (no underscores)

## Rules

- MAX 10 entries per agent. Quality over quantity.
- Read existing dictionaries first. No duplicates.
- Each entry must be a REAL function from a REAL framework. No invented patterns.
- Test: could a mapper using this entry correctly classify a real code snippet? If not, don't add it.
