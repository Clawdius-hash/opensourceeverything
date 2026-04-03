/**
 * Source code analysis utilities for CWE verifiers.
 *
 * String processing (comment stripping, literal stripping) and
 * taint neutralization detection (dead branches, static values, HashMap keys).
 * These operate on source code text — no graph types needed.
 */

/**
 * Strip content inside string literals and regex literals, leaving delimiters.
 * "/\bDES\b/" → "//", "Math.random()" → "". Used by crypto/PRNG verifiers
 * to avoid self-detection when scanning DST's own detection patterns.
 */
export function stripLiterals(code: string): string {
  // Replace regex literals: /pattern/flags → //
  let result = code.replace(/(?<![=!<>])\/(?![/*])(?:[^/\\]|\\.)+\/[gimsuy]*/g, '//');
  // Replace double-quoted strings: "content" → ""
  result = result.replace(/"(?:[^"\\]|\\.)*"/g, '""');
  // Replace single-quoted strings: 'content' → ''
  result = result.replace(/'(?:[^'\\]|\\.)*'/g, "''");
  // Replace template literals: `content` → ``
  result = result.replace(/`(?:[^`\\]|\\.)*`/g, '``');
  return result;
}

/**
 * Strip only regex literals from code, leaving string literals intact.
 * Used by CWE-798 and similar verifiers that need to detect credential VALUES
 * (which are in string literals) but not match against detection regex patterns
 * (which are regex literals inside DST's own verifier code).
 */
export function stripRegexLiterals(code: string): string {
  return code.replace(/(?<![=!<>])\/(?![/*])(?:[^/\\]|\\.)+\/[gimsuy]*/g, '//');
}

export function stripComments(code: string): string {
  let result = '';
  let i = 0;
  const len = code.length;

  while (i < len) {
    const ch = code[i];
    const next = i + 1 < len ? code[i + 1] : '';

    // String literals — skip through without stripping
    if (ch === '"' || ch === "'" || ch === '`') {
      const quote = ch;
      result += ch;
      i++;
      while (i < len) {
        if (code[i] === '\\') {
          // Escaped character — consume both
          result += code[i] + (i + 1 < len ? code[i + 1] : '');
          i += 2;
          continue;
        }
        if (code[i] === quote) {
          result += code[i];
          i++;
          break;
        }
        result += code[i];
        i++;
      }
      continue;
    }

    // Multi-line comment: /* ... */
    if (ch === '/' && next === '*') {
      i += 2;
      while (i < len) {
        if (code[i] === '*' && i + 1 < len && code[i + 1] === '/') {
          i += 2;
          break;
        }
        i++;
      }
      result += ' '; // Replace comment with space to avoid token merging
      continue;
    }

    // Single-line comment: // ...
    if (ch === '/' && next === '/') {
      // Skip to end of line
      i += 2;
      while (i < len && code[i] !== '\n') {
        i++;
      }
      continue;
    }

    // Hash comment: # ... (Python, Ruby, PHP)
    if (ch === '#') {
      // Skip to end of line
      i++;
      while (i < len && code[i] !== '\n') {
        i++;
      }
      continue;
    }

    result += ch;
    i++;
  }

  return result;
}

/** Escape special regex characters so a string can be used in new RegExp(). */
export function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Test if `word` appears as a whole word in `text`.
 * Equivalent to /\bword\b/ but works correctly with dynamic strings
 * (avoids the JS string escaping pitfall where '\\b' becomes backspace).
 */
export function wholeWord(text: string, word: string): boolean {
  let idx = 0;
  while (true) {
    const pos = text.indexOf(word, idx);
    if (pos === -1) return false;
    const before = pos > 0 ? text[pos - 1]! : ' ';
    const after = pos + word.length < text.length ? text[pos + word.length]! : ' ';
    const isWordBefore = /\w/.test(before);
    const isWordAfter = /\w/.test(after);
    if (!isWordBefore && !isWordAfter) return true;
    idx = pos + 1;
  }
}

/**
 * Detect dead-branch taint neutralization in Java source code.
 *
 * BenchmarkJava (and similar code) uses constant-arithmetic ternary/if-else
 * and switch-on-constant patterns to guarantee a safe branch is always taken.
 *
 * Returns true when dead-branch neutralization is detected (taint is suppressed).
 */
export function detectDeadBranchNeutralization(sourceCode: string): boolean {
  const cleanSrc = stripComments(sourceCode);

  // Pattern 1: Arithmetic constant condition with variable reference
  // (a * b) [+-] varName  {> < >= <=}  threshold
  const arithCondMatch = cleanSrc.match(
    /\((\d+)\s*\*\s*(\d+)\)\s*([+-])\s*(\w+)\s*([><=!]+)\s*(\d+)/
  );
  if (arithCondMatch) {
    const a = parseInt(arithCondMatch[1]!);
    const b = parseInt(arithCondMatch[2]!);
    const op = arithCondMatch[3]!;
    const varName = arithCondMatch[4]!;
    const cmpOp = arithCondMatch[5]!;
    const threshold = parseInt(arithCondMatch[6]!);
    // Try to find the variable's value: int varName = N;
    const varDeclMatch = cleanSrc.match(new RegExp('int\\s+' + varName + '\\s*=\\s*(\\d+)'));
    if (varDeclMatch) {
      const varVal = parseInt(varDeclMatch[1]!);
      const lhs = op === '+' ? (a * b) + varVal : (a * b) - varVal;
      const condAlwaysTrue = evaluateConstantComparison(lhs, cmpOp, threshold);
      if (condAlwaysTrue === true) {
        return true;
      }
      if (condAlwaysTrue === false) {
        const ternAfter = cleanSrc.match(
          new RegExp('\\(\\d+\\s*\\*\\s*\\d+\\)\\s*[+-]\\s*' + varName + '\\s*[><=!]+\\s*\\d+\\s*\\?\\s*(\\w+)\\s*:\\s*"[^"]*"')
        );
        if (ternAfter) return true;
      }
    }
  }

  // Pattern 2: Simple constant comparison without variable
  const simpleConstMatch = cleanSrc.match(
    /(\d+)\s*([><=!]+)\s*(\d+)\s*\?\s*(?:"[^"]*"|'[^']*')\s*:\s*\w+/
  );
  if (simpleConstMatch) {
    const lhs = parseInt(simpleConstMatch[1]!);
    const cmpOp = simpleConstMatch[2]!;
    const rhs = parseInt(simpleConstMatch[3]!);
    if (evaluateConstantComparison(lhs, cmpOp, rhs) === true) {
      return true;
    }
  }
  // Inverse: N1 < N2 ? param : "safe" (always-false -> safe branch taken)
  const simpleConstMatchInv = cleanSrc.match(
    /(\d+)\s*([><=!]+)\s*(\d+)\s*\?\s*\w+\s*:\s*(?:"[^"]*"|'[^']*')/
  );
  if (simpleConstMatchInv) {
    const lhs = parseInt(simpleConstMatchInv[1]!);
    const cmpOp = simpleConstMatchInv[2]!;
    const rhs = parseInt(simpleConstMatchInv[3]!);
    if (evaluateConstantComparison(lhs, cmpOp, rhs) === false) {
      return true;
    }
  }

  // Pattern 4: Switch with constant target
  const charAtMatch = cleanSrc.match(/(\w+)\.charAt\s*\((\d+)\)[\s\S]*?switch/);
  if (charAtMatch) {
    const receiverVar = charAtMatch[1]!;
    const charIdx = parseInt(charAtMatch[2]!);
    const strDeclMatch = cleanSrc.match(
      new RegExp('String\\s+' + receiverVar + '\\s*=\\s*"([^"]*)"')
    );
    if (strDeclMatch && charIdx >= 0 && charIdx < strDeclMatch[1]!.length) {
      const selectedChar = strDeclMatch[1]![charIdx]!;
      const switchBodyMatch = cleanSrc.match(/switch\s*\([^)]*\)\s*\{([\s\S]*?\n\s*\})/);
      if (switchBodyMatch) {
        const switchBody = switchBodyMatch[1]!;
        const caseLabels = switchBody.split(/(?=case\s+'[^']*'\s*:|default\s*:)/);
        let foundSelected = false;
        let neutralized = false;
        for (const clause of caseLabels) {
          const labelMatch = clause.match(/^(?:case\s+'([^']*)'\s*:|default\s*:)/);
          if (!labelMatch) continue;
          const caseChar = labelMatch[1];
          if (!foundSelected && caseChar === selectedChar) foundSelected = true;
          if (foundSelected) {
            if (/\b\w+\s*=\s*"[^"]*"\s*;/.test(clause) && !/\b\w+\s*=\s*param\b/.test(clause)) {
              neutralized = true; break;
            }
            if (/\b\w+\s*=\s*param\b/.test(clause)) {
              neutralized = false; break;
            }
            if (/\bbreak\s*;|\breturn\b/.test(clause)) break;
          }
        }
        if (neutralized) return true;
      }
    }
  }

  return false;
}

/**
 * Evaluate a constant integer comparison.
 * Returns true if condition is always true, false if always false, null if unknown.
 */
export function evaluateConstantComparison(lhs: number, op: string, rhs: number): boolean | null {
  switch (op) {
    case '>':  return lhs > rhs;
    case '<':  return lhs < rhs;
    case '>=': return lhs >= rhs;
    case '<=': return lhs <= rhs;
    case '==': return lhs === rhs;
    case '!=': return lhs !== rhs;
    default:   return null;
  }
}

/**
 * Per-method forward taint analysis that detects when a taint chain is abandoned
 * for a static literal.
 *
 * Returns true when the last assignment to the variable before the sink is a static literal.
 */
export function detectStaticValueNeutralization(sourceCode: string): boolean {
  const src = stripComments(sourceCode);
  const lines = src.split('\n');

  // Track variables and their last-assignment status
  const tainted = new Set<string>();
  const safe = new Set<string>();

  for (const line of lines) {
    const ln = line.trim();
    if (ln.startsWith('//') || ln.startsWith('*')) continue;

    // Source: user input API
    const srcM = ln.match(/(\w+)\s*=\s*(?:\w+\.)*(?:getParameter|getHeader|getCookies|getInputStream|getReader|getQueryString)\s*\(/);
    if (srcM) { tainted.add(srcM[1]!); safe.delete(srcM[1]!); continue; }

    // Static literal assignment kills taint
    const litM = ln.match(/^(?:(?:final\s+)?(?:[\w.]+\s+))?(\w+)\s*=\s*"[^"]*"\s*;/);
    if (litM && tainted.has(litM[1]!)) { tainted.delete(litM[1]!); safe.add(litM[1]!); continue; }

    // Propagation: bar = tainted_var
    const propM = ln.match(/^(?:\w+\s+)?(\w+)\s*=\s*(\w+)\s*;/);
    if (propM && tainted.has(propM[2]!)) { tainted.add(propM[1]!); }

    // Method call with safe arg returns safe
    const callM = ln.match(/(\w+)\s*=\s*(?:new\s+\w+\(\)\s*\.\s*)?\w+\s*\(\s*(\w+)\s*\)/);
    if (callM && safe.has(callM[2]!)) { safe.add(callM[1]!); }
  }

  // If any originally-tainted variable was reassigned to a literal, neutralization occurred
  return safe.size > 0 && tainted.size === 0;
}

/**
 * Resolve HashMap put/get taint by key. Given source lines, a tainted variable set,
 * a map variable name, and the key being retrieved, determines if the value stored
 * at that key is tainted.
 *
 * Returns 'tainted' if the value at the key is tainted, 'safe' if it's a safe value,
 * or 'unknown' if the key was never put.
 */
export function resolveMapKeyTaint(
  lines: string[], taintedVars: Set<string>, mapVar: string, getKey: string, upToLine: number
): 'tainted' | 'safe' | 'unknown' {
  let result: 'tainted' | 'safe' | 'unknown' = 'unknown';
  for (let j = 0; j < upToLine; j++) {
    const pLine = lines[j]!.trim();
    // Match put("key", variableName)
    const putM = pLine.match(new RegExp(escapeRegExp(mapVar) + '\\.put\\s*\\(\\s*"([^"]*)"\\s*,\\s*(\\w+)\\s*\\)'));
    if (putM && putM[1] === getKey) {
      result = taintedVars.has(putM[2]!) ? 'tainted' : 'safe';
    }
    // Match put("key", "stringLiteral") — string literal values are always safe
    const putLitM = pLine.match(new RegExp(escapeRegExp(mapVar) + '\\.put\\s*\\(\\s*"([^"]*)"\\s*,\\s*"[^"]*"\\s*\\)'));
    if (putLitM && putLitM[1] === getKey) {
      result = 'safe';
    }
  }
  return result;
}
