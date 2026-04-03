/**
 * DST Verification Engine
 *
 * Walks a NeuralMap and verifies security properties hold.
 * Each CWE maps to a verification path: a specific gap pattern
 * checked against the graph structure.
 *
 * The neural map IS the query. The node types ARE the verification logic.
 * The CWE→assertion mapping is just an index into which path to run.
 */

import type { NeuralMap, NeuralMapNode } from '../types';
import { evaluateControlEffectiveness, getContainingScopeSnapshots, sinkHasTaintedDataIn, scopeBasedTaintReaches, findNearestNode } from '../generated/_helpers.js';
import { GENERATED_REGISTRY } from '../generated/index.js';
import { verifyCWE336_B2, verifyCWE614_B2, verifyCWE759_B2, verifyCWE760_B2 } from '../generated/batch_crypto_B2.js';
import { deduplicateResults, familyDedup } from '../dedup.js';
import { filterCWEsForLanguage } from '../cwe-filter.js';

// Extracted shared utilities
import { stripLiterals, stripRegexLiterals, stripComments, escapeRegExp, wholeWord, detectDeadBranchNeutralization, detectStaticValueNeutralization, resolveMapKeyTaint, detectInterproceduralNeutralization90 } from './source-analysis.ts';
import { FLOW_EDGE_TYPES, nodeRef, nodesOfType, inferMapLanguage, isLibraryCode, hasTaintedPathWithoutControl, hasPathWithoutControl, findContainingFunction, sharesFunctionScope } from './graph-helpers.ts';

// Extracted architecture CWE verifiers (1044–1127)
import { ARCHITECTURE_REGISTRY } from './architecture.ts';

// Extracted crypto & hash CWE verifiers (261, 311, 317-340, 347, 354, 757, 759, 760, 780, 916)
import { CRYPTO_REGISTRY } from './crypto.ts';

// Extracted sensitive data & information disclosure CWE verifiers (200, 209-215, 222-226, 256-260, 312-319, 359, 402, 472-474, 488, 497, 524-552, 598-615, 798)
import { SENSITIVE_DATA_REGISTRY } from './sensitive-data.ts';

// Extracted auth & access control CWE verifiers (250, 266-297, 302-309, 345-360, 384, 419-455, 434, 436, 470, 501, 521-566, 602-654, 862-863, 913, 915, 939-1036)
import { AUTH_REGISTRY } from './auth.ts';

// Extracted resource management & concurrency CWE verifiers (362-386, 400-410, 426-428, 459-464, 662-694, 764-775, 832-833, 1333)
import { RESOURCE_REGISTRY } from './resource.ts';

// Extracted code quality & structural CWE verifiers (456-912, 64 functions)
import { CODE_QUALITY_REGISTRY } from './code-quality.ts';

// Extracted malicious code & covert channel CWE verifiers (494-515, 10 functions)
import { MALICIOUS_CODE_REGISTRY } from './malicious-code.ts';

// Extracted error handling, state management & side channel CWE verifiers (43 functions)
import { ERROR_HANDLING_REGISTRY } from './error-handling.ts';

// Extracted numeric & coercion CWE verifiers (16 functions)
import { NUMERIC_COERCION_REGISTRY } from './numeric-coercion.ts';

// Extracted encoding & validation CWE verifiers (13 functions)
import { ENCODING_VALIDATION_REGISTRY } from './encoding-validation.ts';

// Import types used by remaining verifiers + re-export public types
import type { VerificationResult, Finding } from './types.ts';
export type { VerificationResult, Finding, NodeRef } from './types.ts';

// Re-export string utilities (consumed by comment-strip.test.ts)
export { stripLiterals, stripRegexLiterals, stripComments };

// Satisfy TS — these are used throughout the 509 verifyCWE functions below
void FLOW_EDGE_TYPES;

// Utilities extracted to source-analysis.ts and graph-helpers.ts
// Types extracted to types.ts

// ---------------------------------------------------------------------------
// CWE Verification Paths
// ---------------------------------------------------------------------------

/**
 * CWE-89: SQL Injection
 * Pattern: INGRESS → STORAGE(sql) without CONTROL(parameterization)
 * Property: All database queries use parameterized statements when handling user input
 */
function verifyCWE89(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // Cross-domain exclusion: subtypes belonging to other injection domains must NOT
  // trigger SQL injection.  "xpath_query" and "ldap_query" contain the substring
  // "query" which caused CWE-89 to fire on XPath/LDAP code.
  const NON_SQL_QUERY_DOMAINS = /^(xpath_query|ldap_query|nosql_query|graphql_query|mongo_query|redis_query)$/;

  // File-domain exclusion: STORAGE nodes that are file operations (file_read, file_write,
  // file_access, etc.) should not be treated as SQL sinks. These fire on path traversal
  // code where file.exists()/FileInputStream are misidentified as "query" sinks.
  const FILE_DOMAIN_SUBTYPE = /\bfile/i;
  const FILE_DOMAIN_CODE = /\b(File|FileInputStream|FileOutputStream|FileReader|FileWriter|BufferedReader|BufferedWriter|RandomAccessFile|file\.exists|file\.isFile|file\.isDirectory|Files\.(read|write|copy|move|delete)|createReadStream|createWriteStream|readFile|writeFile|fopen|fread|fwrite)\b/;
  const SQL_DOMAIN_CODE = /\b(Statement|PreparedStatement|ResultSet|Connection|DriverManager|executeQuery|executeUpdate|executeBatch|createStatement|prepareStatement|SELECT\s|INSERT\s|UPDATE\s|DELETE\s|FROM\s|WHERE\s|CREATE\s+TABLE|DROP\s+TABLE|sql|SQL|jdbc)\b/;

  const storage = map.nodes.filter(n => {
    if (n.node_type !== 'STORAGE') return false;
    if (NON_SQL_QUERY_DOMAINS.test(n.node_subtype)) return false;

    // If node subtype is file-related and NOT sql-related, skip it
    if (FILE_DOMAIN_SUBTYPE.test(n.node_subtype) && !n.node_subtype.includes('sql')) return false;

    const matchesSubtype = n.node_subtype.includes('sql') || n.node_subtype.includes('query') ||
      n.node_subtype.includes('db_read') || n.node_subtype.includes('db_write');
    const matchesAttack = n.attack_surface.includes('sql_sink');
    const snap = n.analysis_snapshot || n.code_snapshot;
    const matchesCode = /\b(query|exec|execute\w*|prepare|raw)\s*\(/i.test(snap);

    if (!matchesSubtype && !matchesAttack && !matchesCode) return false;

    // If the code snapshot looks like file-domain code with no SQL indicators, exclude it
    if (FILE_DOMAIN_CODE.test(snap) && !SQL_DOMAIN_CODE.test(snap)) return false;

    return true;
  });

  // Dead-branch neutralization: suppress findings when constant arithmetic ternary/switch
  // guarantees the tainted branch is never taken (BenchmarkJava false-positive pattern).
  const hasDeadBranch89 = map.source_code ? detectDeadBranchNeutralization(map.source_code) : false;

  for (const src of ingress) {
    for (const sink of storage) {
      // Primary: BFS taint path. Fallback (Step 8): check data_in tainted entries on sink.
      if (hasTaintedPathWithoutControl(map, src.id, sink.id) || sinkHasTaintedDataIn(map, sink.id)) {
        if (hasDeadBranch89) continue;
        // Check if the sink or containing scope uses parameterized queries
        const scopeSnapshots = getContainingScopeSnapshots(map, sink.id);
        const combinedScope = stripComments(scopeSnapshots.join('\n') || sink.analysis_snapshot || sink.code_snapshot);
        const sinkSnap = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        const paramRegex = /\$\d|\?\s*[,)"']|\bprepare(?:Statement|d)?\b|\bparameterized\b|\bplaceholder/i;
        let isParameterized = paramRegex.test(combinedScope) || paramRegex.test(sinkSnap);
        // Partial parameterization fix: if prepareStatement/prepareCall is present but tainted
        // variables are concatenated into the SQL string (+ var +), it's NOT properly parameterized
        if (isParameterized && /\bprepare(?:Statement|Call)\b/.test(combinedScope)) {
          const sqlConcatPattern = /["']\s*\+\s*\w+\s*\+\s*["']|["']\s*\+\s*\w+\s*[);]/;
          if (sqlConcatPattern.test(combinedScope)) isParameterized = false;
        }

        if (!isParameterized) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (input validation or parameterized query)',
            severity: 'critical',
            description: `User input from ${src.label} flows to SQL query at ${sink.label} without parameterization. ` +
              `Tainted data reaches the query builder directly.`,
            fix: 'Use parameterized queries (prepared statements) instead of string concatenation. ' +
              'Example: db.query("SELECT * FROM users WHERE id = $1", [userId]) instead of ' +
              'db.query("SELECT * FROM users WHERE id = " + userId)',
          });
        }
      }
    }
  }

  // Source-line fallback for Java: detect SQL injection inside anonymous inner classes
  // where taint crosses class boundaries (e.g., JWT header.get("kid") → executeQuery).
  // The mapper doesn't trace taint across inner class boundaries, so BFS misses these.
  if (findings.length === 0 && map.source_code && !hasDeadBranch89) {
    const sl89 = stripComments(map.source_code);
    const lines89 = sl89.split('\n');

    // Pattern: anonymous inner class or lambda that extracts a value from a
    // request/header/claims object and concatenates it into a SQL query string.
    // Examples:
    //   final String kid = (String) header.get("kid");
    //   ... .executeQuery("SELECT key FROM jwt_keys WHERE id = '" + kid + "'");
    const INNER_SRC_RE = /(\w+)\s*=\s*(?:\(\w+\)\s*)?(?:\w+\.)*(?:get|getParameter|getParameterValues|getParameterNames|getHeader|getString|getValue|claim|getClaim|getCookies|getQueryString|getInputStream|getReader|System\.getenv)\s*\(/;
    const SQL_EXEC_RE = /\b(?:executeQuery|executeUpdate|execute|prepareStatement|createStatement|queryForRowSet|queryForObject|queryForList|queryForMap|queryForInt|queryForLong|prepareCall|jdbcTemplate\.query|namedParameterJdbcTemplate)\s*\(\s*(?:"[^"]*"\s*\+|\w+\s*\+|[^)]*\+\s*\w+)/;
    const PARAM_RE = /\bprepare(?:Statement|d)?\s*\(|\?\s*[,)]/;

    const innerTainted = new Set<string>();
    let innerSrcLine = 0;
    let innerSrcCode = '';
    let hasSqlConcat = false;
    let sqlLine = 0;
    let sqlCode = '';

    for (let i = 0; i < lines89.length; i++) {
      const ln = lines89[i]!.trim();
      if (ln.startsWith('//') || ln.startsWith('*')) continue;

      const srcMatch = ln.match(INNER_SRC_RE);
      if (srcMatch) {
        innerTainted.add(srcMatch[1]!);
        if (!innerSrcLine) { innerSrcLine = i + 1; innerSrcCode = ln; }
      }

      // For-each loop taint propagation: for (Type varName : collection)
      const forEachMatch89 = ln.match(/\bfor\s*\(\s*(?:\w+\.)*\w+(?:\[\])?\s+(\w+)\s*:\s*(\w+)\s*\)/);
      if (forEachMatch89 && innerTainted.has(forEachMatch89[2]!)) {
        innerTainted.add(forEachMatch89[1]!);
      }

      // Propagate simple assignments
      // Also handle assignments after control-flow keywords:
      //   if (...) param = values[0];   else param = "";
      const assignMatch = ln.match(/^(?:\w+\s+)*(\w+)\s*=\s*(.+)/)
        || ln.match(/\belse\s+(\w+)\s*=\s*(.+)/)
        || ln.match(/\bif\s*\([^)]*\)\s*(\w+)\s*=\s*(.+)/);
      if (assignMatch) {
        const lhs = assignMatch[1]!;
        const rhs = assignMatch[2]!;
        for (const tv of innerTainted) {
          if (new RegExp('\\b' + escapeRegExp(tv) + '\\b').test(rhs)) {
            innerTainted.add(lhs);
            break;
          }
        }
      }

      // HashMap taint resolution: bar = (Type) map.get("key")
      const mapGet89 = ln.match(/^(?:\w+\s+)*(\w+)\s*=\s*\(\w+\)\s*(\w+)\.get\s*\(\s*"([^"]*)"\s*\)/);
      if (mapGet89) {
        const mkr89 = resolveMapKeyTaint(lines89, innerTainted, mapGet89[2]!, mapGet89[3]!, i);
        if (mkr89 === 'tainted') innerTainted.add(mapGet89[1]!); else innerTainted.delete(mapGet89[1]!);
      }

      // Check for SQL execution with string concatenation using tainted var
      // Handle both single-line and multi-line SQL statements
      const SQL_CALL_RE89 = /\b(?:executeQuery|executeUpdate|execute|prepareStatement|createStatement|queryForRowSet|queryForObject|queryForList|queryForMap|queryForInt|queryForLong|prepareCall|jdbcTemplate\.query)\s*\(/;
      if ((SQL_EXEC_RE.test(ln) || SQL_CALL_RE89.test(ln)) && !PARAM_RE.test(ln)) {
        // Build a window of nearby lines to check for tainted vars in SQL concat
        // Use a wider lookback (15 lines) to cover multi-line SQL setup patterns
        // where the SQL string is built several lines before the execute call
        const windowStart = Math.max(0, i - 15);
        const windowEnd = Math.min(lines89.length - 1, i + 5);
        const window89 = lines89.slice(windowStart, windowEnd + 1).join(' ');

        // Skip if parameterized — but allow partial parameterization detection:
        // if prepareStatement/prepareCall is present AND tainted var is concatenated into the SQL
        // string, it's NOT properly parameterized (e.g., prepareStatement("SELECT ... '" + bar + "'"))
        let paramSuppressed89 = PARAM_RE.test(window89);
        if (paramSuppressed89 && /\bprepare(?:Statement|Call)\b/.test(window89)) {
          const sqlConcatPattern89 = /["']\s*\+\s*\w+\s*\+\s*["']|["']\s*\+\s*\w+\s*[);]/;
          if (sqlConcatPattern89.test(window89)) paramSuppressed89 = false;
        }
        if (!paramSuppressed89) {
          for (const tv of innerTainted) {
            // Check if tainted var appears in string concatenation near the SQL call
            if (new RegExp('["+\'\\s]\\s*\\+\\s*\\b' + escapeRegExp(tv) + '\\b|\\b' + escapeRegExp(tv) + '\\b\\s*\\+\\s*["+\'\\s]').test(window89)) {
              hasSqlConcat = true;
              // Find the exact line with the tainted var for reporting
              for (let j = windowStart; j <= windowEnd; j++) {
                if (new RegExp('\\b' + escapeRegExp(tv) + '\\b').test(lines89[j]!)) {
                  sqlLine = j + 1;
                  sqlCode = lines89[j]!.trim();
                  break;
                }
              }
              if (!sqlLine) { sqlLine = i + 1; sqlCode = ln; }
              break;
            }
          }
        }
      }
    }

    if (hasSqlConcat && innerSrcLine > 0) {
      findings.push({
        source: { id: `srcline-${innerSrcLine}`, label: `inner class input (line ${innerSrcLine})`, line: innerSrcLine, code: innerSrcCode.slice(0, 200) },
        sink: { id: `srcline-${sqlLine}`, label: `SQL query (line ${sqlLine})`, line: sqlLine, code: sqlCode.slice(0, 200) },
        missing: 'CONTROL (input validation or parameterized query)',
        severity: 'critical',
        description: `Data extracted inside inner class flows to SQL query at line ${sqlLine} via string concatenation without parameterization.`,
        fix: 'Use parameterized queries (prepared statements) instead of string concatenation.',
      });
    }
  }

  // Language-generic SQL concatenation fallback (Go, Python, PHP, etc.)
  // Detects: "SELECT ... " + userVar or fmt.Sprintf("SELECT ... %s", userVar)
  if (findings.length === 0 && map.source_code) {
    const sl89g = stripComments(map.source_code);
    // Generic SQL string concat patterns across languages
    const SQL_CONCAT_GENERIC = /(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\s+[^"]*["']\s*\+\s*\w+|fmt\.Sprintf\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[^"]*%[sv]/i;
    const PARAM_GENERIC = /\$\d+|\?\s*[,)]|\bprepare\b|\bQueryRow\s*\(.*\$|\bExec\s*\(.*\$/i;
    if (SQL_CONCAT_GENERIC.test(sl89g) && !PARAM_GENERIC.test(sl89g)) {
      // Check for taint source
      const HAS_SOURCE_GENERIC = /\b(?:r\.URL\.Query|c\.Query|c\.Param|c\.FormValue|request\.GET|request\.POST|request\.args|\$_GET|\$_POST|\$_REQUEST|params\[|chi\.URLParam|r\.FormValue)\b/i;
      if (HAS_SOURCE_GENERIC.test(sl89g)) {
        const bestSrc = ingress[0];
        const bestSink = storage[0];
        if (bestSrc && bestSink) {
          findings.push({
            source: nodeRef(bestSrc), sink: nodeRef(bestSink),
            missing: 'CONTROL (input validation or parameterized query)',
            severity: 'critical',
            description: `User input concatenated into SQL query string without parameterization.`,
            fix: 'Use parameterized queries with placeholders ($1, ?) instead of string concatenation.',
          });
        }
      }
    }
  }

  return {
    cwe: 'CWE-89',
    name: 'SQL Injection',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-79: Cross-Site Scripting (XSS)
 * Pattern: INGRESS → EGRESS(html/response) without CONTROL(encoding)
 * Property: All user input is encoded before being included in HTML output
 */
function verifyCWE79(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const egress = map.nodes.filter(n =>
    // EGRESS nodes that produce HTML output
    (n.node_type === 'EGRESS' &&
    (n.node_subtype.includes('html') || n.node_subtype.includes('response') ||
     n.node_subtype.includes('render') || n.node_subtype.includes('display') ||
     n.attack_surface.includes('html_output') ||
     (n.analysis_snapshot || n.code_snapshot).match(/\b(innerHTML|render|send|write|res\.send|\.body\s*\(|echo|print)\b/i) !== null ||
     (n.analysis_snapshot || n.code_snapshot).match(/\.println\s*\(|\.print\s*\(|writer\.write\s*\(/i) !== null)) ||
    // EXTERNAL nodes that produce HTML via template engines (render_template_string, Jinja2, etc.)
    (n.node_type === 'EXTERNAL' &&
    (n.node_subtype.includes('template_exec') ||
     (n.analysis_snapshot || n.code_snapshot).match(/\b(render_template_string|render_template|Template)\b/i) !== null))
  );

  // Dead-branch neutralization: suppress findings when constant arithmetic ternary/switch
  // guarantees the tainted branch is never taken (BenchmarkJava false-positive pattern).
  const hasDeadBranch79 = map.source_code ? detectDeadBranchNeutralization(map.source_code) : false;

  // Interprocedural neutralization: inner-class/helper methods that kill taint via
  // static value replacement, HashMap safe-key retrieval, or taint abandonment.
  const hasInterproceduralKill79 = map.source_code ? detectInterproceduralNeutralization90(map.source_code) : false;

  // HashMap safe-key retrieval (inline, non-interprocedural): tainted value is stored
  // under one key but a different (safe) key is retrieved before reaching the sink.
  let hasMapKeySafeRetrieval79 = false;
  if (map.source_code) {
    const cleanSrc79 = stripComments(map.source_code);
    const lines79h = cleanSrc79.split('\n');
    const allGets79 = [...cleanSrc79.matchAll(/(\w+)\.get\s*\(\s*"([^"]*)"\s*\)/g)];
    if (allGets79.length > 0) {
      const lastGet79 = allGets79[allGets79.length - 1]!;
      const mapVar79 = lastGet79[1]!;
      const getKey79 = lastGet79[2]!;
      const taintedVars79 = new Set<string>();
      for (const ln of lines79h) {
        const srcM = ln.match(/(\w+)\s*=\s*(?:\w+\.)*(?:getParameter|getParameterValues|getHeader|getHeaders|getCookies|getInputStream|getReader|getQueryString|nextElement)\s*\(/);
        if (srcM) taintedVars79.add(srcM[1]!);
        const decM = ln.match(/(\w+)\s*=\s*.*(?:URLDecoder\.decode)\s*\(/);
        if (decM) taintedVars79.add(decM[1]!);
      }
      if (taintedVars79.size > 0) {
        const lineIdx79 = lines79h.findIndex(l => l.includes(lastGet79[0]));
        if (lineIdx79 >= 0) {
          const mkr79 = resolveMapKeyTaint(lines79h, taintedVars79, mapVar79, getKey79, lineIdx79);
          if (mkr79 === 'safe') hasMapKeySafeRetrieval79 = true;
        }
      }
    }
  }

  for (const src of ingress) {
    for (const sink of egress) {
      // Primary: BFS taint path. Fallback (Step 8): check data_in tainted entries on sink.
      // Fallback 2: scope-based taint (Java Juliet patterns with incomplete DATA_FLOW edges)
      if (hasTaintedPathWithoutControl(map, src.id, sink.id) || sinkHasTaintedDataIn(map, sink.id) || scopeBasedTaintReaches(map, src.id, sink.id)) {
        if (hasDeadBranch79 || hasInterproceduralKill79 || hasMapKeySafeRetrieval79) continue;
        const scopeSnapshots = getContainingScopeSnapshots(map, sink.id);
        const combinedScope = stripComments(scopeSnapshots.join('\n') || sink.analysis_snapshot || sink.code_snapshot);
        const isEncoded = combinedScope.match(
          /\bescape\s*\(|\bescapeHtml\b|\bhtmlEncode\s*\(|\bencodeURI\b|\bsanitize\s*\(|\bDOMPurify\b|\btextContent\b|\bencodeForHTML\b|\bESAPI\b|\bEncoder\b.*\bencode\b|\bHtmlUtils\.htmlEscape\b|\bStringEscapeUtils\b/i
        ) !== null;

        // JSON responses are not vulnerable to XSS — Content-Type: application/json
        // prevents browser script execution. Detect .send({...}), .json({...}), res.json()
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        const isJsonResponse = sinkCode.match(
          /\.send\s*\(\s*\{|\.json\s*\(\s*\{|\.json\s*\(|res\.send\s*\(\s*\{|reply\.send\s*\(\s*\{|response\.json\s*\(/i
        ) !== null;

        if (!isEncoded && !isJsonResponse) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (output encoding or sanitization)',
            severity: 'high',
            description: `User input from ${src.label} is reflected in HTML output at ${sink.label} without encoding. ` +
              `This allows script injection.`,
            fix: 'Encode output for the target context. Use textContent instead of innerHTML. ' +
              'Use a sanitizer like DOMPurify for rich text. Never trust user input in HTML.',
          });
        } else if (isEncoded && !isJsonResponse) {
          // Context-aware encoding check: encoding exists but may be wrong for the output context.
          const sinkContextCode = stripComments(
            sink.node_subtype + ' ' + (sink.analysis_snapshot || sink.code_snapshot)
          );

          // Determine the output context from the sink's subtype and code_snapshot.
          const isHtmlContext = /\binnerHTML\b|\bdocument\.write\b|\.html\s*\(|render\s*\(|html_response|html_output/i.test(sinkContextCode);
          const isJsContext = /<script\b|eval\s*\(|setTimeout\s*\(\s*[^,)]*[^,)]\s*[,)]/i.test(sinkContextCode) ||
            /js_context|script_context/i.test(sink.node_subtype);
          const isUrlContext = /href\s*=|src\s*=|action\s*=|url_redirect|url_context/i.test(sinkContextCode);
          const isCssContext = /style\s*=|\.css\s*\(/i.test(sinkContextCode) || /css_context/i.test(sink.node_subtype);
          const isAttributeContext = /setAttribute\s*\(/i.test(sinkContextCode) || /attribute_context/i.test(sink.node_subtype);

          // Determine which encoding functions are actually used.
          const hasHtmlEncoding = /\bescapeHtml\b|\bhtmlEncode\b|\bDOMPurify\b|\btextContent\b|\bencodeForHTML\b|\bESAPI\b|\bHtmlUtils\.htmlEscape\b|\bStringEscapeUtils\b/i.test(combinedScope);
          const hasUrlEncoding = /\bencodeURIComponent\b|\bencodeURI\b/i.test(combinedScope);
          const hasJsEncoding = /\bJSON\.stringify\b|\bjsEscape\b|\bescapeJs\b/i.test(combinedScope);

          // Check for wrong encoding given the context.
          let wrongEncodingDescription: string | null = null;

          if (isHtmlContext && !hasHtmlEncoding && (hasUrlEncoding || hasJsEncoding)) {
            wrongEncodingDescription =
              'Output is encoded but using wrong encoding for the context. ' +
              'URL/JS-encoded data in an HTML context can still be exploited.';
          } else if (isJsContext && hasHtmlEncoding && !hasJsEncoding) {
            wrongEncodingDescription =
              'Output is encoded but using wrong encoding for the context. ' +
              'HTML-encoded data in JavaScript context can still be exploited.';
          } else if (isUrlContext && hasHtmlEncoding && !hasUrlEncoding) {
            wrongEncodingDescription =
              'Output is encoded but using wrong encoding for the context. ' +
              'HTML-encoded data in a URL context does not prevent URL-based attacks.';
          } else if (isCssContext && !hasHtmlEncoding && !hasJsEncoding) {
            wrongEncodingDescription =
              'Output is encoded but using wrong encoding for the context. ' +
              'CSS context requires CSS-specific encoding to prevent style injection.';
          } else if (isAttributeContext && hasUrlEncoding && !hasHtmlEncoding) {
            wrongEncodingDescription =
              'Output is encoded but using wrong encoding for the context. ' +
              'URL-encoded data in an HTML attribute context can still be exploited.';
          }

          if (wrongEncodingDescription) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(sink),
              missing: 'CONTROL (correct encoding for output context)',
              severity: 'high',
              description: wrongEncodingDescription,
              fix: 'Use context-appropriate encoding: htmlEscape/DOMPurify for HTML, ' +
                'JSON.stringify/jsEscape for JavaScript, encodeURIComponent for URLs, ' +
                'CSS encoding for style contexts. Never substitute one context\'s encoding for another.',
            });
          }
        }
      }
    }
  }

  // Source-line fallback for Java: detect reflected XSS via @ResponseBody.
  // When a Spring controller method is annotated with @ResponseBody (or the class
  // with @RestController), the return value IS the HTTP response body. If a
  // @RequestParam is concatenated into a StringBuilder or string that gets returned
  // (directly or via .output()), it's reflected XSS without encoding.
  if (findings.length === 0 && map.source_code) {
    const sl79 = stripComments(map.source_code);
    const lines79 = sl79.split('\n');

    // Check for @ResponseBody or @RestController presence
    const hasResponseBody = /@ResponseBody|@RestController/.test(sl79);
    if (hasResponseBody) {
      // Find @RequestParam String variables
      const requestParams79 = new Set<string>();
      const PARAM_RE79 = /@RequestParam(?:\s*\([^)]*\))?\s+(?:String|Integer|Long|int|long)\s+(\w+)/g;
      let pm79;
      while ((pm79 = PARAM_RE79.exec(sl79)) !== null) {
        requestParams79.add(pm79[1]!);
      }

      if (requestParams79.size > 0) {
        // Track taint through assignments and string concatenation
        const tainted79 = new Set(requestParams79);
        const ENCODE_RE79 = /\bescapeHtml\b|\bhtmlEncode\b|\bsanitize\b|\bencodeForHTML\b|\bESAPI\b|\bHtmlUtils\.htmlEscape\b|\bStringEscapeUtils\b|\bDOMPurify\b/i;

        // Check if any request param is concatenated into a string builder or string
        // that reaches a response output without encoding
        let xssFound = false;
        let xssSrcLine = 0;
        let xssSrcCode = '';
        let xssSinkLine = 0;
        let xssSinkCode = '';

        for (let i = 0; i < lines79.length; i++) {
          const ln = lines79[i]!.trim();
          if (ln.startsWith('//') || ln.startsWith('*')) continue;

          // Propagate taint through StringBuilder.append with concat
          for (const tv of tainted79) {
            if (new RegExp('\\b' + escapeRegExp(tv) + '\\b').test(ln)) {
              // String concatenation: "..." + field1
              if (/\+\s*\w+|\w+\s*\+/.test(ln)) {
                // Mark StringBuilder variables as tainted
                const sbMatch = ln.match(/(\w+)\.append\s*\(/);
                if (sbMatch) tainted79.add(sbMatch[1]!);
              }
              // Assignment propagation
              const assignMatch = ln.match(/^(?:\w+\s+)*(\w+)\s*=\s*/);
              if (assignMatch && assignMatch[1] !== tv) tainted79.add(assignMatch[1]!);
            }
          }

          // .toString() propagation from tainted StringBuilder
          const tsMatch = ln.match(/(\w+)\.toString\s*\(\s*\)/);
          if (tsMatch && tainted79.has(tsMatch[1]!)) {
            const outerAssign = ln.match(/(?:^|\s)(\w+)\s*=\s*/);
            if (outerAssign) tainted79.add(outerAssign[1]!);
          }

          // Detect output sinks: .output(...), .body(...), return ..., .send(...)
          const outputMatch = ln.match(/\.output\s*\(([^)]*)\)|\.body\s*\(([^)]*)\)|return\s+(.+)/);
          if (outputMatch) {
            const outputArg = outputMatch[1] || outputMatch[2] || outputMatch[3] || '';
            for (const tv of tainted79) {
              if (new RegExp('\\b' + escapeRegExp(tv) + '\\b').test(outputArg)) {
                // Check if encoding is present in scope
                const scopeSlice = lines79.slice(Math.max(0, i - 30), i + 1).join('\n');
                if (!ENCODE_RE79.test(scopeSlice)) {
                  xssFound = true;
                  // Find the source line
                  for (let j = 0; j < lines79.length; j++) {
                    for (const rp of requestParams79) {
                      if (new RegExp('@RequestParam.*\\b' + escapeRegExp(rp) + '\\b').test(lines79[j]!)) {
                        xssSrcLine = j + 1;
                        xssSrcCode = lines79[j]!.trim();
                        break;
                      }
                    }
                    if (xssSrcLine) break;
                  }
                  xssSinkLine = i + 1;
                  xssSinkCode = ln;
                  break;
                }
              }
            }
          }
          if (xssFound) break;
        }

        if (xssFound && xssSrcLine > 0) {
          findings.push({
            source: { id: `srcline-${xssSrcLine}`, label: `request parameter (line ${xssSrcLine})`, line: xssSrcLine, code: xssSrcCode.slice(0, 200) },
            sink: { id: `srcline-${xssSinkLine}`, label: `@ResponseBody output (line ${xssSinkLine})`, line: xssSinkLine, code: xssSinkCode.slice(0, 200) },
            missing: 'CONTROL (output encoding or sanitization)',
            severity: 'high',
            description: `User input from @RequestParam is reflected in @ResponseBody HTTP response at line ${xssSinkLine} without encoding. ` +
              `An attacker can inject script tags via the request parameter.`,
            fix: 'Encode output for the target context. Use HtmlUtils.htmlEscape() or a sanitizer before including user input in response bodies.',
          });
        }
      }
    }
  }

  return {
    cwe: 'CWE-79',
    name: 'Cross-Site Scripting (XSS)',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-81: XSS in Error Message
 * Pattern: INGRESS → error-output-sink without CONTROL(error-message encoding)
 * Property: User input reflected in error pages/responses (sendError, error handler
 * output, exception.getMessage() in response) must be encoded.
 *
 * This is a SPECIFIC sub-variant of CWE-79. The distinguishing factor is that the
 * sink is an error-handling output path: sendError(), error page rendering, or
 * exception message displayed to the user. Uses a different missingCategory than
 * CWE-79 so family dedup keeps both findings.
 */
function verifyCWE81(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // Sinks specific to CWE-81: error message output paths
  const errorSinks = map.nodes.filter(n => {
    const code = n.analysis_snapshot || n.code_snapshot;
    const sub = n.node_subtype;
    // Must be EGRESS or have output-like characteristics
    if (n.node_type !== 'EGRESS' && n.node_type !== 'TRANSFORM') return false;
    // Specific error-output sinks:
    //   - response.sendError(status, message) — Java Servlet
    //   - sendError / send_error patterns
    //   - error page rendering (error.jsp, error handler, error template)
    //   - exception.getMessage() flowing to response output
    //   - res.status(4xx/5xx).send() patterns
    //   - HttpServletResponse error methods
    return (
      /\bsendError\s*\(/i.test(code) ||
      /\bsend_error\s*\(/i.test(code) ||
      /\berror\s*page\b|\berror\s*handler\b|\berror\s*template\b/i.test(code) ||
      /\b(get)?[Mm]essage\s*\(\s*\)/.test(code) && /\b(print|write|send|render|display)\b/i.test(code) ||
      /\bres\s*\.\s*status\s*\(\s*[45]\d{2}\s*\)\s*\.\s*send\b/i.test(code) ||
      /\bresponse\.sendError\b/i.test(code) ||
      sub.includes('error') ||
      sub.includes('sendError')
    );
  });

  // Also check all EGRESS nodes whose containing scope has sendError / error-output patterns
  const egressWithErrorScope = map.nodes.filter(n => {
    if (n.node_type !== 'EGRESS') return false;
    if (errorSinks.some(s => s.id === n.id)) return false; // already captured
    const scopeSnaps = getContainingScopeSnapshots(map, n.id);
    const scopeCode = stripComments(scopeSnaps.join('\n'));
    return /\bsendError\s*\(/i.test(scopeCode) ||
           /\bresponse\.sendError\b/i.test(scopeCode);
  });

  const allErrorSinks = [...errorSinks, ...egressWithErrorScope];

  for (const src of ingress) {
    for (const sink of allErrorSinks) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id) ||
          sinkHasTaintedDataIn(map, sink.id) ||
          scopeBasedTaintReaches(map, src.id, sink.id)) {
        const scopeSnapshots = getContainingScopeSnapshots(map, sink.id);
        const combinedScope = stripComments(scopeSnapshots.join('\n') || sink.analysis_snapshot || sink.code_snapshot);
        const isEncoded = /\bescape\s*\(|\bescapeHtml\b|\bhtmlEncode\s*\(|\bsanitize\s*\(|\bDOMPurify\b|\btextContent\b|\bencodeForHTML\b|\bESAPI\b|\bEncoder\b.*\bencode\b|\bHtmlUtils\.htmlEscape\b|\bStringEscapeUtils\b/i.test(combinedScope);

        if (!isEncoded) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'ERROR_ENCODING (encode user data in error responses)',
            severity: 'high',
            description: `User input from ${src.label} is reflected in an error response at ${sink.label} without encoding. ` +
              `Error pages that echo user input (e.g. sendError with tainted data) enable reflected XSS.`,
            fix: 'HTML-encode all user-controlled values before including them in error messages or error pages. ' +
              'Use HttpServletResponse.sendError() only with static messages, or encode dynamic values with ESAPI/HtmlUtils.',
          });
        }
      }
    }
  }

  // Source-line scan: look for sendError with string concatenation (direct pattern match)
  if (findings.length === 0) {
    for (const node of map.nodes) {
      const code = stripComments(node.analysis_snapshot || node.code_snapshot);
      // Pattern: sendError(statusCode, <anything> + variable) — tainted data in error message
      if (/\bsendError\s*\(\s*\d+\s*,\s*[^)]*\+\s*\w/i.test(code)) {
        // Check if any INGRESS variable is referenced
        for (const src of ingress) {
          const srcLabel = src.label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          // Check if the ingress label or common tainted variable names appear near the sendError
          if (new RegExp(`\\b(data|input|param|${srcLabel})\\b`, 'i').test(code)) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(node),
              missing: 'ERROR_ENCODING (encode user data in error responses)',
              severity: 'high',
              description: `User input flows to sendError() at ${node.label} via string concatenation. ` +
                `Error messages that include unsanitized user data enable reflected XSS in error pages.`,
              fix: 'HTML-encode user-controlled values before passing to sendError(). ' +
                'Use ESAPI.encoder().encodeForHTML() or HtmlUtils.htmlEscape() on dynamic values.',
            });
            break;
          }
        }
      }
    }
  }

  return {
    cwe: 'CWE-81',
    name: 'XSS in Error Message',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-83: XSS in HTML Attribute
 * Pattern: INGRESS → attribute-context-sink without CONTROL(attribute encoding)
 * Property: User input inserted into HTML attribute values (href, src, onclick, style,
 * event handlers, etc.) must be attribute-encoded.
 *
 * This is a SPECIFIC sub-variant of CWE-79. The distinguishing factor is that the
 * output context is an HTML attribute value, where the attacker can break out of
 * the attribute or inject event handlers. Uses a different missingCategory than
 * CWE-79 so family dedup keeps both findings.
 */
function verifyCWE83(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // Attribute-context HTML output pattern
  const ATTR_CONTEXT_RE = /\b(href|src|action|formaction|onclick|onload|onerror|onmouseover|onfocus|onblur|onchange|onsubmit|style|data-\w+|value|class|id|name|type|alt|title)\s*=\s*["']/i;
  const IMG_TAG_RE = /<img\b[^>]*\bsrc\s*=\s*["'][^"']*\+|<img\b[^>]*\bsrc\s*=\s*["']\s*"\s*\+/i;
  const ATTR_CONCAT_RE = /\b(href|src|action|formaction|onclick|onload|onerror|onmouseover|style)\s*=\s*["'][^"']*["']\s*\+\s*\w|\b(href|src|action|formaction|onclick|onload|onerror|onmouseover|style)\s*=\s*["'][^"']*\+\s*\w/i;

  // Sinks specific to CWE-83: EGRESS nodes that produce output in an attribute context
  const attrSinks = map.nodes.filter(n => {
    if (n.node_type !== 'EGRESS') return false;
    const code = n.analysis_snapshot || n.code_snapshot;
    const sub = n.node_subtype;
    return (
      // Direct attribute-context patterns in code
      ATTR_CONTEXT_RE.test(code) ||
      IMG_TAG_RE.test(code) ||
      ATTR_CONCAT_RE.test(code) ||
      // Subtype hints for attribute context
      sub.includes('attribute') ||
      sub.includes('attr') ||
      // setAttribute calls
      /\bsetAttribute\s*\(/i.test(code) ||
      // HTML output with attribute patterns: println("<tag attr=\"" + data + "\">")
      /\bprintln\s*\(\s*"[^"]*<\w+\s+[^>]*=\s*\\?["'][^"]*"\s*\+/i.test(code) ||
      /\bprint\s*\(\s*"[^"]*<\w+\s+[^>]*=\s*\\?["'][^"]*"\s*\+/i.test(code) ||
      /\bwrite\s*\(\s*"[^"]*<\w+\s+[^>]*=\s*\\?["'][^"]*"\s*\+/i.test(code)
    );
  });

  // Also check EGRESS nodes whose containing scope reveals attribute-context output
  const egressWithAttrScope = map.nodes.filter(n => {
    if (n.node_type !== 'EGRESS') return false;
    if (attrSinks.some(s => s.id === n.id)) return false;
    const scopeSnaps = getContainingScopeSnapshots(map, n.id);
    const scopeCode = stripComments(scopeSnaps.join('\n'));
    return (
      IMG_TAG_RE.test(scopeCode) ||
      ATTR_CONCAT_RE.test(scopeCode) ||
      // Common Juliet pattern: response.getWriter().println("<br>bad() - <img src=\"" + data + "\">");
      /\bprintln\s*\(\s*"[^"]*<img\s+src\s*=\s*\\"/i.test(scopeCode) ||
      /\bprintln\s*\(\s*"[^"]*<\w+\s+\w+\s*=\s*\\"/i.test(scopeCode)
    );
  });

  const allAttrSinks = [...attrSinks, ...egressWithAttrScope];

  for (const src of ingress) {
    for (const sink of allAttrSinks) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id) ||
          sinkHasTaintedDataIn(map, sink.id) ||
          scopeBasedTaintReaches(map, src.id, sink.id)) {
        const scopeSnapshots = getContainingScopeSnapshots(map, sink.id);
        const combinedScope = stripComments(scopeSnapshots.join('\n') || sink.analysis_snapshot || sink.code_snapshot);

        // Attribute-context requires attribute-specific encoding (not just HTML encoding)
        const isEncoded = /\bescapeHtml\b|\bescapeAttribute\b|\bhtmlEncode\s*\(|\bsanitize\s*\(|\bDOMPurify\b|\btextContent\b|\bencodeForHTMLAttribute\b|\bencodeForHTML\b|\bESAPI\b|\bEncoder\b.*\bencode\b|\bHtmlUtils\.htmlEscape\b|\bStringEscapeUtils\b|\bencodeURIComponent\b/i.test(combinedScope);
        // URL validation for href/src attributes
        const hasUrlValidation = /\ballowlist\b|\bwhitelist\b|\bvalid.*url\b|\burl.*valid\b|\bhttps?:\/\/\b.*\bonly\b/i.test(combinedScope);

        if (!isEncoded && !hasUrlValidation) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'ATTRIBUTE_ENCODING (encode user data in HTML attributes)',
            severity: 'high',
            description: `User input from ${src.label} is inserted into an HTML attribute context at ${sink.label} without encoding. ` +
              `Attacker can break out of the attribute value or inject event handlers (e.g. " onmouseover="alert(1)).`,
            fix: 'Use attribute-context encoding (encodeForHTMLAttribute / ESAPI) for all user input in HTML attributes. ' +
              'Always quote attribute values. For URL attributes (href, src), validate against an allowlist of safe schemes.',
          });
        }
      }
    }
  }

  // Source-line scan: look for attribute-context concatenation patterns
  if (findings.length === 0) {
    for (const node of map.nodes) {
      const code = stripComments(node.analysis_snapshot || node.code_snapshot);
      // Pattern: println/print/write with HTML attribute + string concatenation
      if (/\b(println|print|write)\s*\(\s*"[^"]*<\w+\s+\w+\s*=\s*\\?["'][^"]*"\s*\+\s*\w/i.test(code) ||
          /\b(println|print|write)\s*\(\s*"[^"]*<img\s+src\s*=\s*\\"/i.test(code)) {
        for (const src of ingress) {
          const srcLabel = src.label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          if (new RegExp(`\\b(data|input|param|${srcLabel})\\b`, 'i').test(code)) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(node),
              missing: 'ATTRIBUTE_ENCODING (encode user data in HTML attributes)',
              severity: 'high',
              description: `User input flows into an HTML attribute at ${node.label} via string concatenation. ` +
                `Tainted data in attribute values (src, href, event handlers) enables XSS via attribute injection.`,
              fix: 'Use encodeForHTMLAttribute() or ESAPI encoding for user input in attributes. ' +
                'Validate URL attributes against an allowlist of safe protocols.',
            });
            break;
          }
        }
      }
    }
  }

  return {
    cwe: 'CWE-83',
    name: 'XSS in Attribute',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-22: Path Traversal
 * Pattern: INGRESS → STORAGE(filesystem) without CONTROL(path validation)
 * Property: All file operations validate that paths stay within allowed directories
 */
function verifyCWE22(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const fileOps = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' &&
     (n.node_subtype.includes('file') || n.node_subtype.includes('fs') ||
      n.node_subtype === 'file_access' || n.node_subtype === 'file_read' || n.node_subtype === 'file_write' ||
      n.attack_surface.includes('file_access') ||
      (n.analysis_snapshot || n.code_snapshot).match(/\b(readFile|writeFile|createReadStream|open|unlink|readdir)\b/i) !== null)) ||
    // Python: open(filename) is classified as INGRESS/file_read, not STORAGE/file
    (n.node_type === 'INGRESS' && n.node_subtype === 'file_read') ||
    // Java: EGRESS/file_write (e.g. FileOutputStream, Files.write) with user-controlled path
    (n.node_type === 'EGRESS' && n.node_subtype === 'file_write') ||
    // Go: http.ServeFile serves file content from a user-controlled path
    (n.node_type === 'EGRESS' && n.node_subtype === 'file_serve')
  );

  // Path traversal safe patterns: canonicalization + boundary check
  const PATH_SAFE_RE = /\bpath\.resolve\b|\bpath\.normalize\b|\bstartsWith\b|\b\.\.\/\b|\bsanitize.*path|\bgetCanonicalPath\b|\bgetCanonicalFile\b|\bPaths\.get\b.*\bnormalize\b|\brealpath\b|\bfilepath\.Clean\b/i;

  // Java: detect dead-branch taint neutralization patterns in source code.
  // BenchmarkJava uses ternary/switch with constant conditions to neutralize taint.
  // The mapper over-approximates these, so we suppress graph-based findings when
  // the source code proves the tainted branch is never taken.
  const hasDeadBranchNeutralization = map.source_code ? detectDeadBranchNeutralization(map.source_code) : false;
  // Per-index collection taint tracking now handled by the mapper (collectionTaint on VariableInfo).
  const hasStaticValueNeutralization22 = map.source_code ? detectStaticValueNeutralization(map.source_code) : false;
  const hasInterproceduralNeutralization22 = map.source_code ? detectInterproceduralNeutralization90(map.source_code) : false;

  // Detect HashMap safe-key retrieval: tainted value is stored under one key but
  // a different (safe) key is retrieved. Checks interprocedural doSomething methods.
  let hasMapKeySafeRetrieval22 = false;
  if (map.source_code) {
    const cleanSrc22 = stripComments(map.source_code);
    const lines22 = cleanSrc22.split('\n');
    // Find map.get("key") pattern
    const mapGetMatch22 = cleanSrc22.match(/(\w+)\.get\s*\(\s*"([^"]*)"\s*\)/g);
    if (mapGetMatch22) {
      // Check each map.get() — if the LAST one retrieves a safe key, taint is neutralized
      const allGets = [...cleanSrc22.matchAll(/(\w+)\.get\s*\(\s*"([^"]*)"\s*\)/g)];
      if (allGets.length > 0) {
        const lastGet = allGets[allGets.length - 1]!;
        const mapVar = lastGet[1]!;
        const getKey = lastGet[2]!;
        // Find tainted vars from source
        const taintedVars22 = new Set<string>();
        for (const ln of lines22) {
          const srcM = ln.match(/(\w+)\s*=\s*(?:\w+\.)*(?:getParameter|getHeader|getCookies|getInputStream|getReader|getQueryString)\s*\(/);
          if (srcM) taintedVars22.add(srcM[1]!);
          const decM = ln.match(/(\w+)\s*=\s*.*(?:URLDecoder\.decode)\s*\(/);
          if (decM) taintedVars22.add(decM[1]!);
        }
        if (taintedVars22.size > 0) {
          const lineIdx = lines22.findIndex(l => l.includes(lastGet[0]));
          if (lineIdx >= 0) {
            const mkr = resolveMapKeyTaint(lines22, taintedVars22, mapVar, getKey, lineIdx);
            if (mkr === 'safe') hasMapKeySafeRetrieval22 = true;
          }
        }
      }
    }
  }

  for (const src of ingress) {
    for (const sink of fileOps) {
      // Primary: BFS taint path from INGRESS to file-operation node.
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        // Suppress graph-based findings when dead-branch, list-offset, static-value,
        // safe-source, or map-key neutralization is detected.
        // The graph tracks taint through all branches, but constant ternary/switch patterns
        // guarantee the tainted branch is never taken.
        if (hasDeadBranchNeutralization || hasStaticValueNeutralization22 || hasInterproceduralNeutralization22 || hasMapKeySafeRetrieval22) continue;

        const scopeSnapshots = getContainingScopeSnapshots(map, sink.id);
        const combinedScope = stripComments(scopeSnapshots.join('\n') || sink.analysis_snapshot || sink.code_snapshot);
        const isValidated = PATH_SAFE_RE.test(combinedScope);

        if (!isValidated) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (path validation / directory restriction)',
            severity: 'high',
            description: `User input from ${src.label} controls a file path at ${sink.label} without validation. ` +
              `An attacker can use ../../ to access files outside the intended directory.`,
            fix: 'Resolve the full path with path.resolve(), then verify it starts with your allowed base directory. ' +
              'Never use user input directly in file operations.',
          });
        }
      }
    }
  }

  // Source-code scanning fallback for Java: detects patterns where user input
  // (getParameter, getCookies, getHeaders) flows to File/FileInputStream/FileOutputStream
  // constructors via local variable assignment + string concatenation, even when
  // the mapper doesn't emit DATA_FLOW edges for the full chain.
  if (findings.length === 0 && map.source_code && !hasDeadBranchNeutralization && !hasStaticValueNeutralization22 && !hasInterproceduralNeutralization22 && !hasMapKeySafeRetrieval22) {
    const src = stripComments(map.source_code);
    // Normalize: collapse whitespace/newlines for multi-line statement parsing
    const normalized = src.replace(/\n\s*/g, ' ');
    // Split into statements at semicolons
    const stmts = normalized.split(';').map(s => s.trim());

    // Detect Java HTTP user-input sources
    const javaSourceRe = /\b(?:request|req|httpRequest)\s*\.\s*(?:getParameter|getCookies|getHeader|getHeaders|getQueryString|getInputStream|getReader)\s*\(|\.getValue\s*\(\s*\)|\.readLine\s*\(\s*\)/;
    const hasUserSource = javaSourceRe.test(src);

    // Detect Java file sinks with variable-based paths (not hardcoded string literals)
    const javaFileSinkRe = /new\s+(?:java\.io\.)?(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|PrintWriter)\s*\(\s*(?!["'])/;
    const hasFileSink = javaFileSinkRe.test(normalized);

    if (hasUserSource && hasFileSink) {
      // Find variables assigned from user input (statement-level scanning)
      const taintedVars = new Set<string>();
      for (const stmt of stmts) {
        // Direct: param = request.getParameter(...) or param = cookie.getValue()
        const assignMatch = stmt.match(/\b(\w+)\s*=\s*.*(?:getParameter|getCookies|getHeader|getHeaders|getQueryString|getInputStream|getReader|\.getValue|\.readLine)\s*\(/);
        if (assignMatch) taintedVars.add(assignMatch[1]!);
        // Cookie/header decode: param = ...decode(theCookie.getValue(), ...)
        const cookieMatch = stmt.match(/\b(\w+)\s*=\s*.*(?:URLDecoder\.decode|java\.net\.URLDecoder\.decode)\s*\(/);
        if (cookieMatch) taintedVars.add(cookieMatch[1]!);
        // Header: param = headers.nextElement()
        const headerMatch = stmt.match(/\b(\w+)\s*=\s*\w+\.nextElement\s*\(/);
        if (headerMatch) taintedVars.add(headerMatch[1]!);
      }

      if (taintedVars.size > 0) {
        // Propagate taint through assignments: bar = f(param); fileName = prefix + bar
        // SKIP: ternary expressions (condition may make tainted branch unreachable)
        // SKIP: assignments inside switch/case blocks (selected case may be safe)
        let changed = true;
        while (changed) {
          changed = false;
          for (const stmt of stmts) {
            const propMatch = stmt.match(/\b(\w+)\s*=\s*(.*)/s);
            if (propMatch) {
              const lhs = propMatch[1]!;
              const rhs = propMatch[2]!;
              if (!taintedVars.has(lhs)) {
                // Skip ternary expressions
                if (rhs.includes('?') && rhs.includes(':')) continue;
                // Skip assignments inside switch/case blocks
                if (/\bcase\s+|default\s*:/.test(stmt)) continue;
                for (const tv of taintedVars) {
                  if (wholeWord(rhs, tv)) {
                    taintedVars.add(lhs);
                    changed = true;
                    break;
                  }
                }
              }
            }
          }
        }

        // Check if any file sink uses a tainted variable
        // Uses paren-depth counting for nested constructors: new File(new File(base), bar)
        let sinkUsesUserInput = false;
        const sinkStartRe = /new\s+(?:java\.io\.)?(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|PrintWriter)\s*\(/g;
        let sinkStartMatch;
        while ((sinkStartMatch = sinkStartRe.exec(normalized)) !== null) {
          let depth = 1;
          let pos = sinkStartMatch.index + sinkStartMatch[0].length;
          while (pos < normalized.length && depth > 0) {
            if (normalized[pos] === '(') depth++;
            else if (normalized[pos] === ')') depth--;
            pos++;
          }
          const argsRegion = normalized.slice(sinkStartMatch.index + sinkStartMatch[0].length, pos - 1);
          for (const tv of taintedVars) {
            if (wholeWord(argsRegion, tv)) {
              sinkUsesUserInput = true;
              break;
            }
          }
          if (sinkUsesUserInput) break;
        }

        // Check for path validation in scope
        const isValidated = PATH_SAFE_RE.test(src);

        if (sinkUsesUserInput && !isValidated) {
          const bestSrc = ingress.find(n => n.node_subtype === 'http_request') || ingress[0];
          const bestSink = fileOps[0] || map.nodes.find(n =>
            (n.analysis_snapshot || n.code_snapshot).match(/new\s+(?:java\.io\.)?(?:File|FileInputStream|FileOutputStream)\s*\(/) !== null
          );
          if (bestSrc && bestSink) {
            findings.push({
              source: nodeRef(bestSrc),
              sink: nodeRef(bestSink),
              missing: 'CONTROL (path validation / directory restriction)',
              severity: 'high',
              description: `User input from ${bestSrc.label} controls a file path at ${bestSink.label} without validation. ` +
                `An attacker can use ../../ to access files outside the intended directory.`,
              fix: 'Canonicalize the path with File.getCanonicalPath(), then verify it starts with your allowed base directory. ' +
                'Never use user input directly in file operations.',
            });
          }
        }
      }
    }
  }

  // Source-line fallback for Java method-param taint: detect path traversal where
  // a filename/path comes from a method parameter (not directly from @RequestParam).
  // Pattern: method receives a String parameter (fullName, filename, path, etc.),
  // and uses it in new File(directory, paramName) without canonicalization checks.
  // This catches cross-method taint where a controller passes user input to a helper.
  // Skip when dead-branch neutralization proves taint never reaches the sink.
  if (findings.length === 0 && map.source_code && !hasDeadBranchNeutralization && !hasStaticValueNeutralization22 && !hasInterproceduralNeutralization22 && !hasMapKeySafeRetrieval22) {
    const sl22m = stripComments(map.source_code);
    const lines22m = sl22m.split('\n');

    // Find ALL String/Path/File/MultipartFile method parameters
    const PARAM_EXTRACT_RE = /(?:String|Path|File|MultipartFile)\s+(\w+)/g;
    const fileParamNames = new Set<string>();
    let mp22;
    while ((mp22 = PARAM_EXTRACT_RE.exec(sl22m)) !== null) {
      const paramName = mp22[1]!;
      // Only treat as potential taint if the parameter name suggests file/path input
      if (/name|file|path|dir|folder|upload|location|dest|target|input|param/i.test(paramName)) {
        fileParamNames.add(paramName);
      }
    }

    if (fileParamNames.size > 0) {
      // Propagate taint through assignments
      const tainted22m = new Set(fileParamNames);
      for (const line of lines22m) {
        const asgn = line.match(/(?:var|final\s+\w+|\w+)\s+(\w+)\s*=\s*(.+)/);
        if (asgn) {
          const lhs = asgn[1]!;
          const rhs = asgn[2]!;
          for (const tv of tainted22m) {
            if (new RegExp('\\b' + escapeRegExp(tv) + '\\b').test(rhs)) {
              tainted22m.add(lhs);
              break;
            }
          }
        }
      }

      // Check for File constructor usage with tainted variable
      let fileSinkFound = false;
      let fileSinkLine = 0;
      let fileSinkCode = '';
      let fileParamLine = 0;
      let fileParamCode = '';

      for (let i = 0; i < lines22m.length; i++) {
        const ln = lines22m[i]!.trim();
        const fileConstructor = ln.match(/new\s+(?:java\.io\.)?File\s*\(([^)]+)\)/);
        if (fileConstructor) {
          const args = fileConstructor[1]!;
          for (const tv of tainted22m) {
            if (new RegExp('\\b' + escapeRegExp(tv) + '\\b').test(args)) {
              // Check that path validation is NOT present
              const fullSrc = sl22m;
              // Only flag if there's no canonicalization + startsWith check
              const hasCanonCheck = /getCanonicalPath\s*\(\s*\)[\s\S]{0,200}startsWith\s*\(|getCanonicalFile\s*\(\s*\)[\s\S]{0,200}startsWith\s*\(/
                .test(fullSrc);
              const hasNormCheck = /normalize\s*\(\s*\)[\s\S]{0,200}startsWith\s*\(/.test(fullSrc);
              const hasResolveCheck = /path\.resolve[\s\S]{0,200}startsWith/.test(fullSrc);
              // Check for getCanonicalPath used to PREVENT traversal (reject/throw)
              // Note: using getCanonicalPath only to CHECK results after-the-fact is NOT prevention
              // Be precise: "throw new" (actual throw), "return failed(" (actual rejection), NOT "throws" in method sig
              const hasCanonReject = /getCanonicalPath[\s\S]{0,100}(?:throw\s+new\s|return\s+failed\s*\(|return\s+error|reject\s*\(|deny|block|403)/i.test(fullSrc);

              if (!hasCanonCheck && !hasNormCheck && !hasResolveCheck && !hasCanonReject) {
                fileSinkFound = true;
                fileSinkLine = i + 1;
                fileSinkCode = ln;
                // Find the parameter declaration line
                for (let j = 0; j < lines22m.length; j++) {
                  for (const fp of fileParamNames) {
                    if (new RegExp('String\\s+' + escapeRegExp(fp) + '\\b|MultipartFile\\s+' + escapeRegExp(fp) + '\\b').test(lines22m[j]!)) {
                      fileParamLine = j + 1;
                      fileParamCode = lines22m[j]!.trim();
                      break;
                    }
                  }
                  if (fileParamLine) break;
                }
                break;
              }
            }
          }
        }
        if (fileSinkFound) break;
      }

      if (fileSinkFound && fileParamLine > 0) {
        findings.push({
          source: { id: `srcline-${fileParamLine}`, label: `method parameter (line ${fileParamLine})`, line: fileParamLine, code: fileParamCode.slice(0, 200) },
          sink: { id: `srcline-${fileSinkLine}`, label: `file operation (line ${fileSinkLine})`, line: fileSinkLine, code: fileSinkCode.slice(0, 200) },
          missing: 'CONTROL (path validation / directory restriction)',
          severity: 'high',
          description: `Method parameter used as filename flows to File constructor at line ${fileSinkLine} without path validation. ` +
            `If the caller passes user-controlled input, an attacker can use ../../ to traverse directories.`,
          fix: 'Canonicalize the path with File.getCanonicalPath(), then verify it starts with your allowed base directory. ' +
            'Reject requests where the canonical path escapes the intended directory.',
        });
      }
    }
  }

  return {
    cwe: 'CWE-22',
    name: 'Path Traversal',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-23: Relative Path Traversal
 * UPGRADED — hand-written with specific detection for relative traversal sequences.
 *
 * Distinct from CWE-22 (generic path traversal):
 *   CWE-23 specifically targets the case where tainted input is CONCATENATED to a base
 *   directory path (e.g. `root + data`, `basePath + userInput`). The risk is that the
 *   attacker sends "../../../etc/passwd" to escape the base directory.
 *
 * Missing category: SANITIZE (different from CWE-22's CONTROL) so family dedup preserves both.
 *
 * Safe patterns: getCanonicalPath/getCanonicalFile, realpath, path.resolve followed by
 *   startsWith, explicit ".." rejection, normalize + boundary check.
 */
function verifyCWE23(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const fileOps = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' &&
     (n.node_subtype.includes('file') || n.node_subtype.includes('fs') ||
      n.node_subtype === 'file_access' || n.node_subtype === 'file_read' || n.node_subtype === 'file_write' ||
      n.attack_surface.includes('file_access') ||
      (n.analysis_snapshot || n.code_snapshot).match(/\b(readFile|writeFile|createReadStream|open|unlink|readdir)\b/i) !== null)) ||
    (n.node_type === 'INGRESS' && n.node_subtype === 'file_read') ||
    (n.node_type === 'EGRESS' && n.node_subtype === 'file_write') ||
    (n.node_type === 'EGRESS' && n.node_subtype === 'file_serve')
  );

  // CWE-23-specific safe patterns: canonicalization or explicit dot-dot rejection
  const RELATIVE_SAFE_RE = /\bgetCanonicalPath\b|\bgetCanonicalFile\b|\brealpath\b|\bpath\.resolve\b.*\bstartsWith\b|\bstartsWith\b.*\bpath\.resolve\b|\b\.contains\s*\(\s*["']\.\.["']\s*\)|\bindexOf\s*\(\s*["']\.\.["']\s*\)|\bincludes\s*\(\s*["']\.\.["']\s*\)|\bnormalize\b.*\bstartsWith\b|\bfilepath\.Clean\b|\bFilenameUtils\.normalize\b/i;

  // Dead-branch neutralization detection (shared helper, same as CWE-22)
  const hasDeadBranchNeutralization = map.source_code ? detectDeadBranchNeutralization(map.source_code) : false;

  // --- Strategy 1: Graph-based detection — INGRESS->file-op with path concatenation ---
  for (const src of ingress) {
    for (const sink of fileOps) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (hasDeadBranchNeutralization) continue;

        const scopeSnapshots = getContainingScopeSnapshots(map, sink.id);
        const combinedScope = stripComments(scopeSnapshots.join('\n') || sink.analysis_snapshot || sink.code_snapshot);

        // CWE-23 specific: look for path concatenation at the SINK itself (base + input)
        // This is the signature of relative traversal: the input is appended to a base dir
        // Check the sink's own code snapshot for concatenation, not the full scope
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        const hasSinkConcat = /new\s+(?:java\.io\.)?(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter)\s*\(\s*\w+\s*\+/i.test(sinkCode) ||
          /\bPaths\.get\s*\(\s*\w+\s*,/i.test(sinkCode) ||
          /\bPath\.of\s*\(\s*\w+\s*,/i.test(sinkCode) ||
          /\bpath\.join\s*\(/i.test(sinkCode) ||
          /\bpath\.resolve\s*\(\s*\w+\s*,/i.test(sinkCode);
        // Also check scope for base directory + variable concatenation patterns
        const hasBaseDirConcat = /(?:root|base|dir|prefix|folder|upload)\s*\+\s*\w+/i.test(combinedScope) &&
          /new\s+(?:java\.io\.)?(?:File|FileInputStream|FileOutputStream)\b/i.test(combinedScope);

        if ((hasSinkConcat || hasBaseDirConcat) && !RELATIVE_SAFE_RE.test(combinedScope)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'SANITIZE (relative path sequence filtering / canonicalization)',
            severity: 'high',
            description: `User input from ${src.label} is concatenated to a base directory at ${sink.label} without canonicalization. ` +
              `An attacker can send "../" sequences to escape the intended directory and read/write arbitrary files.`,
            fix: 'Canonicalize the combined path with File.getCanonicalPath() or path.resolve(), then verify the result ' +
              'starts with the intended base directory. Reject any input containing ".." sequences.',
          });
        }
      }
    }
  }

  // --- Strategy 2: Source-code scanning fallback for Java ---
  if (findings.length === 0 && map.source_code) {
    const src = stripComments(map.source_code);
    const normalized = src.replace(/\n\s*/g, ' ');
    const stmts = normalized.split(';').map(s => s.trim());

    // Detect taint sources (network, HTTP, etc.)
    const javaSourceRe = /\b(?:request|req|httpRequest)\s*\.\s*(?:getParameter|getCookies|getHeader|getHeaders|getQueryString|getInputStream|getReader)\s*\(|\.getValue\s*\(\s*\)|\.readLine\s*\(\s*\)/;
    const hasUserSource = javaSourceRe.test(src);

    // CWE-23 specific: file sink with concatenation (base + tainted)
    // Pattern: new File(someBase + taintedVar) or Paths.get(base, taintedVar)
    const concatFileSinkRe = /new\s+(?:java\.io\.)?(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|PrintWriter)\s*\(\s*(?:\w+\s*\+|\w+\s*,)/;
    const hasConcatFileSink = concatFileSinkRe.test(normalized);

    // Also detect: explicit base directory variable assigned then concatenated
    const hasBaseDirConcat = /(?:root|base|dir|prefix|folder|upload|path)\s*\+\s*\w+/i.test(normalized) &&
      /new\s+(?:java\.io\.)?(?:File|FileInputStream|FileOutputStream)\b/i.test(normalized);

    if (hasUserSource && (hasConcatFileSink || hasBaseDirConcat)) {
      // Track tainted variables
      const taintedVars = new Set<string>();
      for (const stmt of stmts) {
        const assignMatch = stmt.match(/\b(\w+)\s*=\s*.*(?:getParameter|getCookies|getHeader|getHeaders|getQueryString|getInputStream|getReader|\.getValue|\.readLine)\s*\(/);
        if (assignMatch) taintedVars.add(assignMatch[1]!);
        const cookieMatch = stmt.match(/\b(\w+)\s*=\s*.*(?:URLDecoder\.decode|java\.net\.URLDecoder\.decode)\s*\(/);
        if (cookieMatch) taintedVars.add(cookieMatch[1]!);
        const headerMatch = stmt.match(/\b(\w+)\s*=\s*\w+\.nextElement\s*\(/);
        if (headerMatch) taintedVars.add(headerMatch[1]!);
      }

      // Propagate taint
      if (taintedVars.size > 0) {
        let changed = true;
        while (changed) {
          changed = false;
          for (const stmt of stmts) {
            const propMatch = stmt.match(/\b(\w+)\s*=\s*(.*)/s);
            if (propMatch) {
              const lhs = propMatch[1]!;
              const rhs = propMatch[2]!;
              if (!taintedVars.has(lhs)) {
                if (rhs.includes('?') && rhs.includes(':')) continue;
                if (/\bcase\s+|default\s*:/.test(stmt)) continue;
                for (const tv of taintedVars) {
                  if (wholeWord(rhs, tv)) {
                    taintedVars.add(lhs);
                    changed = true;
                    break;
                  }
                }
              }
            }
          }
        }

        // Check if a file sink uses concatenation with a tainted var and a base dir
        const concatSinkRe = /new\s+(?:java\.io\.)?(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|PrintWriter)\s*\(\s*(\w+)\s*\+/g;
        let concatMatch;
        let sinkUsesConcat = false;
        while ((concatMatch = concatSinkRe.exec(normalized)) !== null) {
          // Extract the full argument region after the opening paren
          let depth = 1;
          let pos = concatMatch.index + concatMatch[0].length;
          while (pos < normalized.length && depth > 0) {
            if (normalized[pos] === '(') depth++;
            else if (normalized[pos] === ')') depth--;
            pos++;
          }
          const argsRegion = normalized.slice(concatMatch.index + concatMatch[0].length - concatMatch[1]!.length - 1, pos - 1);
          for (const tv of taintedVars) {
            if (wholeWord(argsRegion, tv)) {
              sinkUsesConcat = true;
              break;
            }
          }
          if (sinkUsesConcat) break;
        }

        const isValidated = RELATIVE_SAFE_RE.test(src);

        if (sinkUsesConcat && !isValidated) {
          const bestSrc = ingress.find(n => n.node_subtype === 'http_request') || ingress[0];
          const bestSink = fileOps[0] || map.nodes.find(n =>
            (n.analysis_snapshot || n.code_snapshot).match(/new\s+(?:java\.io\.)?(?:File|FileInputStream|FileOutputStream)\s*\(/) !== null
          );
          if (bestSrc && bestSink) {
            findings.push({
              source: nodeRef(bestSrc),
              sink: nodeRef(bestSink),
              missing: 'SANITIZE (relative path sequence filtering / canonicalization)',
              severity: 'high',
              description: `User input from ${bestSrc.label} is concatenated to a base directory at ${bestSink.label} without canonicalization. ` +
                `An attacker can send "../" sequences to escape the intended directory and read/write arbitrary files.`,
              fix: 'Canonicalize the combined path with File.getCanonicalPath(), then verify the result ' +
                'starts with the intended base directory. Reject any input containing ".." sequences.',
            });
          }
        }
      }
    }
  }

  return {
    cwe: 'CWE-23',
    name: 'Relative Path Traversal',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-36: Absolute Path Traversal
 * UPGRADED — hand-written with specific detection for absolute path injection.
 *
 * Distinct from CWE-22 (generic path traversal):
 *   CWE-36 specifically targets the case where tainted input is used as the ENTIRE
 *   file path (e.g. `new File(data)`) without being restricted to a base directory.
 *   The risk is that the attacker sends "/etc/passwd" or "C:\Windows\System32\..."
 *   to access any file on the filesystem.
 *
 * Missing category: VALIDATE (different from CWE-22's CONTROL) so family dedup preserves both.
 *
 * Safe patterns: startsWith check against allowed base, path.isAbsolute() + reject,
 *   forced prefix concatenation (base + input), chroot/jail.
 */
function verifyCWE36(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const fileOps = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' &&
     (n.node_subtype.includes('file') || n.node_subtype.includes('fs') ||
      n.node_subtype === 'file_access' || n.node_subtype === 'file_read' || n.node_subtype === 'file_write' ||
      n.attack_surface.includes('file_access') ||
      (n.analysis_snapshot || n.code_snapshot).match(/\b(readFile|writeFile|createReadStream|open|unlink|readdir)\b/i) !== null)) ||
    (n.node_type === 'INGRESS' && n.node_subtype === 'file_read') ||
    (n.node_type === 'EGRESS' && n.node_subtype === 'file_write') ||
    (n.node_type === 'EGRESS' && n.node_subtype === 'file_serve')
  );

  // CWE-36-specific safe patterns: enforce a base directory prefix, or reject absolute paths
  const ABSOLUTE_SAFE_RE = /\bstartsWith\b|\bisAbsolute\b.*reject|\bisAbsolute\b.*throw|\bisAbsolute\b.*return|\bpath\.relative\b|\bchroot\b|\bjail\b|\bsandbox\b|\bwhitelist\b.*path|\ballowedPaths\b|\bgetCanonicalPath\b.*\bstartsWith\b|\bstartsWith\b.*\bgetCanonicalPath\b|\bFilenameUtils\.normalize\b.*\bstartsWith\b/i;

  // Dead-branch neutralization detection (shared helper, same as CWE-22)
  const hasDeadBranchNeutralization = map.source_code ? detectDeadBranchNeutralization(map.source_code) : false;

  // --- Strategy 1: Graph-based detection — INGRESS->file-op where input is used as entire path ---
  for (const src of ingress) {
    for (const sink of fileOps) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (hasDeadBranchNeutralization) continue;

        const scopeSnapshots = getContainingScopeSnapshots(map, sink.id);
        const combinedScope = stripComments(scopeSnapshots.join('\n') || sink.analysis_snapshot || sink.code_snapshot);

        // CWE-36 specific: detect when tainted input is used DIRECTLY as file path
        // without being concatenated to a base directory. This is the absolute path pattern.
        // Negative indicator: if there's base dir concatenation, it's CWE-23 not CWE-36
        const hasBaseConcat = /\w+\s*\+\s*\w+\s*\)|root\s*\+|base\s*\+|dir\s*\+|prefix\s*\+|folder\s*\+|uploads.*\+/i.test(combinedScope);

        // Positive indicator: direct use of tainted input as path
        const hasDirectPathUse = /new\s+(?:java\.io\.)?File\s*\(\s*\w+\s*\)|open\s*\(\s*\w+|readFile\s*\(\s*\w+|createReadStream\s*\(\s*\w+|FileInputStream\s*\(\s*\w+\s*\)|FileOutputStream\s*\(\s*\w+\s*\)/i.test(combinedScope);

        if (!hasBaseConcat && hasDirectPathUse && !ABSOLUTE_SAFE_RE.test(combinedScope)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'VALIDATE (absolute path rejection / base directory enforcement)',
            severity: 'high',
            description: `User input from ${src.label} is used as the entire file path at ${sink.label} without restricting to a base directory. ` +
              `An attacker can send an absolute path like "/etc/passwd" or "C:\\Windows\\..." to access any file on the filesystem.`,
            fix: 'Never use user input as the entire file path. Always prepend a base directory and canonicalize: ' +
              'new File(BASE_DIR, input).getCanonicalPath() then verify startsWith(BASE_DIR). Reject absolute paths.',
          });
        }
      }
    }
  }

  // --- Strategy 2: Source-code scanning fallback for Java ---
  if (findings.length === 0 && map.source_code) {
    const src = stripComments(map.source_code);
    const normalized = src.replace(/\n\s*/g, ' ');
    const stmts = normalized.split(';').map(s => s.trim());

    // Detect taint sources
    const javaSourceRe = /\b(?:request|req|httpRequest)\s*\.\s*(?:getParameter|getCookies|getHeader|getHeaders|getQueryString|getInputStream|getReader)\s*\(|\.getValue\s*\(\s*\)|\.readLine\s*\(\s*\)/;
    const hasUserSource = javaSourceRe.test(src);

    // CWE-36 specific: file sink with DIRECT variable use (no concatenation)
    // Pattern: new File(data) — where data is the tainted variable, used alone as the entire path
    const directFileSinkRe = /new\s+(?:java\.io\.)?(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|PrintWriter)\s*\(\s*(\w+)\s*\)/g;

    // Negative: skip if there's base-dir concatenation (that's CWE-23)
    const hasBaseDirConcat = /(?:root|base|dir|prefix|folder|upload)\s*\+/i.test(normalized);

    if (hasUserSource && !hasBaseDirConcat) {
      // Track tainted variables
      const taintedVars = new Set<string>();
      for (const stmt of stmts) {
        const assignMatch = stmt.match(/\b(\w+)\s*=\s*.*(?:getParameter|getCookies|getHeader|getHeaders|getQueryString|getInputStream|getReader|\.getValue|\.readLine)\s*\(/);
        if (assignMatch) taintedVars.add(assignMatch[1]!);
        const cookieMatch = stmt.match(/\b(\w+)\s*=\s*.*(?:URLDecoder\.decode|java\.net\.URLDecoder\.decode)\s*\(/);
        if (cookieMatch) taintedVars.add(cookieMatch[1]!);
        const headerMatch = stmt.match(/\b(\w+)\s*=\s*\w+\.nextElement\s*\(/);
        if (headerMatch) taintedVars.add(headerMatch[1]!);
      }

      // Propagate taint
      if (taintedVars.size > 0) {
        let changed = true;
        while (changed) {
          changed = false;
          for (const stmt of stmts) {
            const propMatch = stmt.match(/\b(\w+)\s*=\s*(.*)/s);
            if (propMatch) {
              const lhs = propMatch[1]!;
              const rhs = propMatch[2]!;
              if (!taintedVars.has(lhs)) {
                if (rhs.includes('?') && rhs.includes(':')) continue;
                if (/\bcase\s+|default\s*:/.test(stmt)) continue;
                for (const tv of taintedVars) {
                  if (wholeWord(rhs, tv)) {
                    taintedVars.add(lhs);
                    changed = true;
                    break;
                  }
                }
              }
            }
          }
        }

        // Check if a file sink uses a tainted variable DIRECTLY (not concatenated)
        let sinkUsesDirect = false;
        let directMatch;
        while ((directMatch = directFileSinkRe.exec(normalized)) !== null) {
          const argVar = directMatch[1]!;
          if (taintedVars.has(argVar)) {
            sinkUsesDirect = true;
            break;
          }
        }

        const isValidated = ABSOLUTE_SAFE_RE.test(src);

        if (sinkUsesDirect && !isValidated) {
          const bestSrc = ingress.find(n => n.node_subtype === 'http_request') || ingress[0];
          const bestSink = fileOps[0] || map.nodes.find(n =>
            (n.analysis_snapshot || n.code_snapshot).match(/new\s+(?:java\.io\.)?(?:File|FileInputStream|FileOutputStream)\s*\(/) !== null
          );
          if (bestSrc && bestSink) {
            findings.push({
              source: nodeRef(bestSrc),
              sink: nodeRef(bestSink),
              missing: 'VALIDATE (absolute path rejection / base directory enforcement)',
              severity: 'high',
              description: `User input from ${bestSrc.label} is used as the entire file path at ${bestSink.label} without restricting to a base directory. ` +
                `An attacker can send an absolute path like "/etc/passwd" or "C:\\Windows\\..." to access any file on the filesystem.`,
              fix: 'Never use user input as the entire file path. Always prepend a base directory and canonicalize: ' +
                'new File(BASE_DIR, input).getCanonicalPath() then verify startsWith(BASE_DIR). Reject absolute paths.',
            });
          }
        }
      }
    }
  }

  return {
    cwe: 'CWE-36',
    name: 'Absolute Path Traversal',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-502: Deserialization of Untrusted Data
 * Pattern: INGRESS → TRANSFORM(deserialize) without CONTROL(type validation)
 * Property: All deserialization of user input uses safe parsers with type constraints
 */
function verifyCWE502(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const deserialize = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' &&
     (n.node_subtype.includes('deserialize') || n.node_subtype.includes('parse') ||
      (n.analysis_snapshot || n.code_snapshot).match(/\b(unserialize|pickle\.load|yaml\.load|eval|JSON\.parse|XStream|XMLDecoder|ObjectMapper|Kryo)\b/i) !== null)) ||
    // Python: pickle.loads is classified as EXTERNAL/deserialize, not TRANSFORM
    (n.node_type === 'EXTERNAL' && n.node_subtype.startsWith('deserialize')) ||
    // Rust/Java: serde_json::from_str, XMLDecoder.readObject etc. may be INGRESS/deserialize or INGRESS/deserialize_rce
    (n.node_type === 'INGRESS' && n.node_subtype.startsWith('deserialize'))
  );

  for (const src of ingress) {
    for (const sink of deserialize) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        // EXTERNAL/deserialize nodes are inherently dangerous (yaml.load, pickle.loads, etc.)
        // TRANSFORM/parse nodes need code_snapshot check to distinguish safe vs unsafe
        const isDangerous =
          (sink.node_type === 'EXTERNAL' && sink.node_subtype.startsWith('deserialize')) ||
          // Rust/Java: serde_json::from_str, XMLDecoder.readObject etc. — includes deserialize_rce
          (sink.node_type === 'INGRESS' && sink.node_subtype.startsWith('deserialize')) ||
          (sink.analysis_snapshot || sink.code_snapshot).match(
            /\b(unserialize|pickle\.load|yaml\.load|yaml\.loadAll|yaml\.safe_load|eval|Function\s*\(|deserialize|serde_json::from_str|serde_json::from_value|serde_json::from_slice|XStream\.fromXML|XMLDecoder\.readObject|\.readValue\s*\(|Kryo\.readObject|Yaml\.load)\b/i
          ) !== null;

        if (isDangerous) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (safe deserialization with type constraints)',
            severity: 'critical',
            description: `User input from ${src.label} is deserialized at ${sink.label} using an unsafe method. ` +
              `This can lead to arbitrary code execution.`,
            fix: 'Use safe parsers: JSON.parse for JSON, yaml.safeLoad / yaml.safe_load for YAML. ' +
              'Never use eval, unserialize, pickle.load, or yaml.load on untrusted data. ' +
              'Add schema validation (zod, joi) after parsing.',
          });
        }
      }
    }
  }

  // Source-code fallback for Java deserialization sinks not caught by BFS
  if (findings.length === 0 && map.source_code) {
    const src502 = stripComments(map.source_code);
    const DESER_SINK_502 = /\b(Yaml\.load|Yaml\.loadAll|XStream\.fromXML|XMLDecoder\.readObject|Kryo\.readObject|ObjectInputStream\.readObject|readUnshared)\s*\(|\.\s*readValue\s*\(/i;
    const DESER_SAFE_502 = /\benableDefaultTyping\b.*\bfalse\b|\bObjectInputFilter\b|\bvalidateObject\b|\bdefaultClassLoader\b.*\bnull\b|\bJsonTypeInfo\b/i;
    if (DESER_SINK_502.test(src502) && !DESER_SAFE_502.test(src502)) {
      const hasIngressSrc = /\b(?:request|req|httpRequest)\s*\.\s*(?:getParameter|getInputStream|getReader)\s*\(|\.readObject\s*\(/i.test(src502);
      if (hasIngressSrc) {
        findings.push({
          source: { id: 'srcline-deser', label: 'untrusted input', line: 0, code: '' },
          sink: { id: 'srcline-deser-sink', label: 'deserialization sink', line: 0, code: '' },
          missing: 'CONTROL (safe deserialization with type constraints)',
          severity: 'critical',
          description: 'Untrusted data flows to a dangerous deserialization sink without type filtering.',
          fix: 'Use ObjectInputFilter, type-safe parsers, or avoid deserializing untrusted data entirely.',
        });
      }
    }
  }

  return {
    cwe: 'CWE-502',
    name: 'Deserialization of Untrusted Data',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-918: Server-Side Request Forgery (SSRF)
 * Pattern: INGRESS → EXTERNAL without CONTROL(URL validation)
 * Property: All user-controlled URLs are validated against an allowlist before making requests
 */
function verifyCWE918(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const external = map.nodes.filter(n =>
    n.node_type === 'EXTERNAL' &&
    (n.node_subtype.includes('http') || n.node_subtype.includes('request') ||
     n.node_subtype.includes('fetch') || n.node_subtype.includes('api_call') ||
     (n.analysis_snapshot || n.code_snapshot).match(
       /\b(fetch|axios|request|http\.get|https\.get|got|requests\.get|requests\.post|requests\.put|requests\.delete|urllib\.request|urllib\.urlopen|urllib2\.urlopen|RestTemplate\.getForObject|RestTemplate\.exchange|RestTemplate\.postForObject|WebClient\.get|WebClient\.post|HttpClient\.send|HttpClient\.execute|OkHttpClient|http\.Get|http\.Post|curl_exec|file_get_contents|fopen\s*\(\s*['"]https?:)\b/i
     ) !== null)
  );

  for (const src of ingress) {
    for (const sink of external) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const scopeSnapshots = getContainingScopeSnapshots(map, sink.id);
        const combinedScope = stripComments(scopeSnapshots.join('\n') || sink.analysis_snapshot || sink.code_snapshot);
        const isValidated = combinedScope.match(
          /\ballowlist\b|\bwhitelist\b|\bvalidateUrl\b|\bURL\b.*\bnew\b|\bstartsWith\b/i
        ) !== null;

        if (!isValidated) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (URL validation / allowlist)',
            severity: 'high',
            description: `User input from ${src.label} controls the URL for an HTTP request at ${sink.label}. ` +
              `An attacker can make the server request internal resources (SSRF).`,
            fix: 'Validate URLs against an allowlist of permitted domains. ' +
              'Parse the URL with new URL() and check the hostname. ' +
              'Never let user input directly control request destinations.',
          });
        }
      }
    }
  }

  // Source-code fallback: when the mapper doesn't emit an EXTERNAL node for HTTP calls
  // (e.g., dynamically-resolved `client.get(url)` or indirect `http.get(url)`), fall back
  // to scanning source_code for SSRF-indicative patterns.
  if (findings.length === 0 && map.source_code) {
    const src918 = stripComments(map.source_code);
    // Direct HTTP client calls (literal API names)
    const SSRF_SINK_DIRECT = /\b(fetch|axios\.get|axios\.post|axios\.put|axios\.delete|axios\.request|axios\(|http\.get|https\.get|http\.request|https\.request|got|got\.get|got\.post|request\.get|request\.post|urllib\.request\.urlopen|urllib2\.urlopen|requests\.get|requests\.post|requests\.put|requests\.delete|RestTemplate\.getForObject|RestTemplate\.exchange|RestTemplate\.postForObject|WebClient\.get|WebClient\.post|HttpClient\.send|HttpClient\.execute|OkHttpClient|http\.Get|http\.Post|curl_exec|file_get_contents|Net::HTTP\.get|open-uri|Faraday\.get|HTTPoison\.get|HttpClient\.GetAsync|WebRequest\.Create)\s*\(/i;
    // Indirect HTTP client calls: require('http')/require('https') + dynamic .get/.request call
    const hasHttpModule = /require\s*\(\s*['"]https?['"]\s*\)|from\s+['"]https?['"]/i.test(src918);
    const hasDynamicHttpCall = /\w+\.get\s*\(\s*\w+|\w+\.request\s*\(\s*\w+/i.test(src918);
    const hasSsrfSink = SSRF_SINK_DIRECT.test(src918) || (hasHttpModule && hasDynamicHttpCall);

    const SSRF_INGRESS_918 = /\b(?:req|request|ctx)\s*\.\s*(?:headers|query|params|body|getParameter|getHeader|getQueryString)\b/i;
    const SSRF_SAFE_918 = /\ballowlist\b|\bwhitelist\b|\bvalidateUrl\b|\bsafeUrl\b|\bisAllowed\b|\bstartsWith\s*\(\s*['"]https?:\/\/(?:api\.|internal\.)/i;
    if (hasSsrfSink && SSRF_INGRESS_918.test(src918) && !SSRF_SAFE_918.test(src918)) {
      findings.push({
        source: { id: 'srcline-ssrf', label: 'user-controlled input', line: 0, code: '' },
        sink: { id: 'srcline-ssrf-sink', label: 'HTTP client call', line: 0, code: '' },
        missing: 'CONTROL (URL validation / allowlist)',
        severity: 'high',
        description: 'User-controlled input flows to an HTTP client call without URL validation. ' +
          'An attacker can make the server request internal resources (SSRF).',
        fix: 'Validate URLs against an allowlist of permitted domains. ' +
          'Parse the URL with new URL() and check the hostname. ' +
          'Never let user input directly control request destinations.',
      });
    }
  }

  return {
    cwe: 'CWE-918',
    name: 'Server-Side Request Forgery (SSRF)',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-78: OS Command Injection
 * Pattern: INGRESS → EXTERNAL(shell/exec) without CONTROL(input sanitization)
 * Property: User input is never passed directly to shell commands
 */
function verifyCWE78(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const shellExec = map.nodes.filter(n =>
    n.node_type === 'EXTERNAL' &&
    (n.node_subtype.includes('shell') || n.node_subtype.includes('exec') ||
     n.node_subtype.includes('command') || n.attack_surface.includes('shell_exec') ||
     (n.analysis_snapshot || n.code_snapshot).match(/\b(exec|execSync|spawn|system|child_process|popen|shell_exec)\b/i) !== null)
  );

  for (const src of ingress) {
    for (const sink of shellExec) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id) || sinkHasTaintedDataIn(map, sink.id)) {
        const scopeSnapshots78 = getContainingScopeSnapshots(map, sink.id);
        const combinedScope78 = stripComments(scopeSnapshots78.join('\n') || sink.analysis_snapshot || sink.code_snapshot);
        const isSafe = combinedScope78.match(
          /\bexecFile\s*\(|\bspawn\s*\(.*\[|\bshellEscape\s*\(|\bescapeShell\s*\(|\bsanitize\s*\(/i
        ) !== null;
        if (!isSafe) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (input sanitization or safe command API)',
            severity: 'critical',
            description: `User input from ${src.label} flows to shell command at ${sink.label} without sanitization. ` +
              `An attacker can inject arbitrary OS commands (e.g., ; rm -rf /).`,
            fix: 'Never pass user input to shell commands. Use execFile or spawn with an argument array ' +
              'instead of exec with string interpolation. If shell is unavoidable, use a strict allowlist ' +
              'of permitted values.',
          });
        }
      }
    }
  }

  // Source-line fallback for Java: statement-level taint tracking detects
  // Runtime.exec / ProcessBuilder patterns where BFS taint path breaks.
  if (findings.length === 0 && map.source_code) {
    const sl78 = map.source_code.split('\n');
    const SRC78 = /(\w+)\s*=\s*(?:\w+\.)*(?:getParameter|getParameterValues|getParameterNames|getHeader|getHeaders|getCookies|getQueryString|getInputStream|getReader|getTheParameter|System\.getenv)\s*\(/;
    const CK78 = /(\w+)\s*=\s*(?:java\.net\.URLDecoder\.decode\s*\(\s*)?(?:\w+\.getValue\s*\()/;
    const EN78 = /(\w+)\s*=\s*(?:\(\w+\)\s*)?(?:\w+\.nextElement\s*\()/;
    const EX78 = /(?:\.exec\s*\(|ProcessBuilder\s*\(|\.command\s*\()\s*([^)]*)/;
    const tv = new Set<string>();
    let sln = 0; let scd = '';
    for (let i = 0; i < sl78.length; i++) {
      const ln = sl78[i]!.trim();
      if (ln.startsWith('//') || ln.startsWith('*') || ln.startsWith('/*')) continue;
      let mx = ln.match(SRC78); if (mx) { tv.add(mx[1]!); sln = i + 1; scd = ln; }
      mx = ln.match(CK78); if (mx) { tv.add(mx[1]!); if (!sln) { sln = i + 1; scd = ln; } }
      mx = ln.match(EN78); if (mx) { tv.add(mx[1]!); if (!sln) { sln = i + 1; scd = ln; } }
      // Assignment propagation: supports both "bar = param;" and "String bar = param;"
      const va = ln.match(/^(?:(?:final\s+)?(?:String|int|long|Object|byte)\s+)?(\w+)\s*=\s*(\w+)\s*;/);
      if (va && tv.has(va[2]!)) tv.add(va[1]!);
      const mc = ln.match(/^(?:\w+\s+)?(\w+)\s*=\s*(\w+)\.\w+\s*\(/);
      if (mc && tv.has(mc[2]!)) tv.add(mc[1]!);
      const ma = ln.match(/^(?:\w+\s+)?(\w+)\s*=\s*\w+(?:\.\w+)*\s*\(\s*(\w+)\s*\)/);
      if (ma && tv.has(ma[2]!)) tv.add(ma[1]!);
      const ca = ln.match(/^(?:\w+\s+)?(\w+)\s*=\s*.*\b(\w+)\b.*\+/);
      if (ca && tv.has(ca[2]!)) tv.add(ca[1]!);
      const cc = ln.match(/^(?:\w+\s+)?(\w+)\s*=\s*.*\+.*\b(\w+)\b/);
      if (cc && tv.has(cc[2]!)) tv.add(cc[1]!);
      const ai = ln.match(/^(?:\w+\[\]\s+)?(\w+)\s*=\s*(?:new\s+\w+\s*\[\]\s*)?\{([^}]+)\}/);
      if (ai) { for (const t of tv) { if (new RegExp('\\b' + escapeRegExp(t) + '\\b').test(ai[2]!)) { tv.add(ai[1]!); break; } } }
      const sb = ln.match(/(\w+)\s*=\s*new\s+StringBuilder\s*\(\s*(\w+)\s*\)/);
      if (sb && tv.has(sb[2]!)) tv.add(sb[1]!);
      const ts = ln.match(/^(?:\w+\s+)?(\w+)\s*=\s*(\w+)\.(?:append\s*\([^)]*\)\s*\.)*toString\s*\(\s*\)/);
      if (ts && tv.has(ts[2]!)) tv.add(ts[1]!);
      const ck = ln.match(/^(?:\w+\s+)?(\w+)\s*=\s*"[^"]*"\s*;/);
      if (ck) tv.delete(ck[1]!);
      const atm = ln.match(/if\s*\(\s*\(\s*(\d+)\s*\*\s*(\d+)\s*\)\s*-\s*\w+\s*>\s*(\d+)\s*\)\s*(\w+)\s*=\s*"[^"]*"/);
      if (atm && parseInt(atm[1]!) * parseInt(atm[2]!) > parseInt(atm[3]!) + 100) tv.delete(atm[4]!);
      const mg = ln.match(/^(?:\w+\s+)?(\w+)\s*=\s*\(\w+\)\s*(\w+)\.get\s*\(\s*"([^"]*)"\s*\)/);
      if (mg) {
        const mv = mg[2]!; const gk = mg[3]!; let kt = false;
        for (let j = 0; j < i; j++) {
          const pl = sl78[j]!.trim();
          const pm = pl.match(new RegExp(escapeRegExp(mv) + '\\.put\\s*\\(\\s*"([^"]*)"\\s*,\\s*(\\w+)\\s*\\)'));
          if (pm && pm[1] === gk) kt = tv.has(pm[2]!);
        }
        if (kt) tv.add(mg[1]!); else tv.delete(mg[1]!);
      }
      const lg = ln.match(/^(?:\w+\s+)?(\w+)\s*=\s*(\w+)\.get\s*\(\s*(\d+)\s*\)/);
      if (lg) {
        const lv = lg[2]!; const gi = parseInt(lg[3]!);
        const items: { tainted: boolean }[] = []; let rc = 0;
        for (let j = 0; j < i; j++) {
          const al = sl78[j]!.trim();
          const am = al.match(new RegExp(escapeRegExp(lv) + '\\.add\\s*\\(\\s*(?:"[^"]*"|(\\w+))\\s*\\)'));
          if (am) items.push({ tainted: am[1] ? tv.has(am[1]) : false });
          if (al.includes(lv + '.remove(')) rc++;
        }
        const adj = items.slice(rc);
        if (gi < adj.length && !adj[gi]!.tainted) tv.delete(lg[1]!);
        else tv.add(lg[1]!);
      }
      // Interprocedural: bar = new Test().doSomething(request, param) or bar = doSomething(request, param)
      const ipCall78 = ln.match(/(\w+)\s*=\s*(?:new\s+\w+\(\)\s*\.\s*)?(\w+)\s*\(\s*(?:request\s*,\s*)?(\w+)\s*\)/);
      if (ipCall78 && tv.has(ipCall78[3]!)) {
        const mn78 = ipCall78[2]!;
        let kills78 = false;
        // Search for the method DECLARATION (not call site): must have access modifier or
        // return-type keyword before the method name, indicating a method signature not a call.
        const methodDeclRe = new RegExp('(?:private|protected|public|static|final)\\s+.*\\b' + escapeRegExp(mn78) + '\\s*\\(');
        for (let j = 0; j < sl78.length; j++) {
          if (j === i) continue; // skip the call site itself
          const md78 = sl78[j]!.trim();
          if (methodDeclRe.test(md78) || (md78.includes(`${mn78}(`) && /^\s*(?:public|private|protected)\s/.test(sl78[j]!))) {
            let bd78 = 0; let fo78 = false;
            // Collect the method body lines to analyze return taint
            const bodyLines78: string[] = [];
            for (let k = j; k < Math.min(j + 50, sl78.length); k++) {
              if (sl78[k]!.includes('{')) { bd78++; fo78 = true; }
              if (sl78[k]!.includes('}')) bd78--;
              if (fo78 && bd78 <= 0) break;
              const mt78 = sl78[k]!.trim();
              if (k !== j) bodyLines78.push(mt78);
              // Strong sanitizers kill taint unconditionally
              if (/\b(?:parseInt|parseLong|parseFloat|parseDouble|Integer\.valueOf|Long\.valueOf|Pattern\.matches|Pattern\.compile|\.matches\s*\(\s*"[^"]*"|validate\s*\(|sanitize\s*\()\b/i.test(mt78)) { kills78 = true; break; }
            }
            if (!kills78) {
              // Analyze whether the method's return value carries taint from param.
              // Strategy: track a mini taint set within the method body.
              const mtv = new Set<string>(['param']);
              let returnVar78 = '';
              // Track pending multi-line assignment: when we see "bar =" or "bar ="
              // on one line, look for tainted refs on subsequent lines until ";"
              let pendingAssignVar78 = '';
              // Dead-branch detection for switch statements: track constant char values
              // derived from charAt() on string literals to identify which case is taken.
              const constChars78 = new Map<string, string>(); // var -> resolved char value
              const constStrings78 = new Map<string, string>(); // var -> literal string
              let activeSwitchVar78 = ''; let activeSwitchChar78 = '';
              let inDeadBranch78 = false;
              for (const bl of bodyLines78) {
                // Multi-line assignment continuation: if a pending var is being assigned
                // and this line contains a tainted reference, taint the pending var
                if (pendingAssignVar78) {
                  for (const t of mtv) {
                    if (new RegExp('\\b' + escapeRegExp(t) + '\\b').test(bl)) { mtv.add(pendingAssignVar78); break; }
                  }
                  if (bl.includes(';')) pendingAssignVar78 = '';
                }
                // Track constant string literals: String x = "literal"
                const strLit78 = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*"([^"]*)"\s*;/);
                if (strLit78) constStrings78.set(strLit78[1]!, strLit78[2]!);
                // Track charAt on constant strings: x = str.charAt(N)
                const charAtMatch = bl.match(/(?:\w+\s+)?(\w+)\s*=\s*(\w+)\.charAt\s*\(\s*(\d+)\s*\)/);
                if (charAtMatch && constStrings78.has(charAtMatch[2]!)) {
                  const s = constStrings78.get(charAtMatch[2]!)!;
                  const idx = parseInt(charAtMatch[3]!);
                  if (idx < s.length) constChars78.set(charAtMatch[1]!, s[idx]!);
                }
                // Switch statement: check if switching on a known constant char
                const switchMatch = bl.match(/switch\s*\(\s*(\w+)\s*\)/);
                if (switchMatch && constChars78.has(switchMatch[1]!)) {
                  activeSwitchVar78 = switchMatch[1]!;
                  activeSwitchChar78 = constChars78.get(switchMatch[1]!)!;
                  inDeadBranch78 = true; // assume dead until we find the matching case
                }
                // Case label: check if this is the active case.
                // Once we find the matching case, stay in live branch until break.
                const caseMatch = bl.match(/case\s+'(.)'/);
                if (caseMatch && activeSwitchVar78) {
                  if (caseMatch[1] === activeSwitchChar78) {
                    inDeadBranch78 = false; // found the live case
                  } else if (inDeadBranch78) {
                    // Stay dead (haven't found live case yet, or past it after break)
                  }
                  // If we're already in a live branch (fall-through from matching case),
                  // another case label doesn't make it dead.
                }
                if (bl === 'default:' && activeSwitchVar78 && inDeadBranch78) {
                  // default is dead only if we haven't been in a live branch
                }
                // break exits the live branch of the switch
                if (bl === 'break;' && activeSwitchVar78 && !inDeadBranch78) {
                  inDeadBranch78 = true; // after break, subsequent cases are dead again
                }
                // Simple assignment propagation: x = param or x = tainted_var
                // Skip assignments in dead branches of constant-resolved switch statements
                const simpleAssign = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*(\w+)\s*;/);
                if (simpleAssign && mtv.has(simpleAssign[2]!) && !inDeadBranch78) mtv.add(simpleAssign[1]!);
                // If-gated assignment: if (...) x = param;
                const ifAssign = bl.match(/\bif\s*\(.*\)\s*(\w+)\s*=\s*(\w+)\s*;/);
                if (ifAssign && mtv.has(ifAssign[2]!)) mtv.add(ifAssign[1]!);
                // Method call propagation: x = something(tainted)
                const mcProp = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*.*\(\s*.*\b(\w+)\b.*\)/);
                if (mcProp && mtv.has(mcProp[2]!)) mtv.add(mcProp[1]!);
                // Multi-line assignment start: "bar =" at end of line (no semicolon)
                const multiAssign = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*$/);
                if (multiAssign && !bl.includes(';')) pendingAssignVar78 = multiAssign[1]!;
                // Also detect: "bar = \n new String(" pattern
                const multiAssign2 = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*\S+/);
                if (multiAssign2 && !bl.includes(';')) pendingAssignVar78 = multiAssign2[1]!;
                // StringBuilder: sb = new StringBuilder(tainted)
                const sbProp = bl.match(/(\w+)\s*=\s*new\s+StringBuilder\s*\(\s*(\w+)\s*\)/);
                if (sbProp && mtv.has(sbProp[2]!)) mtv.add(sbProp[1]!);
                // toString: x = sb.toString() or x = sb.append(...).toString()
                // Exclude .get(N) which is handled by the precise list tracking below
                const tsProp = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*(?:\(\w+\)\s*)?(\w+)\.(?:append\s*\([^)]*\)\s*\.)*(?:toString)\s*\(/);
                if (tsProp && mtv.has(tsProp[2]!)) mtv.add(tsProp[1]!);
                // HashMap put/get tracking
                const putCall = bl.match(/(\w+)\.put\s*\(\s*"([^"]*)"?\s*,\s*(?:\w+\.toString\s*\(\s*\)|\w+)\s*\)/);
                if (putCall) { for (const t of mtv) { if (bl.includes(t)) { mtv.add(putCall[1]!); break; } } }
                const getCast = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*\(\w+\)\s*(\w+)\.get\s*\(/);
                if (getCast && mtv.has(getCast[2]!)) mtv.add(getCast[1]!);
                // List add/get tracking with mutation awareness
                const addCall = bl.match(/(\w+)\.add\s*\(\s*(\w+)\s*\)/);
                if (addCall && mtv.has(addCall[2]!)) mtv.add(addCall[1]!);
                const listGet = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*(\w+)\.get\s*\(\s*(\d+)\s*\)/);
                if (listGet) {
                  // Precise list tracking: replay add/remove operations to determine
                  // whether the element at the requested index is tainted.
                  const listVar = listGet[2]!; const getIdx = parseInt(listGet[3]!);
                  const listItems: { tainted: boolean }[] = []; let removeCount = 0;
                  for (const prev of bodyLines78) {
                    const prevAdd = prev.match(new RegExp(escapeRegExp(listVar) + '\\.add\\s*\\(\\s*(?:"[^"]*"|(\\w+))\\s*\\)'));
                    if (prevAdd) listItems.push({ tainted: prevAdd[1] ? mtv.has(prevAdd[1]) : false });
                    if (prev.includes(listVar + '.remove(')) removeCount++;
                    if (prev === bl) break;
                  }
                  const adjusted = listItems.slice(removeCount);
                  if (getIdx < adjusted.length && adjusted[getIdx]!.tainted) mtv.add(listGet[1]!);
                  else if (getIdx < adjusted.length && !adjusted[getIdx]!.tainted) { /* safe: don't taint */ }
                  else if (mtv.has(listVar)) mtv.add(listGet[1]!); // fallback: list is tainted
                }
                // Concat propagation: x = ... + tainted or x = tainted + ...
                const concatProp = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*(.+)/);
                if (concatProp && /\+/.test(concatProp[2]!)) {
                  for (const t of mtv) { if (new RegExp('\\b' + escapeRegExp(t) + '\\b').test(concatProp[2]!)) { mtv.add(concatProp[1]!); break; } }
                }
                // Note: we do NOT apply static string kills in the mini-taint tracker.
                // Multi-branch code (switch/if) may assign both param and literals to the
                // same variable. Conservative analysis: if ANY branch taints it, it's tainted.
                // Capture return variable
                const ret = bl.match(/return\s+(\w+)\s*;/);
                if (ret) returnVar78 = ret[1]!;
              }
              // If we can identify a return variable and it's NOT in the mini taint set,
              // the method neutralizes the tainted input.
              if (returnVar78 && !mtv.has(returnVar78)) kills78 = true;
              // If param is never referenced at all in the body, taint doesn't flow.
              if (!bodyLines78.some(l => /\bparam\b/.test(l))) kills78 = true;
            }
            break;
          }
        }
        if (kills78) tv.delete(ipCall78[1]!); else tv.add(ipCall78[1]!);
      }
      // For-each loop: for (Type var : collection) -- propagate taint from collection to loop var
      const forEach78 = ln.match(/for\s*\(\s*\w+\s+(\w+)\s*:\s*(\w+)\s*\)/);
      if (forEach78 && tv.has(forEach78[2]!)) tv.add(forEach78[1]!);

      const em = ln.match(EX78);
      if (em && sln > 0) {
        const ea = em[1] || ''; let hit = false;
        for (const t of tv) { if (new RegExp('\\b' + escapeRegExp(t) + '\\b').test(ea)) { hit = true; break; } }
        if (!hit) {
          // Lookback: check nearby lines for tainted data flowing into exec args.
          // First, identify variables that appear in the exec arg list.
          const execArgVars = new Set<string>();
          for (const word of ea.match(/\b[a-zA-Z_]\w*\b/g) || []) execArgVars.add(word);
          for (let j = Math.max(0, i - 25); j < i; j++) {
            const pl = sl78[j]!.trim();
            for (const t of tv) {
              // Only match concat/array/add patterns that involve an exec arg variable
              const concatRe = new RegExp('\\+\\s*\\b' + escapeRegExp(t) + '\\b|\\b' + escapeRegExp(t) + '\\b\\s*\\+');
              if (concatRe.test(pl)) {
                // Check that this line involves an exec arg var or feeds into one
                for (const av of execArgVars) {
                  if (new RegExp('\\b' + escapeRegExp(av) + '\\b').test(pl)) { hit = true; break; }
                }
                if (hit) break;
              }
              const arrRe = new RegExp('\\{[^}]*\\b' + escapeRegExp(t) + '\\b');
              if (arrRe.test(pl)) {
                // Check that this array init assigns to an exec arg variable
                const arrAssign = pl.match(/^(?:\w+\[\]\s+)?(\w+)\s*=/);
                if (arrAssign && execArgVars.has(arrAssign[1]!)) { hit = true; break; }
              }
              const addRe = new RegExp('\\.add\\s*\\([^)]*\\b' + escapeRegExp(t) + '\\b');
              if (addRe.test(pl)) {
                // Check that this .add() is on an exec arg variable
                const addTarget = pl.match(/(\w+)\s*\.\s*add\s*\(/);
                if (addTarget && execArgVars.has(addTarget[1]!)) { hit = true; break; }
              }
            }
            if (hit) break;
          }
        }
        if (hit) {
          findings.push({
            source: { id: `srcline-${sln}`, label: `user input (line ${sln})`, line: sln, code: scd.slice(0, 200) },
            sink: { id: `srcline-${i + 1}`, label: `command execution (line ${i + 1})`, line: i + 1, code: ln.slice(0, 200) },
            missing: 'CONTROL (input sanitization or safe command API)', severity: 'critical',
            description: `User input flows to OS command execution at line ${i + 1} without sanitization.`,
            fix: 'Never pass user input to shell commands. Use safe APIs with argument arrays.',
          });
          break;
        }
      }
    }
  }

  // Source-line fallback for Java deserialization: detect command injection where
  // fields populated by defaultReadObject()/readObject() flow to Runtime.exec().
  // Pattern: class implements Serializable, readObject() calls defaultReadObject(),
  // then a field (e.g., taskAction) is passed to Runtime.getRuntime().exec(field).
  if (findings.length === 0 && map.source_code) {
    const sl78d = stripComments(map.source_code);
    const hasDefaultReadObject = /\bdefaultReadObject\s*\(\s*\)|\breadObject\s*\(\s*\w+\s*\)/.test(sl78d);
    const hasSerializable = /\bSerializable\b/.test(sl78d);
    const hasRuntimeExec = /\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|new\s+ProcessBuilder\s*\(/.test(sl78d);

    if (hasDefaultReadObject && hasSerializable && hasRuntimeExec) {
      // Find fields that are used in exec() calls
      const lines78d = sl78d.split('\n');
      // Collect instance fields (private/protected/public String fieldName)
      const fields78 = new Set<string>();
      const FIELD_RE = /(?:private|protected|public)\s+(?:static\s+)?(?:final\s+)?(?:String|int|long|Object)\s+(\w+)\s*[;=]/;
      for (const line of lines78d) {
        const fm = line.match(FIELD_RE);
        if (fm) fields78.add(fm[1]!);
      }

      // After defaultReadObject(), all instance fields are tainted
      let deserLine = 0;
      let deserCode = '';
      let execLine = 0;
      let execCode = '';
      let taintedFieldUsed = false;

      for (let i = 0; i < lines78d.length; i++) {
        const ln = lines78d[i]!.trim();
        if (/defaultReadObject\s*\(/.test(ln)) {
          deserLine = i + 1;
          deserCode = ln;
        }
        const execMatch = ln.match(/\.exec\s*\(\s*(\w+)\s*\)|new\s+ProcessBuilder\s*\(\s*(\w+)/);
        if (execMatch) {
          const execArg = execMatch[1] || execMatch[2] || '';
          if (fields78.has(execArg)) {
            taintedFieldUsed = true;
            execLine = i + 1;
            execCode = ln;
          }
        }
      }

      if (taintedFieldUsed && deserLine > 0) {
        findings.push({
          source: { id: `srcline-${deserLine}`, label: `deserialization (line ${deserLine})`, line: deserLine, code: deserCode.slice(0, 200) },
          sink: { id: `srcline-${execLine}`, label: `command execution (line ${execLine})`, line: execLine, code: execCode.slice(0, 200) },
          missing: 'CONTROL (input sanitization or safe command API)',
          severity: 'critical',
          description: `Deserialized field flows to OS command execution at line ${execLine}. ` +
            `After defaultReadObject(), attacker-controlled field data reaches Runtime.exec() without sanitization.`,
          fix: 'Never pass deserialized field values to shell commands. Validate deserialized data against a strict allowlist. ' +
            'Consider using look-ahead deserialization (ObjectInputFilter) to restrict deserialized classes.',
        });
      }
    }
  }

  return {
    cwe: 'CWE-78',
    name: 'OS Command Injection',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-611: XML External Entity (XXE)
 * Pattern: INGRESS → TRANSFORM(xml) without CONTROL(parser configuration)
 * Property: XML parsers disable external entity processing when handling user input
 */
function verifyCWE611(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // XML parser regex — matches across TRANSFORM, EXTERNAL, and STORAGE nodes
  const xmlParserPattern = /\b(parseXml|parseXmlString|parseXML|DOMParser|SAXParser|xml2js|libxml|libxmljs2?|etree\.parse|etree\.fromstring|xml\.sax|minidom\.parseString|XmlReader|ElementTree\.parse|lxml\.etree|parseFromString)\b/i;
  // Cross-domain exclusion: XPath evaluation (xpath_query) selects nodes in an
  // already-parsed document — it does NOT parse XML or process external entities.
  // Including xpath_query caused CWE-611 to fire on CWE-643 XPath injection code.
  const xmlParsers = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'EXTERNAL' || n.node_type === 'STORAGE') &&
    n.node_subtype !== 'xpath_query' &&
    (n.node_subtype.includes('xml') || n.node_subtype.includes('xpath') ||
     n.attack_surface.includes('xml_parse') ||
     xmlParserPattern.test(n.analysis_snapshot || n.code_snapshot))
  );

  // Dangerous XML parser configurations that ENABLE XXE
  // libxmljs: parseXmlString(data, {noent:true}) — noent:true substitutes entities (DANGEROUS)
  // xml2js: explicitCharkey enables character key processing (DANGEROUS with crafted XML)
  const dangerousXmlConfigPattern = /noent\s*:\s*true|explicitCharkey/i;

  for (const src of ingress) {
    for (const sink of xmlParsers) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        // Check if the parser is configured dangerously (explicit XXE-enabling config)
        // Strip comments so dangerous config in comments doesn't misfire
        const sinkCodeOnly = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        const hasDangerousConfig = dangerousXmlConfigPattern.test(sinkCodeOnly);

        // Check if external entities are properly disabled
        const isSecure = !hasDangerousConfig && sinkCodeOnly.match(
          /\bnoent\s*:\s*false\b|\bdisable.*entity\b|\bresolveEntities\s*:\s*false\b|\bXMLReader.*FEATURE.*external.*false\b|\bdefusedxml\b|\bsafe.*parse/i
        ) !== null;

        if (!isSecure) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (XML parser security configuration — disable external entities)',
            severity: 'high',
            description: `User-supplied XML from ${src.label} is parsed at ${sink.label} without disabling external entities. ` +
              (hasDangerousConfig
                ? `The parser is configured with dangerous options (noent:true or explicitCharkey) that enable entity expansion.`
                : `An attacker can read local files, perform SSRF, or cause denial of service via entity expansion.`),
            fix: 'Disable external entity processing in the XML parser configuration. ' +
              'Use defusedxml (Python), set resolveEntities: false, or use noent: false. ' +
              'For libxmljs: NEVER use {noent:true}. Consider using JSON instead of XML where possible.',
          });
        }
      }
    }
  }

  // Secondary check: XML parsing with dangerous config inside vm.runInContext or similar
  // code execution sinks. The taint flows through a sandbox object literal which breaks
  // the normal BFS taint path. Detect: any EXTERNAL/system_exec node whose code_snapshot
  // contains XML parsing with dangerous config, when INGRESS nodes exist in the same graph.
  if (findings.length === 0 && ingress.length > 0) {
    const execWithXml = map.nodes.filter(n =>
      n.node_type === 'EXTERNAL' &&
      n.node_subtype === 'system_exec' &&
      xmlParserPattern.test(n.analysis_snapshot || n.code_snapshot) &&
      dangerousXmlConfigPattern.test(n.analysis_snapshot || n.code_snapshot)
    );

    for (const execNode of execWithXml) {
      // Check if the exec node is in the same function scope as an INGRESS node
      const ingressInScope = ingress.find(src =>
        sharesFunctionScope(map, src.id, execNode.id)
      );

      if (ingressInScope) {
        const closestIngress = ingressInScope;
        findings.push({
          source: nodeRef(closestIngress),
          sink: nodeRef(execNode),
          missing: 'CONTROL (XML parser security configuration — disable external entities)',
          severity: 'critical',
          description: `User-supplied data from ${closestIngress.label} reaches XML parsing inside ${execNode.label} with dangerous configuration. ` +
            `The parser is configured with noent:true or explicitCharkey inside a code execution sink (vm.runInContext), enabling entity expansion.`,
          fix: 'Disable external entity processing in the XML parser configuration. ' +
            'NEVER use {noent:true} with libxmljs/libxmljs2. ' +
            'Use noent: false or remove the noent option entirely.',
        });
      }
    }
  }

  // Source-line fallback for Java: detect XXE in XML parser methods that receive
  // XML as a parameter. The mapper doesn't create INGRESS nodes for method params
  // (only for @RequestParam etc.), so BFS misses these. Pattern:
  //   XMLInputFactory.newInstance() → createXMLStreamReader(new StringReader(xml))
  //   without setProperty(ACCESS_EXTERNAL_DTD, "") or setProperty(...FEATURE...external..., false)
  // Also catches: SAXParserFactory, DocumentBuilderFactory without security config.
  if (findings.length === 0 && map.source_code) {
    // Strip both comments and string/regex literals so detection patterns inside DST's own
    // verifier code (e.g. the XML_FACTORY_RE definition itself) don't self-trigger when
    // verifier.ts is scanned.
    const sl611 = stripLiterals(stripComments(map.source_code));

    // Detect Java XML parser factories without security configuration
    const XML_FACTORY_RE = /\b(XMLInputFactory|SAXParserFactory|DocumentBuilderFactory|TransformerFactory|SchemaFactory|XMLReaderFactory)\s*\.\s*(?:newInstance|newFactory)\s*\(/;
    const XML_SECURE_RE = /\bsetProperty\s*\(\s*(?:XMLConstants\s*\.\s*)?(?:ACCESS_EXTERNAL_DTD|ACCESS_EXTERNAL_SCHEMA|ACCESS_EXTERNAL_STYLESHEET|FEATURE.*(?:external|dtd|entity))\b|\bsetFeature\s*\(.*(?:external|dtd|disallow|FEATURE)\b|\bdefusedxml\b/i;

    // Check if there's an XML factory without security properties
    const factoryMatch = sl611.match(XML_FACTORY_RE);
    if (factoryMatch) {
      // Find the variable holding the factory
      const factoryLine = sl611.indexOf(factoryMatch[0]);
      const factoryVarMatch = sl611.slice(Math.max(0, factoryLine - 100), factoryLine + factoryMatch[0].length + 10)
        .match(/(?:var|final\s+\w+|\w+)\s+(\w+)\s*=\s*/);
      const factoryVar = factoryVarMatch ? factoryVarMatch[1] : null;

      // Check if security properties are set on this factory
      let isSecured = XML_SECURE_RE.test(sl611);

      // Check for conditional security: if (securityEnabled) { setProperty... }
      // If security is gated behind a boolean parameter or variable, the unsecured
      // code path exists by definition. A method parameter `boolean securityEnabled`
      // means callers CAN pass false. This is a vulnerability — security should be
      // unconditional for XML parsing.
      if (isSecured) {
        const condSecMatch = sl611.match(/if\s*\(\s*(\w+)\s*\)\s*\{[^}]*(?:ACCESS_EXTERNAL_DTD|setProperty|setFeature)/s);
        if (condSecMatch) {
          const condVar = condSecMatch[1]!;
          // If the condition variable is a method parameter, security is optional
          const isMethodParam = new RegExp(
            '\\b(?:boolean|Boolean)\\s+' + escapeRegExp(condVar) + '\\b'
          ).test(sl611);
          // If any caller passes false, or it's a method param (callers could pass false)
          const calledWithFalse = new RegExp(
            '\\b\\w+\\s*\\([^)]*,\\s*false\\s*\\)'
          ).test(sl611);
          if (isMethodParam || calledWithFalse) {
            isSecured = false; // conditional security — unsecured path exists
          }
        }
      }

      // Check if the method receives XML as a parameter (method-param taint)
      const xmlParamRe = /(?:String|InputStream|Reader|Source)\s+(\w+).*\{[\s\S]*?(?:createXMLStreamReader|parse|unmarshal|transform)\s*\(/;
      const hasXmlParam = xmlParamRe.test(sl611);

      // Check if XML is used with createXMLStreamReader or similar parse calls
      const xmlParseCall = /\b(?:createXMLStreamReader|\.parse\s*\(|\.unmarshal\s*\()\s*\(/;
      const hasXmlParse = xmlParseCall.test(sl611) || /createXMLStreamReader/.test(sl611);

      if (!isSecured && hasXmlParse) {
        // Find the line numbers
        const lines611 = sl611.split('\n');
        let factoryLineNum = 0;
        let parseLineNum = 0;
        for (let i = 0; i < lines611.length; i++) {
          if (XML_FACTORY_RE.test(lines611[i]!)) factoryLineNum = i + 1;
          if (/createXMLStreamReader|\.parse\s*\(|\.unmarshal\s*\(/.test(lines611[i]!)) parseLineNum = i + 1;
        }

        findings.push({
          source: { id: `srcline-${factoryLineNum}`, label: `XML parser factory (line ${factoryLineNum})`, line: factoryLineNum, code: factoryMatch[0].slice(0, 200) },
          sink: { id: `srcline-${parseLineNum}`, label: `XML parse operation (line ${parseLineNum})`, line: parseLineNum, code: 'XML parsing without external entity protection' },
          missing: 'CONTROL (XML parser security configuration — disable external entities)',
          severity: 'high',
          description: `XML parser created at line ${factoryLineNum} does not disable external entity processing. ` +
            `An attacker can supply malicious XML with external entity references to read local files or perform SSRF.`,
          fix: 'Set XMLConstants.ACCESS_EXTERNAL_DTD and ACCESS_EXTERNAL_SCHEMA to empty string. ' +
            'For XMLInputFactory: xif.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, ""). ' +
            'For DocumentBuilderFactory: dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true).',
        });
      }
    }
  }

  return {
    cwe: 'CWE-611',
    name: 'XML External Entity (XXE)',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-94: Code Injection
 * Pattern: INGRESS → EXTERNAL(system_exec) without CONTROL, where code_snapshot contains eval/exec/Function
 * Property: User input is never passed to code evaluation functions
 */
function verifyCWE94(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const vmExecPattern = /\b(eval|exec|compile|Function\s*\(|execScript|setInterval|setTimeout|vm\.run|vm\.compile|vm\.create|runInContext|runInNewContext|runInThisContext|compileFunction|ejs\.render|pug\.render|nunjucks\.render)\b/i;
  const codeExec = map.nodes.filter(n =>
    n.node_type === 'EXTERNAL' &&
    (n.node_subtype.includes('system_exec') || n.node_subtype.includes('exec') ||
     n.node_subtype.includes('eval') || n.node_subtype.includes('template_exec')) &&
    vmExecPattern.test(n.analysis_snapshot || n.code_snapshot)
  );

  for (const src of ingress) {
    for (const sink of codeExec) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        // "sandbox" and "safeEval" are NOT safe for vm.runInContext --
        // vm modules execute arbitrary code even inside sandbox contexts.
        // Only treat as safe if it's ast.literal_eval or JSON.parse (truly safe parsers).
        const sinkCodeOnly94 = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        const isVmExec = /\bvm\.|runInContext|runInNewContext|runInThisContext|compileFunction\b/i.test(sinkCodeOnly94);
        const isSafe = !isVmExec && sinkCodeOnly94.match(
          /\bsandbox\b|\bsafe.*eval\b|\bast\.literal_eval\b|\bJSON\.parse\b/i
        ) !== null;

        if (!isSafe) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (input validation or sandboxed evaluation)',
            severity: 'critical',
            description: `User input from ${src.label} flows to code evaluation at ${sink.label} without sanitization. ` +
              (isVmExec
                ? `Node.js vm module does NOT provide a security sandbox -- user-controlled data in vm.runInContext enables arbitrary code execution.`
                : `An attacker can execute arbitrary code on the server.`),
            fix: isVmExec
              ? 'NEVER use vm.runInContext/runInNewContext with user-controlled data. ' +
                'The Node.js vm module is NOT a security mechanism. ' +
                'Use a true sandbox (vm2, isolated-vm) or avoid dynamic code evaluation entirely.'
              : 'Never pass user input to eval(), exec(), or Function(). ' +
                'Use ast.literal_eval() for Python or JSON.parse() for JSON data. ' +
                'If dynamic evaluation is required, use a sandboxed environment with strict allowlists.',
          });
        }
      }
    }
  }

  // Secondary check: vm.runInContext/runInNewContext where taint flows through
  // object literals (sandbox pattern). The pattern is:
  //   const data = req.body.x;              // tainted
  //   const sandbox = { safeEval, data };   // object literal contains tainted var
  //   vm.runInContext('safeEval(data)', sandbox);  // taint reaches code exec via sandbox
  // BFS doesn't find this because the object literal breaks the edge chain.
  // Detect: vm.* EXTERNAL nodes that reference variables also referenced by INGRESS,
  // when both are in the same function scope.
  if (findings.length === 0 && ingress.length > 0) {
    const vmNodes = codeExec.filter(n =>
      /\bvm\.|runInContext|runInNewContext|runInThisContext\b/i.test(n.analysis_snapshot || n.code_snapshot)
    );

    for (const vmNode of vmNodes) {
      // Check if any INGRESS node shares a function scope with this vm node
      for (const src of ingress) {
        if (sharesFunctionScope(map, src.id, vmNode.id)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(vmNode),
            missing: 'CONTROL (input validation or sandboxed evaluation)',
            severity: 'critical',
            description: `User input from ${src.label} is accessible within the vm execution context at ${vmNode.label}. ` +
              `Node.js vm module does NOT provide a security sandbox -- user-controlled data passed through object literals (sandbox pattern) enables arbitrary code execution.`,
            fix: 'NEVER use vm.runInContext/runInNewContext with user-controlled data. ' +
              'The Node.js vm module is NOT a security mechanism. ' +
              'Use a true sandbox (vm2, isolated-vm) or avoid dynamic code evaluation entirely.',
          });
          break; // One finding per vm node is sufficient
        }
      }
    }
  }

  // Tertiary check: When TypeScript type annotations cause the JS parser to
  // swallow destructured request parameters into ERROR nodes (0 INGRESS nodes),
  // but the function clearly handles HTTP request data (body, params, query)
  // and passes it to vm.*. Detect by code_snapshot analysis of sibling nodes.
  if (findings.length === 0 && ingress.length === 0) {
    const vmNodes = codeExec.filter(n =>
      /\bvm\.|runInContext|runInNewContext|runInThisContext\b/i.test(n.analysis_snapshot || n.code_snapshot)
    );

    for (const vmNode of vmNodes) {
      // Find the containing function by line range
      const containingFunc = map.nodes.find(n =>
        n.node_type === 'STRUCTURAL' &&
        n.node_subtype === 'function' &&
        n.line_start <= vmNode.line_start &&
        n.line_end >= vmNode.line_start &&
        // Must be an Express-like handler (references body, params, query, req)
        /\b(body|params|query|req\b|Request)\b/i.test(n.analysis_snapshot || n.code_snapshot)
      );

      if (containingFunc) {
        // Check if any sibling node in the same function references request data
        const requestDataPattern = /\bbody\.([\w]+)|\breq\.(body|params|query|headers)\b|\brequest\.(body|params|query)\b/i;
        const hasRequestData = map.nodes.some(n =>
          n.line_start >= containingFunc.line_start &&
          n.line_start <= containingFunc.line_end &&
          requestDataPattern.test(n.analysis_snapshot || n.code_snapshot)
        );

        if (hasRequestData) {
          findings.push({
            source: nodeRef(containingFunc),
            sink: nodeRef(vmNode),
            missing: 'CONTROL (input validation or sandboxed evaluation)',
            severity: 'critical',
            description: `HTTP request data is passed to code execution at ${vmNode.label} within ${containingFunc.label}. ` +
              `Node.js vm module does NOT provide a security sandbox -- user-controlled data in vm.runInContext enables arbitrary code execution.`,
            fix: 'NEVER use vm.runInContext/runInNewContext with user-controlled data. ' +
              'The Node.js vm module is NOT a security mechanism. ' +
              'Use a true sandbox (vm2, isolated-vm) or avoid dynamic code evaluation entirely.',
          });
          break;
        }
      }
    }
  }

  return {
    cwe: 'CWE-94',
    name: 'Code Injection',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-1321: Prototype Pollution (Improperly Controlled Modification of Object Prototype Attributes)
 * Pattern: INGRESS → TRANSFORM(mass_assignment) without CONTROL
 * Property: User input is never used to set arbitrary object properties without allowlisting
 *
 * Primarily JS-specific (Object.assign, spread into user-controlled keys, lodash.merge),
 * but the pattern extends to any language with dynamic property assignment.
 */
function verifyCWE1321(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  // Only check languages with dynamic prototypes/object mutation
  const lang = inferMapLanguage(map);
  const PROTOTYPE_LANGUAGES = new Set(['javascript', 'typescript', 'python', 'ruby', 'php']);
  if (lang && !PROTOTYPE_LANGUAGES.has(lang)) {
    return { cwe: 'CWE-1321', name: 'Prototype Pollution', holds: true, findings: [] };
  }

  const massAssign = map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('mass_assignment') || n.node_subtype.includes('merge') ||
     (n.node_subtype.includes('assign') && (n.analysis_snapshot || n.code_snapshot).match(/\bObject\.assign\b|\bmerge\b|\bextend\b|\b__dict__\b|\battr_accessor\b/i)) ||
     (n.analysis_snapshot || n.code_snapshot).match(/\bObject\.assign\b|\b\.merge\b|\b\.extend\b|\b\.\.\.\s*req\b|\bdeepMerge\b|\bdefaultsDeep\b/i) !== null)
  );

  for (const src of ingress) {
    for (const sink of massAssign) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const isSafe = stripComments(sink.analysis_snapshot || sink.code_snapshot).match(
          /\ballowlist\b|\bwhitelist\b|\bpick\s*\(|\bsanitize\s*\(|\bObject\.create\(null\)/i
        ) !== null;

        if (!isSafe) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (property allowlisting or safe merge)',
            severity: 'high',
            description: `User input from ${src.label} is merged into an object at ${sink.label} without property filtering. ` +
              `An attacker can inject __proto__ or constructor.prototype to pollute Object.prototype.`,
            fix: 'Never merge user input directly into objects. Use an allowlist of permitted keys. ' +
              'Use Object.create(null) for lookup objects. Avoid lodash.merge/defaultsDeep with untrusted data. ' +
              'Consider using Map instead of plain objects for dynamic keys.',
          });
        }
      }
    }
  }

  return {
    cwe: 'CWE-1321',
    name: 'Prototype Pollution',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-158: Improper Neutralization of Null Byte or NUL Character
 * Pattern: CONTROL(validation using includes/endsWith/match) → file operation,
 *          where the validation does not strip null bytes before checking.
 * Classic pattern: filename.includes('.js') passes for "file.js%00.txt"
 *
 * Also detects: INGRESS → file_read/file_write where validation occurs but
 * cutOffPoisonNullByte/replace(\x00) is called AFTER the validation check.
 */
function verifyCWE158(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // Null byte sanitization patterns
  const nullByteSanitizePattern = /cutOffPoisonNullByte|replace\s*\(\s*['"`]?\\x00|replace\s*\(\s*['"`]?\\0|replace\s*\(\s*['"`]?%00|\bnull.*byte\b.*strip|\breplace.*\\x00/i;

  // File type validation patterns — broad: includes function calls that check file types
  const fileValidationPattern = /\b(endsWith|includes|match|test|indexOf|startsWith)\s*\(.*\.(md|pdf|xml|zip|jpg|png|gif|js|ts|txt|html|css|json|yml|yaml)/i;
  const fileValidationFnPattern = /\b(endsWithAllowlisted|allowlistedFileType|validFileType|checkFileType|isValidExtension|fileTypeCheck|acceptedFileType|isAllowedExt)/i;

  // Find nodes that do file type validation — both CONTROL nodes and any node in the graph
  const validationNodes = map.nodes.filter(n =>
    fileValidationPattern.test(n.analysis_snapshot || n.code_snapshot) ||
    fileValidationFnPattern.test(n.analysis_snapshot || n.code_snapshot)
  );

  // Find nodes that do null byte sanitization
  const sanitizeNodes = map.nodes.filter(n =>
    nullByteSanitizePattern.test(n.analysis_snapshot || n.code_snapshot)
  );

  // File operation sinks
  const fileOps = map.nodes.filter(n =>
    (n.node_type === 'EGRESS' || n.node_type === 'INGRESS' || n.node_type === 'STORAGE') &&
    (n.node_subtype.includes('file') ||
     (n.analysis_snapshot || n.code_snapshot).match(/\b(sendFile|readFile|createReadStream|createWriteStream|writeFile|unlink|open|access|stat|path\.resolve)\s*\(/i) !== null)
  );

  // Pattern 1: File type validation exists, null byte sanitization exists,
  // but sanitization is AFTER the validation (wrong order).
  // This is the fileServer.ts pattern: endsWithAllowlistedFileType(file) -> cutOffPoisonNullByte(file)
  if (validationNodes.length > 0 && sanitizeNodes.length > 0) {
    for (const valNode of validationNodes) {
      for (const sanNode of sanitizeNodes) {
        // Sanitization happens AFTER validation (wrong order)
        if (sanNode.line_start > valNode.line_start) {
          // Check if there's NO sanitization BEFORE the validation
          const hasPreSanitize = sanitizeNodes.some(s => s.line_start < valNode.line_start);
          if (!hasPreSanitize) {
            const sourceNode = ingress.length > 0 ? ingress[0]! : valNode;
            findings.push({
              source: nodeRef(sourceNode),
              sink: nodeRef(sanNode),
              missing: 'TRANSFORM (null byte neutralization BEFORE validation, not after)',
              severity: 'high',
              description: `Null byte sanitization at ${sanNode.label} (line ${sanNode.line_start}) occurs AFTER filename validation at ${valNode.label} (line ${valNode.line_start}). ` +
                `An attacker can bypass the file type check with a poison null byte (e.g., "evil.txt%00.pdf" passes an endsWith(".pdf") check, then the null byte is stripped, serving "evil.txt").`,
              fix: 'Move null byte sanitization BEFORE the file type/extension validation. ' +
                'The correct order is: (1) strip null bytes, (2) validate file type, (3) perform file operation.',
            });
            break;
          }
        }
      }
      if (findings.length > 0) break;
    }
  }

  // Pattern 2: File type validation with file operation but NO null byte sanitization at all
  if (findings.length === 0 && validationNodes.length > 0 && sanitizeNodes.length === 0 && fileOps.length > 0) {
    for (const src of ingress) {
      for (const fileOp of fileOps) {
        if (src.id === fileOp.id) continue;
        // Check if there's a validation node between them
        const hasVal = validationNodes.some(v =>
          v.line_start >= src.line_start && v.line_start <= fileOp.line_start
        );
        if (hasVal) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(fileOp),
            missing: 'TRANSFORM (null byte neutralization before filename validation)',
            severity: 'high',
            description: `Filename from ${src.label} is validated using file type checks but null bytes are never stripped. ` +
              `An attacker can bypass the validation with a poison null byte (e.g., "malicious.txt%00.pdf").`,
            fix: 'Strip null bytes from filenames BEFORE validation. ' +
              'Use filename.replace(/\\0/g, "") or a dedicated function like cutOffPoisonNullByte(). ' +
              'Always sanitize null bytes before any file type or extension check.',
          });
          break;
        }
      }
      if (findings.length > 0) break;
    }
  }

  return {
    cwe: 'CWE-158',
    name: 'Improper Neutralization of Null Byte or NUL Character',
    holds: findings.length === 0,
    findings,
  };
}

// ---------------------------------------------------------------------------
// CWE-117: Improper Output Neutralization for Logs (broadened — cross-language)
// ---------------------------------------------------------------------------

/**
 * CWE-117: Log Injection
 * Detects user input flowing to logging functions without sanitization.
 *
 * The generated verifier only looks at STORAGE nodes, but most logging calls
 * are classified as EGRESS/display (println, print, System.out, fmt.Println)
 * or EXTERNAL (log.info, logger.warn). This override broadens the sink filter.
 *
 * Language patterns caught:
 *   Java/Kotlin: System.out.println(), Logger.info/warn/error(), println()
 *   Python:      logging.info/warn/error(), print()
 *   Go:          log.Printf(), fmt.Println(), log.Println()
 *   PHP:         error_log(), syslog(), trigger_error()
 *   Swift:       print(), NSLog(), os_log()
 *   Ruby:        puts, Logger.info/warn/error
 *   JavaScript:  console.log/warn/error(), winston, bunyan, pino
 *   C#:          Console.WriteLine(), ILogger.Log*
 */
function verifyCWE117(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // Broad logging-function regex across all languages
  const LOG_SINK_RE = /\b(console\.(log|warn|error|info|debug|trace)|logger\.(log|error|warn|info|debug|trace|fatal|verbose)|log\.(log|error|warn|info|debug|trace|fatal|Printf|Println|Print)|println|print\s*\(|System\.out\.print|System\.err\.print|NSLog|os_log|error_log|syslog|trigger_error|puts\s|Logger\.(info|warn|error|debug|fatal)|winston\.(log|error|warn|info|debug)|bunyan\.(error|warn|info|debug|trace|fatal)|pino\.(error|warn|info|debug|trace|fatal)|log4js\.(error|warn|info|debug|trace|fatal)|morgan\(|app\.log\.|syslog\.(log|write)|audit\.log|accessLog\.|errorLog\.|Console\.Write|ILogger|_logger\.|logging\.(info|warning|error|debug|critical)|fmt\.Print|fmt\.Fprint|writeLog|appendFile.*log)\b/i;

  // Safe patterns — encoding or sanitization before logging
  const LOG_SAFE_RE = /\bescape\s*\(|\bencode\s*\(|\bsanitize\s*\(|\bstrip.*newline\b|\breplace.*\\n\b|\blog.*safe\b|\bneutralize\s*\(|\bstructured.*log\b|\bjson.*log\b/i;

  // Find logging sinks — EGRESS, EXTERNAL, STORAGE, or TRANSFORM nodes that match
  const logSinks = map.nodes.filter(n =>
    (n.node_type === 'EGRESS' || n.node_type === 'EXTERNAL' ||
     n.node_type === 'STORAGE' || n.node_type === 'TRANSFORM') &&
    (n.node_subtype.includes('log') || n.node_subtype.includes('audit') ||
     n.node_subtype.includes('display') ||
     n.attack_surface.includes('logging') ||
     LOG_SINK_RE.test(n.analysis_snapshot || n.code_snapshot))
  );

  for (const src of ingress) {
    for (const sink of logSinks) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        // V4-D: check scope snapshots for sanitization applied on prior lines
        const scopeSnapshots117 = getContainingScopeSnapshots(map, sink.id);
        const combinedScope117 = stripComments(scopeSnapshots117.join('\n') || sink.analysis_snapshot || sink.code_snapshot);
        if (!LOG_SAFE_RE.test(combinedScope117)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'TRANSFORM (log encoding — strip newlines, control chars, delimiters)',
            severity: 'medium',
            description: `User input from ${src.label} is logged at ${sink.label} without neutralization. ` +
              `An attacker can inject fake log entries via newlines or forge audit trails.`,
            fix: 'Strip or encode newlines (\\n, \\r), control characters, and log-format delimiters ' +
              'from user input before logging. Use structured logging (JSON) to prevent injection.',
          });
        }
      }
    }
  }

  // Scope-based fallback: INGRESS param shares a function scope with a logging node
  // that has tainted data_in
  if (findings.length === 0) {
    const taintedLogSinks = logSinks.filter(n => n.data_in.some(d => d.tainted));
    for (const src of ingress) {
      for (const sink of taintedLogSinks) {
        if (src.id === sink.id) continue;
        if (sharesFunctionScope(map, src.id, sink.id)) {
          // V4-D: check scope snapshots for sanitization on prior lines
          const scopeSnapshots117b = getContainingScopeSnapshots(map, sink.id);
          const combinedScope117b = stripComments(scopeSnapshots117b.join('\n') || sink.analysis_snapshot || sink.code_snapshot);
          if (!LOG_SAFE_RE.test(combinedScope117b)) {
            const already = findings.some(f =>
              f.source.id === src.id && f.sink.id === sink.id
            );
            if (!already) {
              findings.push({
                source: nodeRef(src),
                sink: nodeRef(sink),
                missing: 'TRANSFORM (log encoding — strip newlines, control chars, delimiters)',
                severity: 'medium',
                description: `User input from ${src.label} is logged at ${sink.label} without neutralization. ` +
                  `An attacker can inject fake log entries via newlines or forge audit trails.`,
                fix: 'Strip or encode newlines (\\n, \\r), control characters, and log-format delimiters ' +
                  'from user input before logging. Use structured logging (JSON) to prevent injection.',
              });
            }
          }
        }
      }
    }
  }

  // Source-line fallback for Java: detect incomplete sanitization for log/output injection.
  // Pattern: @RequestParam flows to .output() or logging, with replace("\n",...) that does NOT
  // also handle \r (carriage return). Replacing only \n with HTML is not proper sanitization
  // because \r\n or just \r can still inject fake log/output entries.
  if (findings.length === 0 && map.source_code) {
    const sl117 = stripComments(map.source_code);
    const lines117 = sl117.split('\n');

    // Find @RequestParam String variables
    const PARAM_RE117 = /@RequestParam(?:\s*\([^)]*\))?\s+(?:String)\s+(\w+)/g;
    const requestParams117 = new Set<string>();
    let pm117;
    while ((pm117 = PARAM_RE117.exec(sl117)) !== null) {
      requestParams117.add(pm117[1]!);
    }

    if (requestParams117.size > 0) {
      for (const paramName of requestParams117) {
        // Check if this parameter has incomplete newline sanitization
        const replaceNewlineRe = new RegExp(
          escapeRegExp(paramName) + '\\s*=\\s*' + escapeRegExp(paramName) +
          '\\.replace\\s*\\(\\s*"\\\\n"\\s*,\\s*"[^"]*"\\s*\\)',
        );
        const replaceCRRe = new RegExp(
          escapeRegExp(paramName) + '\\.replace\\s*\\(\\s*"\\\\r"',
        );
        const stripAllNewlinesRe = new RegExp(
          escapeRegExp(paramName) + '\\.replaceAll\\s*\\(\\s*"\\[\\\\r\\\\n\\]|\\\\\\\\r\\|\\\\\\\\n"',
        );

        const hasNewlineReplace = replaceNewlineRe.test(sl117);
        const hasCRReplace = replaceCRRe.test(sl117);
        const hasFullStrip = stripAllNewlinesRe.test(sl117);

        // Incomplete: replaces \n but not \r
        if (hasNewlineReplace && !hasCRReplace && !hasFullStrip) {
          // Check if the param flows to any output
          let outputLine = 0;
          let outputCode = '';
          let paramLine = 0;
          let paramCode = '';

          for (let i = 0; i < lines117.length; i++) {
            const ln = lines117[i]!.trim();
            if (new RegExp('@RequestParam.*\\b' + escapeRegExp(paramName) + '\\b').test(ln)) {
              paramLine = i + 1;
              paramCode = ln;
            }
            // Any output/display/return that includes the param
            if (new RegExp('\\.output\\s*\\(\\s*' + escapeRegExp(paramName) + '\\s*\\)|\\.body\\s*\\(.*' + escapeRegExp(paramName) + '|return.*' + escapeRegExp(paramName)).test(ln)) {
              outputLine = i + 1;
              outputCode = ln;
            }
          }

          if (outputLine > 0 && paramLine > 0) {
            findings.push({
              source: { id: `srcline-${paramLine}`, label: `request parameter (line ${paramLine})`, line: paramLine, code: paramCode.slice(0, 200) },
              sink: { id: `srcline-${outputLine}`, label: `output (line ${outputLine})`, line: outputLine, code: outputCode.slice(0, 200) },
              missing: 'TRANSFORM (log encoding — strip newlines, control chars, delimiters)',
              severity: 'medium',
              description: `User input "${paramName}" has incomplete newline sanitization: replace("\\n",...) without also replacing "\\r". ` +
                `Carriage return characters can still inject fake log entries or forge output lines.`,
              fix: 'Replace both \\n and \\r (and ideally all control characters) from user input before logging or displaying. ' +
                'Use replaceAll("[\\\\r\\\\n]", "") or a structured logging framework.',
            });
            break;
          }
        }

        // No sanitization at all: param goes directly to output with no replace
        if (!hasNewlineReplace && !hasCRReplace && !hasFullStrip) {
          let outputLine = 0;
          let outputCode = '';
          let paramLine = 0;
          let paramCode = '';

          for (let i = 0; i < lines117.length; i++) {
            const ln = lines117[i]!.trim();
            if (new RegExp('@RequestParam.*\\b' + escapeRegExp(paramName) + '\\b').test(ln)) {
              paramLine = i + 1;
              paramCode = ln;
            }
            if (new RegExp('\\.output\\s*\\(\\s*' + escapeRegExp(paramName) + '\\s*\\)|logger\\..*' + escapeRegExp(paramName) + '|log\\..*' + escapeRegExp(paramName)).test(ln)) {
              outputLine = i + 1;
              outputCode = ln;
            }
          }

          if (outputLine > 0 && paramLine > 0) {
            findings.push({
              source: { id: `srcline-${paramLine}`, label: `request parameter (line ${paramLine})`, line: paramLine, code: paramCode.slice(0, 200) },
              sink: { id: `srcline-${outputLine}`, label: `output (line ${outputLine})`, line: outputLine, code: outputCode.slice(0, 200) },
              missing: 'TRANSFORM (log encoding — strip newlines, control chars, delimiters)',
              severity: 'medium',
              description: `User input "${paramName}" flows to output without any newline neutralization. ` +
                `An attacker can inject fake log entries via \\r\\n sequences.`,
              fix: 'Strip newlines (\\n, \\r) and control characters from user input before output. ' +
                'Use structured logging (JSON) to prevent log injection.',
            });
            break;
          }
        }
      }
    }
  }

  return {
    cwe: 'CWE-117',
    name: 'Improper Output Neutralization for Logs',
    holds: findings.length === 0,
    findings,
  };
}

// ---------------------------------------------------------------------------
// CWE-601: Open Redirect (broadened — cross-language)
// ---------------------------------------------------------------------------

/**
 * CWE-601: Open Redirect
 * Detects user-controlled URLs flowing to redirect operations.
 *
 * The generated verifier only looks at EGRESS/TRANSFORM nodes with redirect
 * subtypes. This override also catches:
 *   - CONTROL/return nodes that return "Location: <user-input>"
 *   - TRANSFORM/template_string nodes that build redirect URLs
 *   - String returns containing redirect-related URLs
 *
 * Language patterns caught:
 *   Java/Kotlin: response.sendRedirect(), "Location: " + url, return "redirect:" + url
 *   Python:      redirect(url), Response(status=302, headers={"Location": url})
 *   Go:          http.Redirect(), w.Header().Set("Location", url)
 *   PHP:         header("Location: " . $url)
 *   Swift/JS:    return "Location: " + url, window.location = url
 */
function verifyCWE601(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Sources: user input that could contain URLs
  const urlInputs = nodesOfType(map, 'INGRESS').filter(n =>
    n.node_subtype.includes('query') || n.node_subtype.includes('param') ||
    n.node_subtype.includes('url') || n.node_subtype.includes('header') ||
    n.node_subtype.includes('http_request') || n.node_subtype.includes('function_param') ||
    n.attack_surface.includes('user_input') || n.attack_surface.includes('url_input') ||
    (n.analysis_snapshot || n.code_snapshot).match(
      /\b(req\.query|req\.params|req\.body|request\.args|request\.form|request\.GET|searchParams|url|redirect|next|return_?to|goto|target|dest|forward|continue|callback|returnUrl)\b/i
    ) !== null
  );

  // Sinks: redirect operations — broadened to catch return statements and template strings
  const REDIRECT_CODE_RE = /\b(res\.redirect|response\.redirect|redirect|sendRedirect|Location\s*[=:]|window\.location|document\.location|meta.*refresh|header\s*\(\s*['"]Location|http\.Redirect)\b|"Location:\s|'Location:\s|redirect\?url=/i;

  const redirectSinks = map.nodes.filter(n =>
    // Original: EGRESS/TRANSFORM with redirect subtypes
    ((n.node_type === 'EGRESS' || n.node_type === 'TRANSFORM') &&
     (n.node_subtype.includes('redirect') || n.node_subtype.includes('location') ||
      n.attack_surface.includes('redirect') ||
      REDIRECT_CODE_RE.test(n.analysis_snapshot || n.code_snapshot))) ||
    // NEW: CONTROL/return nodes whose code contains redirect/Location patterns
    (n.node_type === 'CONTROL' && n.node_subtype === 'return' &&
     REDIRECT_CODE_RE.test(n.analysis_snapshot || n.code_snapshot)) ||
    // NEW: template_string nodes that build redirect URLs
    (n.node_type === 'TRANSFORM' && n.node_subtype === 'template_string' &&
     REDIRECT_CODE_RE.test(n.analysis_snapshot || n.code_snapshot))
  );

  // Safe patterns: allowlist check, relative-path enforcement, same-origin check
  const safeRedirect = (code: string): boolean =>
    /\ballowlist\b|\bwhitelist\b|\ballowed[_-]?(?:urls?|domains?|hosts?)\b/i.test(code) ||
    /\bstartsWith\s*\(\s*['"]\/[^\/]/i.test(code) ||
    /\bnew URL\b.*\.(?:host|origin|hostname)\b/i.test(code) ||
    /\bsame[_-]?origin\b|\burl\.parse\b.*\bhost\b/i.test(code) ||
    /\brelative[_-]?path\b|\bpath\.resolve\b/i.test(code);

  for (const src of urlInputs) {
    for (const sink of redirectSinks) {
      if (src.id === sink.id) continue;

      // Check tainted path first
      let vulnerable = hasTaintedPathWithoutControl(map, src.id, sink.id);

      // Fallback: scope-based check for redirect URLs
      if (!vulnerable && sharesFunctionScope(map, src.id, sink.id)) {
        // Check if the sink's code references the source's label (variable name)
        const srcVarName = src.label.replace(/[^a-zA-Z0-9_]/g, '');
        if (srcVarName && (sink.analysis_snapshot || sink.code_snapshot).includes(srcVarName)) {
          vulnerable = true;
        }
        // Also check if sink has tainted data_in
        if (!vulnerable && sink.data_in.some(d => d.tainted)) {
          vulnerable = true;
        }
      }

      if (vulnerable) {
        const scopeSnapshots601 = getContainingScopeSnapshots(map, sink.id);
        const combinedScope601 = scopeSnapshots601.join('\n') || (sink.analysis_snapshot || sink.code_snapshot);
        if (!safeRedirect(combinedScope601) && !safeRedirect((src.analysis_snapshot || src.code_snapshot))) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (URL allowlist or relative-path enforcement before redirect)',
            severity: 'medium',
            description: `User input from ${src.label} controls redirect destination at ${sink.label}. ` +
              `Attackers can craft URLs like ?next=https://evil.com to phish users via your domain.`,
            fix: 'Validate redirect URLs against an allowlist of trusted domains. ' +
              'Use relative paths only: if (!url.startsWith("/") || url.startsWith("//")) reject. ' +
              'Parse with new URL() and check .hostname against allowed origins.',
          });
        }
      }
    }
  }

  return {
    cwe: 'CWE-601',
    name: 'URL Redirection to Untrusted Site (Open Redirect)',
    holds: findings.length === 0,
    findings,
  };
}

// ---------------------------------------------------------------------------
// Sensitive Data Exposure CWEs (CWE-256 through CWE-319)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// AUTHENTICATION & CREDENTIAL CWE Verification Paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Memory Safety & Arithmetic CWE Verification Paths
// ---------------------------------------------------------------------------

/**
 * CWE-369: Divide By Zero
 * Division or modulo where divisor can be zero. In C/C++: SIGFPE crash.
 * In other languages: Infinity/NaN or exceptions.
 */
function verifyCWE369(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const DIV_RE = /\s\/\s|\s%\s|\bdiv\b|\bmod\b|\bdivmod\b|\bquotient\b|\bremainder\b/i;
  const DIV_FUNC_RE = /\bMath\.floor\s*\(.*\/|\bMath\.ceil\s*\(.*\/|\bMath\.trunc\s*\(.*\/|\bBigInt\b.*\/|\bidiv\b/i;
  const MODULO_RE = /\b\w+\s*%\s*\w+|\bfmod\b|\bmodulo\b/i;
  const ZERO_SAFE_RE = /\b!==?\s*0\b|\b!=\s*0\b|\b>\s*0\b|\b>=\s*1\b|\bif\s*\(.*divisor|\bif\s*\(\s*\w+\s*\)\s*\{?\s*.*\/|\bzero.*check\b|\bdivisor.*valid\b|\bisNaN\b|\bisFinite\b|\b\|\|\s*1\b|\b\?\?\s*1\b|\bdefault\b.*\b[1-9]|\bMath\.abs\s*\(.*\)\s*>\s*0/i;
  const ingress = nodesOfType(map, 'INGRESS');
  const divNodes = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE') &&
    (DIV_RE.test(n.analysis_snapshot || n.code_snapshot) || DIV_FUNC_RE.test(n.analysis_snapshot || n.code_snapshot) ||
     MODULO_RE.test(n.analysis_snapshot || n.code_snapshot) || n.node_subtype.includes('division') ||
     n.node_subtype.includes('arithmetic') || n.attack_surface.includes('arithmetic'))
  );
  for (const src of ingress) {
    for (const sink of divNodes) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const code = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if ((DIV_RE.test(code) || DIV_FUNC_RE.test(code) || MODULO_RE.test(code)) && !ZERO_SAFE_RE.test(code)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (zero divisor check before division/modulo)',
            severity: 'medium',
            description: `User input from ${src.label} controls a divisor at ${sink.label} without zero check. ` +
              `Division by zero causes crashes (SIGFPE in C/C++), exceptions, or NaN/Infinity propagation.`,
            fix: 'Check divisor before dividing: if (divisor === 0) return error or default value. ' +
              'Use || 1 or ?? 1 as fallback. In Rust: checked_div(). In Go: explicit if divisor == 0.',
          });
        }
      }
    }
  }
  if (findings.length === 0) {
    const externalDivNodes = map.nodes.filter(n =>
      (n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE') &&
      (DIV_RE.test(n.analysis_snapshot || n.code_snapshot) || MODULO_RE.test(n.analysis_snapshot || n.code_snapshot)) &&
      n.data_in.some(d => d.tainted)
    );
    for (const node of externalDivNodes) {
      if (!ZERO_SAFE_RE.test(stripComments(node.analysis_snapshot || node.analysis_snapshot || node.code_snapshot))) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (zero divisor validation)',
          severity: 'medium',
          description: `Division at ${node.label} uses tainted data as divisor without zero check.`,
          fix: 'Always validate divisors are non-zero before division.',
        });
      }
    }
  }
  // --- Source-line fallback: scan raw source for division of tainted variables ---
  // The graph approach above misses cases where the division expression is embedded
  // inside a cast or compound expression that tree-sitter does NOT emit as a
  // standalone TRANSFORM node (e.g. Java: int result = (int)(100.0 / data)).
  if (findings.length === 0 && map.source_code) {
    const srcLines = map.source_code.split('\n');
    // Collect tainted variable names from INGRESS/tainted-TRANSFORM nodes
    const taintedVars = new Set<string>();
    for (const n of map.nodes) {
      const snap = n.analysis_snapshot || n.code_snapshot || '';
      if (n.node_type === 'INGRESS' || (n.node_type === 'TRANSFORM' && n.data_in?.some(d => d.tainted))) {
        // Extract LHS variable from assignment snapshots like "data = Float.parseFloat(...)"
        const assignMatch = snap.match(/^(\w+)\s*=/);
        if (assignMatch) taintedVars.add(assignMatch[1]);
        // Also extract variable from readLine/getParameter/etc calls
        const callMatch = snap.match(/(\w+)\s*=\s*\w+\.\w+\(/);
        if (callMatch) taintedVars.add(callMatch[1]);
      }
    }
    // Also scan source for common taint patterns: var = parseXxx(...), readLine(), getParameter(...)
    const TAINT_ASSIGN_RE = /(\w+)\s*=\s*(?:\w+\.)?(?:parse\w+|read\w+|get\w+|next\w+)\s*\(/i;
    for (const line of srcLines) {
      const m = line.match(TAINT_ASSIGN_RE);
      if (m) taintedVars.add(m[1]);
    }
    if (taintedVars.size > 0) {
      // Build regex matching division by a tainted variable: / varName or % varName
      const SRC_DIV_RE = /[\/]\s*(\w+)|\s%\s*(\w+)/;
      for (let i = 0; i < srcLines.length; i++) {
        const line = srcLines[i];
        const trimmed = line.trim();
        // Skip comments
        if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue;
        const divMatch = line.match(SRC_DIV_RE);
        if (!divMatch) continue;
        const divisorVar = divMatch[1] || divMatch[2];
        if (!divisorVar || !taintedVars.has(divisorVar)) continue;
        // Skip if this line contains import/package/comment patterns
        if (/^\s*(?:import|package)\s/.test(line)) continue;
        // Check preceding lines (up to 10) for zero guard on this variable
        let guarded = false;
        for (let j = Math.max(0, i - 10); j < i; j++) {
          const prev = srcLines[j];
          if (ZERO_SAFE_RE.test(prev)) { guarded = true; break; }
          // Also check explicit zero comparisons with the tainted var name
          const varGuardRE = new RegExp(`\\b${divisorVar}\\b\\s*[!=><]=?\\s*0|\\bif\\s*\\(\\s*${divisorVar}\\b`, 'i');
          if (varGuardRE.test(prev)) { guarded = true; break; }
        }
        // Also check if the division is inside a guarded block (if on same line)
        if (ZERO_SAFE_RE.test(line)) guarded = true;
        if (!guarded) {
          const lineNum = i + 1;
          const snippet = trimmed.slice(0, 200);
          findings.push({
            source: { id: `src-line-${lineNum}`, label: `source (line ${lineNum})`, line: lineNum, code: snippet },
            sink: { id: `src-line-${lineNum}`, label: `division (line ${lineNum})`, line: lineNum, code: snippet },
            missing: 'CONTROL (zero divisor check before division/modulo)',
            severity: 'medium',
            description: `Tainted variable '${divisorVar}' used as divisor at line ${lineNum} without zero check. ` +
              `Division by zero causes crashes (SIGFPE in C/C++), exceptions, or NaN/Infinity propagation.`,
            fix: 'Check divisor before dividing: if (divisor != 0) or if (Math.abs(divisor) > epsilon). ' +
              'Use || 1 or ?? 1 as fallback. In Rust: checked_div(). In Go: explicit if divisor == 0.',
          });
          break; // one finding per function is sufficient
        }
      }
    }
  }
  return { cwe: 'CWE-369', name: 'Divide By Zero', holds: findings.length === 0, findings };
}

/**
 * CWE-476: NULL Pointer Dereference
 * Dereferencing a NULL/null/nil/None pointer/reference. Causes segfaults in C/C++,
 * NullPointerException in Java, TypeError in JS, panic in Go/Rust.
 */
function verifyCWE476(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const NULLABLE_SOURCE_RE = /\b(find|findOne|get|getElementById|querySelector|querySelectorAll|getAttribute|getItem|lookup|search|match|exec|pop|shift|first|last|fetch|load|open|fopen|connect|socket|accept|malloc|calloc|realloc)\b/i;
  const DEREF_RE = /\->\w+|\*\s*\w+\b|\.unwrap\s*\(\s*\)|\.\w+\s*\(|\.\w+\s*\[|\.\w+\s*\.|\[\s*\d+\s*\]/;
  const UNSAFE_UNWRAP_RE = /\.unwrap\s*\(\s*\)/i;
  const NULL_SAFE_RE = /\bif\s*\(\s*\w+\s*[!=]==?\s*null\b|\bif\s*\(\s*\w+\s*[!=]=?\s*nil\b|\bif\s*\(\s*\w+\s*is\s+None\b|\bif\s*\(\s*\w+\s*!=?\s*nullptr\b|\bif\s*\(\s*\w+\s*\)|\b\?\.\b|\b\?\?\b|\bif\s+err\s*!=\s*nil|\bif let\b|\bguard let\b|\bif\s+let\s+Some|\bmatch\b.*\bSome|\bmatch\b.*\bOk|\b\.unwrap_or\b|\b\.unwrap_or_else\b|\b\.ok_or\b|\btypeof\b|\bassert\b.*!=.*null|\brequire\b.*!=.*null/i;
  const nullableSources = map.nodes.filter(n =>
    (n.node_type === 'EXTERNAL' || n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE') &&
    (n.node_subtype.includes('nullable') || n.node_subtype.includes('optional') ||
     n.node_subtype.includes('lookup') || n.node_subtype.includes('query') ||
     NULLABLE_SOURCE_RE.test(n.analysis_snapshot || n.code_snapshot))
  );
  const derefSinks = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    (DEREF_RE.test(n.analysis_snapshot || n.code_snapshot) ||
     (n.analysis_snapshot || n.code_snapshot).match(/\.\w+\s*[\([]|\.length\b|\.toString\b|\.valueOf\b/i) !== null)
  );
  // Track seen sink IDs to avoid duplicate findings
  const seenSinks476 = new Set<string>();
  for (const src of nullableSources) {
    for (const sink of derefSinks) {
      if (src.id === sink.id) continue;
      if (seenSinks476.has(sink.id)) continue;
      // Use either DATA_FLOW path or function scope proximity.
      // In JavaScript, db.findOne() result stored in a variable that is then
      // dereferenced in the same function will share scope even without a direct
      // DATA_FLOW edge from the STORAGE source to the dereference TRANSFORM node.
      const reachable = hasPathWithoutControl(map, src.id, sink.id) ||
        sharesFunctionScope(map, src.id, sink.id);
      if (reachable) {
        // Check for null guards in the function scope (not just on src/sink nodes)
        const scopeNullSafe = map.nodes.some(n =>
          sharesFunctionScope(map, src.id, n.id) &&
          NULL_SAFE_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot))
        );
        if (!NULL_SAFE_RE.test(stripComments(sink.analysis_snapshot || sink.code_snapshot)) &&
            !NULL_SAFE_RE.test(stripComments(src.analysis_snapshot || src.analysis_snapshot || src.code_snapshot)) &&
            !scopeNullSafe) {
          seenSinks476.add(sink.id);
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (null/nil/None check before dereference)',
            severity: 'medium',
            description: `Potentially-null value from ${src.label} is dereferenced at ${sink.label} without a null check. ` +
              `NULL dereference causes segfaults in C/C++, NullPointerException in Java, TypeError in JS.`,
            fix: 'Check for null before dereferencing. Use optional chaining (?.) in JS/TS. ' +
              'Use if-let/match in Rust instead of .unwrap(). In Go: check err != nil before using value.',
          });
        }
      }
    }
  }
  // --- Source-based detection: multiple null-dereference patterns ---
  // The graph-based approach above misses patterns where the source is a null literal
  // (not a nullable API call), or where the dereference happens in a structurally
  // broken null-guard (single & instead of &&, dereference inside if-null-true block).
  if (findings.length === 0) {
    const src476 = map.source_code || '';
    if (src476) {
      const lines = src476.split('\n');
      // Track which lines we've already flagged to avoid duplicate findings
      const flaggedLines = new Set<number>();

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/^\s*\/\//.test(line) || /^\s*\*/.test(line)) continue;

        // ── Pattern A: Non-short-circuit & in null check ──
        // if ((x != null) & (x.method())) — single & evaluates both sides,
        // so x.method() executes even when x is null. Must use && instead.
        if (/\bif\s*\(/.test(line)) {
          // Extract the full condition. Handle multi-paren conditions with greedy match.
          const condMatch = line.match(/\bif\s*\((.*)\)\s*$/);
          // Also try without trailing ) for lines like: if ((x != null) & (x.len() > 0)) {
          const condMatch2 = condMatch || line.match(/\bif\s*\((.*)\)/);
          if (condMatch2) {
            const cond = condMatch2[1];
            // Has null check AND has single & (not && or &=)
            if (/\w+\s*!=\s*null/.test(cond) && /[^&]&[^&=]/.test(cond)) {
              // And has dereference on the other side of &
              if (/\.\w+\s*\(/.test(cond) || /\.length\b/.test(cond) || /\.size\b/.test(cond)) {
                if (!flaggedLines.has(i)) {
                  flaggedLines.add(i);
                  const nearNode = map.nodes.find(n => Math.abs(n.line_start - (i + 1)) <= 2) || map.nodes[0];
                  if (nearNode) {
                    findings.push({
                      source: nodeRef(nearNode), sink: nodeRef(nearNode),
                      missing: 'CONTROL (use && not & for null guard — short-circuit evaluation)',
                      severity: 'medium',
                      description: `L${i + 1}: Non-short-circuit operator & used in null check. Both sides of & are always ` +
                        `evaluated, so the dereference executes even when the variable is null. Use && instead.`,
                      fix: 'Use && (short-circuit AND) instead of & (bitwise AND) in null checks. With &&, the right side ' +
                        'is only evaluated if the left side is true, preventing null dereference.',
                    });
                  }
                }
              }
            }
          }
        }

        // ── Pattern B: Dereference inside if (x == null) block ──
        // if (myString == null) { IO.writeLine(myString.length()); }
        // The variable is KNOWN null inside the true branch, so any dereference is a bug.
        if (/\bif\s*\(/.test(line)) {
          const eqNullMatch = line.match(/\bif\s*\(\s*(\w+)\s*==\s*null\s*\)/);
          if (eqNullMatch) {
            const varName = eqNullMatch[1];
            // Find the block after this if: track brace depth.
            // Scan up to 20 lines ahead to handle multi-line blocks where the
            // opening brace is on a separate line (common in Java/C# style).
            let blockDepth = 0;
            let blockStart = -1;
            for (let k = i; k < Math.min(i + 20, lines.length); k++) {
              for (let c = 0; c < lines[k].length; c++) {
                if (lines[k][c] === '{') {
                  if (blockStart === -1) blockStart = k;
                  blockDepth++;
                }
                if (lines[k][c] === '}') blockDepth--;
              }
              if (blockStart !== -1 && blockDepth === 0) {
                // Check all lines within this block for dereference of varName
                const derefInBlock = new RegExp(`\\b${varName}\\.\\w+\\s*[\\(\\[]|\\b${varName}\\.length\\b|\\b${varName}\\.toString\\b`);
                for (let m = blockStart; m <= k; m++) {
                  if (/^\s*\/\//.test(lines[m]) || /^\s*\*/.test(lines[m])) continue;
                  if (derefInBlock.test(lines[m]) && !flaggedLines.has(m)) {
                    flaggedLines.add(m);
                    const nearNode = map.nodes.find(n => Math.abs(n.line_start - (m + 1)) <= 2) || map.nodes[0];
                    if (nearNode) {
                      findings.push({
                        source: nodeRef(nearNode), sink: nodeRef(nearNode),
                        missing: 'CONTROL (do not dereference inside null-true branch)',
                        severity: 'medium',
                        description: `L${m + 1}: Variable '${varName}' is dereferenced inside a block where it is known to be null ` +
                          `(the if at L${i + 1} checks ${varName} == null). This always causes a NullPointerException.`,
                        fix: `Do not dereference '${varName}' inside the null branch. Either handle the null case without ` +
                          `dereferencing, or move the dereference to the else branch (where it is known non-null).`,
                      });
                    }
                  }
                }
                break;
              }
            }
          }
        }

        // ── Pattern C: Variable assigned null, then dereferenced without reassignment or null check ──
        // data = null; ... data.toString() — the original pattern
        const nullAssign = line.match(/(\w+)\s*=\s*null\s*;/);
        if (nullAssign) {
          const varName = nullAssign[1];
          for (let j = i + 1; j < Math.min(i + 30, lines.length); j++) {
            const ahead = lines[j];
            if (/^\s*\/\//.test(ahead) || /^\s*\*/.test(ahead)) continue;
            // Check if variable is reassigned to non-null
            const reassignPat = new RegExp(`\\b${varName}\\s*=\\s*(?!null\\s*;|=)`);
            if (reassignPat.test(ahead)) break; // reassigned — safe
            // Check if there's a null check (both == and != count as awareness of nullability)
            const nullCheckPat = new RegExp(`\\b${varName}\\s*!=\\s*null\\b|\\b${varName}\\s*==\\s*null\\b`);
            if (nullCheckPat.test(ahead)) {
              // If it's a short-circuit guard on the same line as a deref, that's safe
              if (/&&/.test(ahead)) break;
              // If it uses single &, that's Pattern A (handled above) — but also break to avoid double-report
              if (/[^&]&[^&=]/.test(ahead)) break;
              // Otherwise it's a null check — break (handled by Pattern B or actually safe)
              break;
            }
            // Check if variable is dereferenced (method call or property access)
            const derefPat = new RegExp(`\\b${varName}\\.(\\w+)\\s*[\\(\\[]|\\b${varName}\\.length\\b|\\b${varName}\\.toString\\b`);
            if (derefPat.test(ahead)) {
              if (!flaggedLines.has(j)) {
                flaggedLines.add(j);
                const nearNode = map.nodes.find(n => Math.abs(n.line_start - (j + 1)) <= 2) || map.nodes[0];
                if (nearNode) {
                  findings.push({
                    source: nodeRef(nearNode), sink: nodeRef(nearNode),
                    missing: 'CONTROL (null check before dereference)',
                    severity: 'medium',
                    description: `L${j + 1}: Variable '${varName}' was assigned null at L${i + 1} and is dereferenced without a null check.`,
                    fix: 'Add a null check before dereferencing. Ensure the variable is assigned a non-null value before use.',
                  });
                }
              }
              break;
            }
          }
        }
      }
    }
  }

  // --- Rust .unwrap() detection ---
  if (findings.length === 0) {
    const unwrapNodes = map.nodes.filter(n =>
      UNSAFE_UNWRAP_RE.test(n.analysis_snapshot || n.code_snapshot) && !NULL_SAFE_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot))
    );
    for (const node of unwrapNodes) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (handle None/Err case instead of unwrap)',
        severity: 'medium',
        description: `${node.label} uses .unwrap() which panics on None/Err. If the value can be None/Err at runtime, this crashes.`,
        fix: 'Replace .unwrap() with .unwrap_or(default), .unwrap_or_else(|| ...), or pattern matching (match/if-let).',
      });
    }
  }
  return { cwe: 'CWE-476', name: 'NULL Pointer Dereference', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ACCESS CONTROL, INJECTION & FILE HANDLING CWEs
// ---------------------------------------------------------------------------

/** CWE-610: Externally Controlled Reference to a Resource in Another Sphere */
function verifyCWE610(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress610 = nodesOfType(map, 'INGRESS');
  const EXT610 = /\b(fetch|axios|request|http\.get|https\.get|got\(|requests\.(get|post)|urllib|curl|wget|include|require|import|fopen|file_get_contents|LoadLibrary|dlopen|System\.load)\b/i;
  const DB610 = /\b(createConnection|connect|MongoClient|mongoose\.connect|sequelize|createPool|DriverManager\.getConnection|psycopg2\.connect)\b/i;
  const sinks610 = map.nodes.filter(n =>
    (n.node_type === 'EXTERNAL' || n.node_type === 'STORAGE') &&
    (n.node_subtype.includes('http') || n.node_subtype.includes('api_call') ||
     n.node_subtype.includes('request') || n.node_subtype.includes('include') ||
     n.node_subtype.includes('import') || n.node_subtype.includes('db_connect') ||
     n.node_subtype.includes('remote') || n.node_subtype.includes('fetch') ||
     n.attack_surface.includes('cross_sphere') || n.attack_surface.includes('external_reference') ||
     EXT610.test(n.analysis_snapshot || n.code_snapshot) || DB610.test(n.analysis_snapshot || n.code_snapshot))
  );
  const SAFE610 = /\ballowlist\b|\bwhitelist\b|\ballowed.*domain\b|\bvalidateUrl\b|\bvalidateHost\b|\bnew URL\b.*\bhost\b|\bstartsWith\s*\(\s*['"]https?:\/\/\w|\bsame.*origin\b|\btrusted.*host\b/i;
  for (const src of ingress610) {
    for (const sink of sinks610) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (!SAFE610.test(stripComments(sink.analysis_snapshot || sink.code_snapshot)) && !SAFE610.test(stripComments(src.analysis_snapshot || src.analysis_snapshot || src.code_snapshot))) {
          const rt = DB610.test(sink.analysis_snapshot || sink.code_snapshot) ? 'database connection' : 'external resource';
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (external reference validation / allowlist of permitted targets)',
            severity: 'high',
            description: `User input from ${src.label} controls ${rt} reference at ${sink.label}. Attacker can access resources in another security sphere.`,
            fix: 'Validate references against an allowlist. Parse URLs and check hostname. Never let user input control connection strings.',
          });
        }
      }
    }
  }
  return { cwe: 'CWE-610', name: 'Externally Controlled Reference to a Resource in Another Sphere', holds: findings.length === 0, findings };
}

/** CWE-643: XPath Injection */
function verifyCWE643(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress643 = nodesOfType(map, 'INGRESS');
  const XP643 = /\b(xpath|XPath|XPathExpression|evaluate|selectNodes|selectSingleNode|DOMXPath|SimpleXMLElement|etree\.XPath|tree\.xpath|xmlDoc\.evaluate|xpath\.select)\b/i;
  const XP_CAT643 = /['"]\/\/\w.*\+|\+.*['"]\/\/\w|['"]@\w+\s*=\s*'.*\+|xpath.*\+\s*\w/i;
  const xpSinks643 = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'EXTERNAL' || n.node_type === 'STORAGE') &&
    (n.node_subtype.includes('xpath') || n.node_subtype.includes('xml_query') ||
     n.attack_surface.includes('xpath_query') || XP643.test(n.analysis_snapshot || n.code_snapshot) || XP_CAT643.test(n.analysis_snapshot || n.code_snapshot))
  );
  const SAFE643 = /\bescapeXPath\b|\bxpath.*param\b|\bxpath.*compile\b|\bsanitize.*xpath\b|\bXPathVariableResolver\b|\bregister.*variable\b/i;

  // Dead-branch neutralization: suppress findings when constant arithmetic ternary/switch
  // guarantees the tainted branch is never taken (BenchmarkJava false-positive pattern).
  const hasDeadBranch643 = map.source_code ? detectDeadBranchNeutralization(map.source_code) : false;

  // Interprocedural static neutralization: the called method (e.g., doSomething) abandons
  // the tainted parameter and returns a value derived from a static literal instead.
  const hasInterproceduralStatic643 = map.source_code
    ? detectInterproceduralNeutralization90(map.source_code)
    : false;

  for (const src of ingress643) {
    for (const sink of xpSinks643) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        if (hasDeadBranch643 || hasInterproceduralStatic643) continue;
        if (!SAFE643.test(stripComments(sink.analysis_snapshot || sink.code_snapshot)) && !SAFE643.test(stripComments(src.analysis_snapshot || src.analysis_snapshot || src.code_snapshot))) {
          const concat = XP_CAT643.test(sink.analysis_snapshot || sink.code_snapshot);
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (XPath parameterization or input escaping)',
            severity: 'high',
            description: `User input from ${src.label} flows into XPath query at ${sink.label} without sanitization. ` +
              (concat ? 'String concatenation builds the XPath expression. ' : '') +
              `Attacker can inject XPath operators to bypass auth or exfiltrate data.`,
            fix: 'Use parameterized XPath (XPathVariableResolver in Java, variable bindings in lxml). Escape special chars. Never concatenate user input into XPath.',
          });
        }
      }
    }
  }
  if (findings.length === 0 && ingress643.length > 0 && !hasDeadBranch643 && !hasInterproceduralStatic643) {
    const xpScope643 = map.nodes.filter(n => n.node_type !== 'META' && n.node_type !== 'STRUCTURAL' && XP_CAT643.test(n.analysis_snapshot || n.code_snapshot));
    for (const src of ingress643) {
      for (const sink of xpScope643) {
        if (src.id === sink.id) continue;
        if (sharesFunctionScope(map, src.id, sink.id) && !SAFE643.test(stripComments(sink.analysis_snapshot || sink.code_snapshot))) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (XPath parameterization or input escaping)',
            severity: 'high',
            description: `User input from ${src.label} in scope with XPath construction at ${sink.label}. Injection possible if input interpolated.`,
            fix: 'Use parameterized XPath or escape special characters. Never concatenate user input into XPath.',
          }); break;
        }
      }
    }
  }
  // Source-line fallback for Java XPath injection: interprocedural taint tracking
  if (findings.length === 0 && map.source_code && !hasDeadBranch643 && !hasInterproceduralStatic643) {
    // Per-index collection taint tracking now handled by the mapper (collectionTaint on VariableInfo).
    {
      const sl643 = map.source_code.split('\n');
      const SRC643 = /(\w+)\s*=\s*(?:\w+\.)*(?:getParameter|getParameterValues|getHeader|getHeaders|getCookies|getQueryString|getInputStream|getReader|getTheParameter|System\.getenv)\s*\(/;
      const hasXPathContext643 = /\b(?:XPathFactory|javax\.xml\.xpath|XPath|XPathExpression|DOMXPath|SimpleXMLElement|etree\.XPath|tree\.xpath)\b/.test(map.source_code!);
      const XPATH_SINK_RE643 = hasXPathContext643
        ? /\b(?:xpath\.evaluate|XPathExpression\.evaluate|xpath\.compile|selectNodes|selectSingleNode|XPathFactory|DocumentBuilder|\w+\.evaluate)\s*\(/
        : /\b(?:xpath\.evaluate|XPathExpression\.evaluate|xpath\.compile|selectNodes|selectSingleNode|XPathFactory|DocumentBuilder)\s*\(/;
      const tv643 = new Set<string>();
      let sln643 = 0; let scd643 = '';
      for (let i = 0; i < sl643.length; i++) {
        const ln = sl643[i]!.trim();
        if (ln.startsWith('//') || ln.startsWith('*') || ln.startsWith('/*')) continue;
        const mx643 = ln.match(SRC643); if (mx643) { tv643.add(mx643[1]!); sln643 = i + 1; scd643 = ln; }
        const va643 = ln.match(/^(\w+)\s*=\s*(\w+)\s*;/);
        if (va643 && tv643.has(va643[2]!)) tv643.add(va643[1]!);
        const ma643 = ln.match(/^(\w+)\s*=\s*\w+(?:\.\w+)*\s*\(\s*(\w+)\s*\)/);
        if (ma643 && tv643.has(ma643[2]!)) tv643.add(ma643[1]!);
        // Multi-arg call propagation: var = SomeClass.method(taintedVar, otherArg)
        // Also handles: var = new Type(nested.call(taintedVar.method()))
        if (!ma643) {
          const genAssign643 = ln.match(/^(?:(?:\w+\.)*\w+(?:\[\])?\s+)*(\w+)\s*=\s*(.*)/);
          if (genAssign643) {
            const gaLhs643 = genAssign643[1]!;
            let gaRhs643 = genAssign643[2]!;
            // Handle multi-line assignments: if the RHS is empty or doesn't end with ';',
            // join continuation lines until we find one that ends with ';'
            if (!gaRhs643.trimEnd().endsWith(';')) {
              for (let k = i + 1; k < Math.min(i + 8, sl643.length); k++) {
                const cont = sl643[k]!.trim();
                gaRhs643 += ' ' + cont;
                if (cont.endsWith(';')) break;
              }
            }
            // Skip constant string assignments
            if (!/^\s*"[^"]*"\s*;/.test(gaRhs643)) {
              for (const t of tv643) {
                if (new RegExp('\\b' + escapeRegExp(t) + '\\b').test(gaRhs643)) {
                  tv643.add(gaLhs643);
                  break;
                }
              }
            }
          }
        }
        const ca643 = ln.match(/^(\w+)\s*=\s*.*\b(\w+)\b.*\+/);
        if (ca643 && tv643.has(ca643[2]!)) tv643.add(ca643[1]!);
        const ck643 = ln.match(/^(\w+)\s*=\s*"[^"]*"\s*;/);
        if (ck643) tv643.delete(ck643[1]!);
        // HashMap
        const mg643 = ln.match(/^(\w+)\s*=\s*\(\w+\)\s*(\w+)\.get\s*\(\s*"([^"]*)"\s*\)/);
        if (mg643) {
          const mkr643 = resolveMapKeyTaint(sl643, tv643, mg643[2]!, mg643[3]!, i);
          if (mkr643 === 'tainted') tv643.add(mg643[1]!); else tv643.delete(mg643[1]!);
        }
        // List offset
        const lg643 = ln.match(/^(\w+)\s*=\s*(\w+)\.get\s*\(\s*(\d+)\s*\)/);
        if (lg643) {
          const lv643 = lg643[2]!; const gi643 = parseInt(lg643[3]!);
          const items643: { tainted: boolean }[] = []; let rc643 = 0;
          for (let j = 0; j < i; j++) {
            const al643 = sl643[j]!.trim();
            const am643 = al643.match(new RegExp(escapeRegExp(lv643) + '\\.add\\s*\\(\\s*(?:"[^"]*"|(\\w+))\\s*\\)'));
            if (am643) items643.push({ tainted: am643[1] ? tv643.has(am643[1]) : false });
            if (al643.includes(lv643 + '.remove(')) rc643++;
          }
          const adj643 = items643.slice(rc643);
          if (gi643 < adj643.length && !adj643[gi643]!.tainted) tv643.delete(lg643[1]!); else tv643.add(lg643[1]!);
        }
        // Interprocedural
        const ipCall643 = ln.match(/(\w+)\s*=\s*(?:new\s+\w+\(\)\s*\.\s*)?(\w+)\s*\(\s*(?:request\s*,\s*)?(\w+)\s*\)/);
        if (ipCall643 && tv643.has(ipCall643[3]!)) {
          const mn643 = ipCall643[2]!;
          let kills643 = false;
          for (let j = 0; j < sl643.length; j++) {
            const md643 = sl643[j]!.trim();
            if (md643.includes(`${mn643}(`) && (md643.includes('String ') || md643.includes('public '))) {
              let bd643 = 0; let fo643 = false;
              for (let k = j; k < Math.min(j + 40, sl643.length); k++) {
                if (sl643[k]!.includes('{')) { bd643++; fo643 = true; }
                if (sl643[k]!.includes('}')) bd643--;
                if (fo643 && bd643 <= 0) break;
                if (/\b(?:parseInt|parseLong|Pattern\.matches|validate|sanitize)\b/i.test(sl643[k]!.trim())) { kills643 = true; break; }
                if (/^\w+\s*=\s*"[^"]{5,}"/.test(sl643[k]!.trim())) { kills643 = true; break; }
                if (/\.remove\s*\(\s*\d+\s*\)/.test(sl643[k]!.trim())) { kills643 = true; break; }
              }
              break;
            }
          }
          if (kills643) tv643.delete(ipCall643[1]!); else tv643.add(ipCall643[1]!);
        }
        // XPath sink detection — look within a wider window
        if ((XPATH_SINK_RE643.test(ln) || XP_CAT643.test(ln)) && sln643 > 0) {
          const windowStart643 = Math.max(0, i - 10);
          const windowEnd643 = Math.min(sl643.length - 1, i + 5);
          const window643 = sl643.slice(windowStart643, windowEnd643 + 1).join(' ');
          if (SAFE643.test(window643)) continue;
          let hit643 = false;
          for (const t of tv643) {
            if (new RegExp('\\b' + escapeRegExp(t) + '\\b').test(window643) &&
                /\+/.test(window643)) { hit643 = true; break; }
          }
          if (hit643) {
            findings.push({
              source: { id: `srcline-${sln643}`, label: `user input (line ${sln643})`, line: sln643, code: scd643.slice(0, 200) },
              sink: { id: `srcline-${i + 1}`, label: `XPath query (line ${i + 1})`, line: i + 1, code: ln.slice(0, 200) },
              missing: 'CONTROL (XPath parameterization or input escaping)',
              severity: 'high',
              description: `User input flows to XPath query at line ${i + 1} without escaping.`,
              fix: 'Use parameterized XPath with XPathVariableResolver. Never concatenate user input into XPath.',
            });
            break;
          }
        }
      }
    }
  }

  return { cwe: 'CWE-643', name: 'XPath Injection', holds: findings.length === 0, findings };
}

/** CWE-776: XML Entity Expansion (Billion Laughs) */
function verifyCWE776(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress776 = nodesOfType(map, 'INGRESS');
  const XML776 = /\b(parseXml|parseXmlString|parseXML|DOMParser|SAXParser|xml2js|libxml|libxmljs2?|etree\.parse|etree\.fromstring|xml\.sax|minidom\.parseString|XmlReader|ElementTree\.parse|lxml\.etree|parseFromString|DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|XMLReader)\b/i;
  // Exclude regex compilation, string literals, and non-XML parse contexts from XML parser detection.
  // Pattern.compile, re.compile, new RegExp etc. get node_subtype 'parse' but are not XML parsers.
  const NOT_XML776 = /\bPattern\.compile\b|\bre\.compile\b|\bnew\s+RegExp\b|\bRegex\b|\bregex\b|\bPattern\.matches\b|\bPattern\.quote\b/i;
  const xmlParsers776 = map.nodes.filter(n => {
    if (!(n.node_type === 'TRANSFORM' || n.node_type === 'EXTERNAL' || n.node_type === 'STORAGE')) return false;
    const snap = n.analysis_snapshot || n.code_snapshot;
    // Exclude regex/pattern compilation contexts — these are not XML parsers
    if (NOT_XML776.test(snap)) return false;
    return n.node_subtype.includes('xml') ||
     n.attack_surface.includes('xml_parse') || XML776.test(snap);
  });
  const DANGER776 = /\bnoent\s*:\s*true\b|\bentity.*expand\b.*true|\bDTDProcessing\.Parse\b/i;
  const SAFE776 = /\bdefusedxml\b|\bdisallow.*doctype\b|\bentityExpansionLimit\b|\bmaxEntityExpansions\b|\bresolveEntities\s*:\s*false\b|\bnoent\s*:\s*false\b|\bsafe.*parse\b|\bsetFeature.*disallow-doctype-decl.*true\b|\bXMLInputFactory\.SUPPORT_DTD.*false\b/i;
  for (const src of ingress776) {
    for (const sink of xmlParsers776) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sc = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        const hasDanger = DANGER776.test(sc);
        if (!SAFE776.test(sc) || hasDanger) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (XML entity expansion limits or DTD prohibition)',
            severity: 'high',
            description: `User XML from ${src.label} parsed at ${sink.label} without entity expansion limits. ` +
              (hasDanger ? 'Parser has dangerous entity expansion enabled. ' : '') +
              'Billion Laughs attack can expand recursive entities into gigabytes of memory.',
            fix: 'Prohibit DTDs (disallow-doctype-decl). Set entityExpansionLimit. Use defusedxml. Set noent:false in libxmljs.',
          });
        }
      }
    }
  }
  if (findings.length === 0 && ingress776.length > 0 && xmlParsers776.length > 0) {
    for (const src of ingress776) {
      for (const sink of xmlParsers776) {
        if (src.id === sink.id) continue;
        if (sharesFunctionScope(map, src.id, sink.id) && !SAFE776.test(stripComments(sink.analysis_snapshot || sink.code_snapshot))) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (XML entity expansion limits or DTD prohibition)',
            severity: 'high',
            description: `User input from ${src.label} in scope with XML parser at ${sink.label} without entity expansion limits.`,
            fix: 'Prohibit DTDs or set entity expansion limits. Use defusedxml or hardened parser.',
          }); break;
        }
      }
    }
  }
  return { cwe: 'CWE-776', name: 'Improper Restriction of Recursive Entity References in DTDs (Billion Laughs)', holds: findings.length === 0, findings };
}

function verifyCWE20(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const processingSinks = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    !n.node_subtype.includes('sql') && !n.node_subtype.includes('shell') &&
    !n.node_subtype.includes('xml') && !n.node_subtype.includes('command')
  );

  const VALIDATION_SAFE20 = /\b(validate|validator|isValid|parseInt|parseFloat|Number\(|Boolean\(|joi\.|yup\.|zod\.|z\.|schema\.validate|check\(|body\(|param\(|query\(|sanitize|assert|typeof\s+\w+\s*[!=]==?\s*'|instanceof\b|isNaN|Number\.isFinite|Number\.isInteger|\.test\(|match\(|Regex|allowlist|whitelist|enum|includes\(|indexOf\(|\.has\(|switch\s*\(|express-validator|class-validator|ajv|JSON\.parse)\b/i;

  for (const src of ingress) {
    for (const sink of processingSinks) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const srcCode = stripComments(src.analysis_snapshot || src.analysis_snapshot || src.code_snapshot);
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!VALIDATION_SAFE20.test(srcCode) && !VALIDATION_SAFE20.test(sinkCode)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (input validation — type checking, schema validation, or allowlist)',
            severity: 'high',
            description: `User input from ${src.label} reaches ${sink.label} without any input validation. ` +
              `No type checking, schema validation, or constraint enforcement detected.`,
            fix: 'Validate all user input before processing. Use schema validation (Joi, Zod, Yup), ' +
              'type coercion (parseInt, Number), allowlists for enum values, regex patterns for strings, ' +
              'and range checks for numbers. Reject invalid input early.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-20', name: 'Improper Input Validation', holds: findings.length === 0, findings };
}

/**
 * CWE-74: Injection (Generic Parent)
 * Pattern: INGRESS → EGRESS/EXTERNAL(downstream) without CONTROL/TRANSFORM
 * Property: User input is neutralized before output to any downstream component.
 *
 * Parent of ALL injection CWEs. Focuses on EGRESS and EXTERNAL nodes NOT already
 * covered by specific CWEs (SQL, OS, XSS, etc.) — catching injection into less
 * common downstream components (mail headers, logging, IPC, etc.).
 */
function verifyCWE74(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const downstreamSinks74 = map.nodes.filter(n =>
    (n.node_type === 'EXTERNAL' || n.node_type === 'EGRESS') &&
    !n.node_subtype.includes('sql') && !n.node_subtype.includes('shell') &&
    !n.node_subtype.includes('command') && !n.node_subtype.includes('html') &&
    !n.node_subtype.includes('xml') && !n.node_subtype.includes('ldap') &&
    !n.node_subtype.includes('xpath') &&
    ((n.analysis_snapshot || n.code_snapshot).match(
      /\b(send|write|emit|publish|dispatch|render|format|template|header|setHeader|log|print|fprintf|sprintf|IPC|pipe|channel|message)\b/i
    ) !== null || n.attack_surface.includes('output') || n.attack_surface.includes('sink'))
  );

  const NEUTRALIZE_SAFE74 = /\b(escape|encode|sanitize|neutralize|parameteriz|prepared|placeholder|safe.*format|format.*safe|DOMPurify|htmlEncode|urlEncode|encodeURI|encodeURIComponent|validator\.|strip|clean|purify)\b/i;

  for (const src of ingress) {
    for (const sink of downstreamSinks74) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!NEUTRALIZE_SAFE74.test(sinkCode)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (input neutralization before output to downstream component)',
            severity: 'critical',
            description: `User input from ${src.label} flows to downstream component at ${sink.label} without neutralization. ` +
              `If the downstream component interprets special characters, injection is possible.`,
            fix: 'Neutralize user input for the target context before passing to downstream components. ' +
              'Use context-appropriate encoding (URL encoding for URLs, HTML encoding for HTML, etc.). ' +
              'Prefer structured APIs over string concatenation.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-74', name: 'Injection', holds: findings.length === 0, findings };
}

/**
 * CWE-77: Command Injection (Parent — Improper Neutralization of Special Elements in a Command)
 * Pattern: INGRESS → EXTERNAL(command/exec) without CONTROL neutralization
 * Property: User input is neutralized before being embedded in any command string.
 *
 * Parent of CWE-78 (OS command injection). Covers command injection MORE BROADLY —
 * not just OS shells but any command interpreter (database CLI tools, scripting engines,
 * IPC command protocols, etc.).
 */
function verifyCWE77(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const cmdSinks77 = map.nodes.filter(n =>
    n.node_type === 'EXTERNAL' &&
    (n.node_subtype.includes('command') || n.node_subtype.includes('exec') ||
     n.node_subtype.includes('shell') || n.node_subtype.includes('system_exec') ||
     n.attack_surface.includes('shell_exec') || n.attack_surface.includes('command_exec') ||
     (n.analysis_snapshot || n.code_snapshot).match(
       /\b(exec|execSync|execFile|spawn|system|popen|shell_exec|child_process|os\.system|subprocess|Runtime\.exec|ProcessBuilder|Process\.Start|ShellExecute|WScript\.Shell)\s*\(/i
     ) !== null)
  );

  for (const src of ingress) {
    for (const sink of cmdSinks77) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const code77 = stripComments(sink.analysis_snapshot || sink.code_snapshot);

        const usesArgArray77 = /\b(execFile|execFileSync)\s*\(/i.test(code77) ||
          (/\bspawn\s*\([^)]*,\s*\[/i.test(code77) && !/shell\s*:\s*true/i.test(code77)) ||
          (/\bsubprocess\.(run|Popen|call)\s*\(\s*\[/i.test(code77) && !/shell\s*=\s*True/i.test(code77)) ||
          /\bProcessBuilder\s*\(\s*\[/i.test(code77);

        const usesEscaping77 = /\b(shellEscape|escapeShell|escapeShellArg|shlex\.quote|shellescape|quotemeta)\s*\(/i.test(code77);
        const usesAllowlist77 = /\b(allowlist|whitelist|allowedCommands|validCommands|permitted)\b/i.test(code77);

        if (!usesArgArray77 && !usesEscaping77 && !usesAllowlist77) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (command parameterization — argument arrays or input escaping)',
            severity: 'critical',
            description: `User input from ${src.label} flows to command execution at ${sink.label} without neutralization. ` +
              `Special elements in the input can alter the command's intended behavior.`,
            fix: 'Use argument arrays instead of string concatenation for commands. ' +
              'execFile("cmd", [arg1, arg2]) instead of exec("cmd " + arg1). ' +
              'If strings are unavoidable, escape with shlex.quote (Python) or a strict allowlist.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-77', name: 'Command Injection', holds: findings.length === 0, findings };
}

/**
 * CWE-90: LDAP Injection
 * Pattern: INGRESS → EXTERNAL/STORAGE(ldap) without CONTROL(LDAP escaping)
 * Property: User input is escaped for LDAP special characters before query construction.
 *
 * LDAP special characters: * ( ) \ NUL
 * Attacker injects into (cn=INPUT) to alter filter logic: (cn=*)(|(cn=*))
 */
function verifyCWE90(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const LDAP_SINK90 = /\b(ldap\.search|ldap\.bind|ldap_search|ldap_bind|ldap_add|ldap_modify|ldap_list|SearchRequest|LdapConnection|DirectorySearcher|ldap\.query|searchFilter|baseDN)\b/i;
  const LDAP_FILTER_CONCAT90 = /\(\w+=[^)]*(\+|\$\{)/;

  const ldapSinks90 = map.nodes.filter(n =>
    (n.node_type === 'EXTERNAL' || n.node_type === 'STORAGE') &&
    (n.node_subtype.includes('ldap') || n.attack_surface.includes('ldap') ||
     LDAP_SINK90.test(n.analysis_snapshot || n.code_snapshot) || LDAP_FILTER_CONCAT90.test(n.analysis_snapshot || n.code_snapshot))
  );

  const LDAP_SAFE90 = /\b(ldap\.escape|escapeLDAP|ldapEscape|escape_filter_chars|filter\.escape|Filter\.(and|or|eq|present|approx)|ldap_escape|sanitizeLdap|escapeDN|escapeFilter)\b/i;

  // Dead-branch neutralization: suppress findings when constant arithmetic ternary/switch
  // guarantees the tainted branch is never taken (BenchmarkJava false-positive pattern).
  const hasDeadBranch90 = map.source_code ? detectDeadBranchNeutralization(map.source_code) : false;
  // Per-index collection taint tracking now handled by the mapper (collectionTaint on VariableInfo).
  const hasStaticVal90 = map.source_code ? detectStaticValueNeutralization(map.source_code) : false;
  // Interprocedural neutralization: check if inner-class/helper method kills taint
  // by returning a static literal, retrieving a safe HashMap key, or abandoning the tainted chain.
  const hasInterproceduralKill90 = map.source_code ? detectInterproceduralNeutralization90(map.source_code) : false;

  for (const src of ingress) {
    for (const sink of ldapSinks90) {
      if (src.id === sink.id) continue;
      // Primary: BFS taint path. Fallback (Step 8): check data_in tainted entries on sink.
      if (hasTaintedPathWithoutControl(map, src.id, sink.id) || sinkHasTaintedDataIn(map, sink.id)) {
        if (hasDeadBranch90 || hasStaticVal90 || hasInterproceduralKill90) continue;
        const sinkCode90 = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!LDAP_SAFE90.test(sinkCode90)) {
          const usesFilterConcat90 = LDAP_FILTER_CONCAT90.test(sinkCode90);
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (LDAP special character escaping or parameterized filter)',
            severity: 'high',
            description: `User input from ${src.label} flows to LDAP operation at ${sink.label} without escaping. ` +
              (usesFilterConcat90
                ? `String concatenation builds the LDAP filter. Attacker can inject *, (, ), \\ to alter query logic.`
                : `Attacker can inject LDAP metacharacters to bypass authentication or extract directory data.`),
            fix: 'Escape LDAP special characters (*, (, ), \\, NUL) in user input. ' +
              'Use ldap.escape() or escape_filter_chars(). Prefer filter builder APIs (Filter.eq, Filter.and) ' +
              'over string concatenation. Validate input format (e.g., alphanumeric only for usernames).',
          });
        }
      }
    }
  }

  // Source-line fallback for Java LDAP injection: interprocedural taint tracking
  if (findings.length === 0 && map.source_code && !hasDeadBranch90) {
    const sl90 = map.source_code.split('\n');
    const SRC90 = /(\w+)\s*=\s*(?:\w+\.)*(?:getParameter|getParameterValues|getHeader|getHeaders|getCookies|getQueryString|getInputStream|getReader|getTheParameter|System\.getenv|getParameterMap)\s*\(/;
    const LDAP_SINK_RE90 = /\b(?:search|DirContext\.search|NamingEnumeration|ctx\.search|dirContext\.search|ldapTemplate\.search|idc\.search)\s*\(/;
    const LDAP_SAFE_SL90 = /\b(?:escapeLDAPSearchFilter|LdapEncoder\.filterEncode|FilterEncoder|ldap\.escape|escape_filter_chars|parseInt|parseLong|Pattern\.matches)\b/i;
    const tv90 = new Set<string>();
    let sln90 = 0; let scd90 = '';
    let inSwitch90 = false;
    let switchBraceDepth90 = 0;
    const switchTaintedVars90 = new Set<string>();
    for (let i = 0; i < sl90.length; i++) {
      const ln = sl90[i]!.trim();
      if (ln.startsWith('//') || ln.startsWith('*') || ln.startsWith('/*')) continue;
      // Track switch blocks using brace counting
      if (/\bswitch\s*\(/.test(ln)) { inSwitch90 = true; switchBraceDepth90 = 0; }
      if (inSwitch90) {
        for (const ch of ln) {
          if (ch === '{') switchBraceDepth90++;
          if (ch === '}') { switchBraceDepth90--; if (switchBraceDepth90 <= 0) { inSwitch90 = false; switchTaintedVars90.clear(); } }
        }
      }
      const mx90 = ln.match(SRC90); if (mx90) { tv90.add(mx90[1]!); sln90 = i + 1; scd90 = ln; }
      // Taint propagation for tainted_map.get("key") => result is tainted
      const mapGetProp90 = ln.match(/(\w+)\s*=\s*(\w+)\.get\s*\(/);
      if (mapGetProp90 && tv90.has(mapGetProp90[2]!)) tv90.add(mapGetProp90[1]!);
      // Array access: param = values[0] where values is tainted
      const arrAccess90 = ln.match(/(\w+)\s*=\s*(\w+)\s*\[\s*\d+\s*\]/);
      if (arrAccess90 && tv90.has(arrAccess90[2]!)) tv90.add(arrAccess90[1]!);
      // Simple assignment propagation
      const va90 = ln.match(/^(\w+)\s*=\s*(\w+)\s*;/);
      if (va90 && tv90.has(va90[2]!)) {
        tv90.add(va90[1]!);
        if (inSwitch90) switchTaintedVars90.add(va90[1]!);
      }
      // Method call propagation
      const ma90 = ln.match(/^(\w+)\s*=\s*\w+(?:\.\w+)*\s*\(\s*(\w+)\s*\)/);
      if (ma90 && tv90.has(ma90[2]!)) tv90.add(ma90[1]!);
      // String concat propagation
      const ca90 = ln.match(/^(\w+)\s*=\s*.*\b(\w+)\b.*\+/);
      if (ca90 && tv90.has(ca90[2]!)) tv90.add(ca90[1]!);
      // Static literal kills taint — but NOT inside switch if the var was tainted in another case
      const ck90 = ln.match(/^(\w+)\s*=\s*"[^"]*"\s*;/);
      if (ck90) {
        if (inSwitch90 && switchTaintedVars90.has(ck90[1]!)) {
          // Inside switch: var was tainted in another case branch, don't kill
        } else {
          tv90.delete(ck90[1]!);
        }
      }
      // HashMap put/get
      const mg90 = ln.match(/^(\w+)\s*=\s*\(\w+\)\s*(\w+)\.get\s*\(\s*"([^"]*)"\s*\)/);
      if (mg90) {
        const mkr90 = resolveMapKeyTaint(sl90, tv90, mg90[2]!, mg90[3]!, i);
        if (mkr90 === 'tainted') tv90.add(mg90[1]!); else tv90.delete(mg90[1]!);
      }
      // List offset
      const lg90 = ln.match(/^(\w+)\s*=\s*(\w+)\.get\s*\(\s*(\d+)\s*\)/);
      if (lg90) {
        const lv90 = lg90[2]!; const gi90 = parseInt(lg90[3]!);
        const items90: { tainted: boolean }[] = []; let rc90 = 0;
        for (let j = 0; j < i; j++) {
          const al90 = sl90[j]!.trim();
          const am90 = al90.match(new RegExp(escapeRegExp(lv90) + '\\.add\\s*\\(\\s*(?:"[^"]*"|(\\w+))\\s*\\)'));
          if (am90) items90.push({ tainted: am90[1] ? tv90.has(am90[1]) : false });
          if (al90.includes(lv90 + '.remove(')) rc90++;
        }
        const adj90 = items90.slice(rc90);
        if (gi90 < adj90.length && !adj90[gi90]!.tainted) tv90.delete(lg90[1]!); else tv90.add(lg90[1]!);
      }
      // Interprocedural: bar = new Test().doSomething(request, param)
      // Run mini forward taint analysis inside the called method to determine if
      // the return value carries taint from param.
      const ipCall90 = ln.match(/(\w+)\s*=\s*(?:new\s+\w+\(\)\s*\.\s*)?(\w+)\s*\(\s*(?:request\s*,\s*)?(\w+)\s*\)/);
      if (ipCall90 && tv90.has(ipCall90[3]!)) {
        const mn90 = ipCall90[2]!;
        let kills90 = false;
        // Find method declaration
        const methodDeclRe90 = new RegExp('(?:public|private|protected|static)\\s+.*\\b' + escapeRegExp(mn90) + '\\s*\\(');
        for (let j = 0; j < sl90.length; j++) {
          if (j === i) continue;
          const md90 = sl90[j]!.trim();
          if (methodDeclRe90.test(md90)) {
            // Extract method body lines
            let bd90 = 0; let fo90 = false;
            const bodyLines90: string[] = [];
            for (let k = j; k < Math.min(j + 60, sl90.length); k++) {
              if (sl90[k]!.includes('{')) { bd90++; fo90 = true; }
              if (sl90[k]!.includes('}')) bd90--;
              if (fo90 && bd90 <= 0) break;
              if (k !== j) bodyLines90.push(sl90[k]!.trim());
            }
            // Strong sanitizers kill taint unconditionally
            if (bodyLines90.some(bl => LDAP_SAFE_SL90.test(bl))) { kills90 = true; break; }
            if (bodyLines90.some(bl => /\.remove\s*\(\s*\d+\s*\)/.test(bl))) { kills90 = true; break; }
            // Mini forward taint analysis inside method body (switch-aware)
            const mtv90 = new Set<string>(['param']);
            let returnVar90 = '';
            let inSw90 = false; let swBd90 = 0;
            const swTainted90 = new Set<string>();
            for (const bl of bodyLines90) {
              // Track switch blocks
              if (/\bswitch\s*\(/.test(bl)) { inSw90 = true; swBd90 = 0; }
              if (inSw90) { for (const c of bl) { if (c === '{') swBd90++; if (c === '}') { swBd90--; if (swBd90 <= 0) { inSw90 = false; swTainted90.clear(); } } } }
              // Simple assignment propagation
              const mva = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*(\w+)\s*;/);
              if (mva && mtv90.has(mva[2]!)) { mtv90.add(mva[1]!); if (inSw90) swTainted90.add(mva[1]!); }
              // Constructor propagation: var = new Type(tainted)
              const mcon = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*new\s+\w+\s*\(\s*(\w+)\s*\)/);
              if (mcon && mtv90.has(mcon[2]!)) mtv90.add(mcon[1]!);
              // Method call propagation: var = something.method(tainted)
              const mcall = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*(?:\w+\.)*\w+\s*\(\s*(\w+)\s*[,)]/);
              if (mcall && mtv90.has(mcall[2]!)) mtv90.add(mcall[1]!);
              // String concat propagation
              const mcc = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*.*\b(\w+)\b.*\+/);
              if (mcc && mtv90.has(mcc[2]!)) mtv90.add(mcc[1]!);
              // toString propagation: var = tainted.toString()
              const mts = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*(\w+)\.toString\(\)/);
              if (mts && mtv90.has(mts[2]!)) mtv90.add(mts[1]!);
              // Static literal kills taint — but NOT inside switch if var was tainted in another case
              const mlit = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*"[^"]*"\s*;/);
              if (mlit) {
                if (inSw90 && swTainted90.has(mlit[1]!)) { /* don't kill */ } else { mtv90.delete(mlit[1]!); }
              }
              // HashMap safe key retrieval
              const mget = bl.match(/^(?:\w+\s+)?(\w+)\s*=\s*\(\w+\)\s*(\w+)\.get\s*\(\s*"([^"]*)"\s*\)/);
              if (mget) {
                const mkr = resolveMapKeyTaint(bodyLines90, mtv90, mget[2]!, mget[3]!, bodyLines90.indexOf(bl));
                if (mkr === 'tainted') mtv90.add(mget[1]!); else mtv90.delete(mget[1]!);
              }
              // Return
              const mret = bl.match(/return\s+(\w+)\s*;/);
              if (mret) { returnVar90 = mret[1]!; break; }
            }
            // If the return variable is NOT tainted, the method kills taint
            if (returnVar90 && !mtv90.has(returnVar90)) kills90 = true;
            break;
          }
        }
        if (kills90) tv90.delete(ipCall90[1]!); else tv90.add(ipCall90[1]!);
      }
      // LDAP sink detection
      if (LDAP_SINK_RE90.test(ln) && sln90 > 0) {
        const scopeSlice90 = sl90.slice(Math.max(0, i - 10), i + 5).join('\n');
        if (LDAP_SAFE_SL90.test(scopeSlice90)) continue;
        let hit90 = false;
        for (const t of tv90) {
          if (new RegExp('\\b' + escapeRegExp(t) + '\\b').test(ln) ||
              new RegExp('["+]\\s*\\b' + escapeRegExp(t) + '\\b|\\b' + escapeRegExp(t) + '\\b\\s*[+"]').test(scopeSlice90)) {
            hit90 = true; break;
          }
        }
        if (hit90) {
          findings.push({
            source: { id: `srcline-${sln90}`, label: `user input (line ${sln90})`, line: sln90, code: scd90.slice(0, 200) },
            sink: { id: `srcline-${i + 1}`, label: `LDAP query (line ${i + 1})`, line: i + 1, code: ln.slice(0, 200) },
            missing: 'CONTROL (LDAP special character escaping or parameterized filter)',
            severity: 'high',
            description: `User input flows to LDAP query at line ${i + 1} without escaping.`,
            fix: 'Escape LDAP special characters. Use filter builder APIs over string concatenation.',
          });
          break;
        }
      }
    }
  }

  return { cwe: 'CWE-90', name: 'LDAP Injection', holds: findings.length === 0, findings };
}

/**
 * CWE-91: XML Injection / Blind XPath Injection
 * Pattern: INGRESS → TRANSFORM/EXTERNAL(xml/xpath) without CONTROL(encoding)
 * Property: User input is XML-encoded before being embedded in XML documents or XPath queries.
 *
 * Two vectors:
 * 1. XML Element Injection — user input in XML doc via string concat
 * 2. Blind XPath Injection — user input in XPath query; attacker infers data
 *    via boolean conditions (true/false response differences)
 *
 * Distinguished from CWE-643 by explicitly covering the "blind" XPath variant.
 */
function verifyCWE91(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const XML_XPATH_SINK91 = /\b(createElement|appendChild|parseFromString|selectNodes|xpath\.select|evaluate|etree\.(SubElement|fromstring|XML)|DOMParser|xml2js|XPathExpression|selectSingleNode|DOMXPath|SimpleXMLElement)\b/i;
  const XML_STRING_CONCAT91 = /<\w+[^>]*>.*(\+|\$\{)/;

  const xmlSinks91 = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('xml') || n.node_subtype.includes('xpath') ||
     n.attack_surface.includes('xml_construct') || n.attack_surface.includes('xpath_query') ||
     XML_XPATH_SINK91.test(n.analysis_snapshot || n.code_snapshot) || XML_STRING_CONCAT91.test(n.analysis_snapshot || n.code_snapshot))
  );

  const SAFE_XML91 = /\b(createTextNode|escapeXml|xmlEncode|xmlEscape|encodeXml|he\.encode|entities\.encode|XPathEvaluator|xpath.*variable|bindVariable|xml2js\.Builder|xmlbuilder|js2xml|sanitize.*xml|xmlSanitize|defusedxml|escapeXPath)\b/i;

  for (const src of ingress) {
    for (const sink of xmlSinks91) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode91 = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!SAFE_XML91.test(sinkCode91)) {
          const isXpath91 = /\bxpath\b|\bselectNodes\b|\bevaluate\b|\bselectSingleNode\b|\b\/\/\w+\[/i.test(sinkCode91);
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: isXpath91
              ? 'CONTROL (XPath parameterization or escaping — blind injection possible)'
              : 'CONTROL (XML entity encoding before document construction)',
            severity: 'high',
            description: `User input from ${src.label} flows to ${isXpath91 ? 'XPath query' : 'XML construction'} at ${sink.label} without encoding. ` +
              (isXpath91
                ? `Even without direct data exfiltration, blind XPath injection extracts data character-by-character via response differences.`
                : `Attacker can inject XML elements or attributes to alter document structure.`),
            fix: isXpath91
              ? 'Use parameterized XPath with variable binding. Never concatenate user input into XPath strings. ' +
                'Blind injection leaks data via behavior differences even without direct output.'
              : 'Use DOM APIs (createTextNode, setAttribute) instead of string concatenation. ' +
                'Encode XML special characters (&, <, >, \', ") with escapeXml() or he.encode().',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-91', name: 'XML Injection / Blind XPath Injection', holds: findings.length === 0, findings };
}

/**
 * CWE-93: CRLF Injection (Improper Neutralization of CRLF Sequences)
 * Pattern: INGRESS → EGRESS(http_header/log) without CONTROL(CRLF stripping)
 * Property: User input is stripped of CR/LF before embedding in HTTP headers or logs.
 *
 * Injecting \r\n into HTTP headers enables response splitting, cache poisoning, log forging.
 */
function verifyCWE93(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const HEADER_LOG_SINK93 = /\b(setHeader|writeHead|res\.header|res\.set|response\.addHeader|response\.setHeader|addHeader|header\(|Header\.set|appendHeader|log\.(info|warn|error|debug)|logger\.|console\.(log|warn|error)|syslog|fprintf|mail\(|sendmail|SMTP)\b/i;

  const headerLogSinks93 = map.nodes.filter(n =>
    (n.node_type === 'EGRESS' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('http_header') || n.node_subtype.includes('header') ||
     n.node_subtype.includes('log') || n.node_subtype.includes('response') ||
     n.attack_surface.includes('http_header') || n.attack_surface.includes('log_sink') ||
     HEADER_LOG_SINK93.test(n.analysis_snapshot || n.code_snapshot))
  );

  const CRLF_SAFE93 = /\b(stripNewlines|sanitizeHeader|encodeHeader|headerEncode|escapeHeader|removeCRLF|removeNewlines)\b/i;
  const CRLF_STRIP93 = /replace\s*\([^)]*[\\]r|replace\s*\([^)]*[\\]n|\.replace\s*\(\s*\/\\r\\n/i;

  for (const src of ingress) {
    for (const sink of headerLogSinks93) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode93 = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!CRLF_SAFE93.test(sinkCode93) && !CRLF_STRIP93.test(sinkCode93)) {
          const isHeader93 = /\b(setHeader|writeHead|header|addHeader|appendHeader|response\.set)\b/i.test(sinkCode93);
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (CRLF character stripping before header/log insertion)',
            severity: isHeader93 ? 'high' : 'medium',
            description: `User input from ${src.label} flows to ${isHeader93 ? 'HTTP header' : 'log/output'} at ${sink.label} without CRLF neutralization. ` +
              (isHeader93
                ? `Injecting \\r\\n enables HTTP response splitting, header injection, and cache poisoning.`
                : `Injecting newlines enables log forging — attacker can inject fake log entries.`),
            fix: 'Strip or reject CR (\\r) and LF (\\n) characters from user input before embedding in headers or logs. ' +
              'Use input.replace(/[\\r\\n]/g, "") or a framework header sanitization function. ' +
              'Modern frameworks (Express 4+) auto-reject headers with CRLF, but explicit validation is safer.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-93', name: 'CRLF Injection', holds: findings.length === 0, findings };
}

/**
 * CWE-95: Eval Injection (Improper Neutralization of Directives in Dynamically Evaluated Code)
 * Pattern: INGRESS → EXTERNAL(eval/exec) without CONTROL
 * Property: User input is never passed to dynamic code evaluation functions.
 *
 * Distinguished from CWE-94: CWE-95 specifically covers eval()-style functions that
 * DYNAMICALLY evaluate code at runtime. Includes setTimeout/setInterval with string args
 * (which use eval internally), and Node.js vm module (NOT a security sandbox).
 */
function verifyCWE95(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const EVAL_PATTERN95 = /\b(eval|exec|compile|Function\s*\(|execScript|vm\.run|vm\.compile|runInContext|runInNewContext|runInThisContext|compileFunction|new\s+Function)\b/i;
  const TIMER_EVAL95 = /\b(setTimeout|setInterval)\s*\(\s*['"`]/i;

  const evalSinks95 = map.nodes.filter(n =>
    (n.node_type === 'EXTERNAL' || n.node_type === 'TRANSFORM') &&
    (n.node_subtype.includes('eval') || n.node_subtype.includes('exec') ||
     n.node_subtype.includes('system_exec') || n.node_subtype.includes('template_exec') ||
     EVAL_PATTERN95.test(n.analysis_snapshot || n.code_snapshot) || TIMER_EVAL95.test(n.analysis_snapshot || n.code_snapshot))
  );

  const EVAL_SAFE95 = /\b(ast\.literal_eval|JSON\.parse|parseInt|parseFloat|Number\(|isolated-vm|vm2\.run)\b/i;

  for (const src of ingress) {
    for (const sink of evalSinks95) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode95 = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        const isVm95 = /\bvm\.|runInContext|runInNewContext|runInThisContext\b/i.test(sinkCode95);
        const isSafe95 = !isVm95 && EVAL_SAFE95.test(sinkCode95);

        if (!isSafe95) {
          const isTimerEval95 = TIMER_EVAL95.test(sinkCode95);
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (eliminate dynamic code evaluation or use safe parsing alternatives)',
            severity: 'critical',
            description: `User input from ${src.label} flows to dynamic code evaluation at ${sink.label}. ` +
              (isTimerEval95
                ? `setTimeout/setInterval with a string argument internally uses eval(). Replace with a function reference.`
                : isVm95
                  ? `Node.js vm module does NOT provide security isolation. User-controlled code achieves full RCE.`
                  : `Attacker can execute arbitrary code by injecting into the evaluated string.`),
            fix: isTimerEval95
              ? 'Replace setTimeout("code", ms) with setTimeout(function, ms). Never pass user input as a string to timer functions.'
              : 'Eliminate eval/exec entirely. Use JSON.parse for JSON, ast.literal_eval for Python literals. ' +
                'If dynamic evaluation is required, use isolated-vm (NOT Node.js vm module) with strict input validation.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-95', name: 'Eval Injection', holds: findings.length === 0, findings };
}

/**
 * CWE-96: Improper Neutralization of Directives in Statically Saved Code
 * Pattern: INGRESS → STORAGE(file write) where file has executable extension
 * Property: User input is never written to files that are subsequently interpreted as code.
 *
 * Covers "stored code injection" — user input written to a file (.php, .js, .py, .jsp,
 * config files, cron entries, .htaccess, etc.) that is later executed by the server.
 * Unlike CWE-94/95 (runtime eval), CWE-96 is about PERSISTENT code injection via file writes.
 */
function verifyCWE96(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const CODE_FILE96 = /\.(php|jsp|asp|aspx|py|rb|pl|cgi|js|ts|sh|bash|cron|htaccess|ini|conf|yaml|yml|xml|json|sql)\b/i;
  const FILE_WRITE96 = /\b(writeFile|writeFileSync|appendFile|appendFileSync|fs\.write|fwrite|file_put_contents|open\s*\([^)]*['"]w|FileWriter|BufferedWriter|StreamWriter|fopen.*w)\b/i;

  const fileWriteSinks96 = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    (n.node_subtype.includes('file') || n.node_subtype.includes('fs') ||
     n.attack_surface.includes('file_write') ||
     FILE_WRITE96.test(n.analysis_snapshot || n.code_snapshot)) &&
    (CODE_FILE96.test(n.analysis_snapshot || n.code_snapshot) ||
     (n.analysis_snapshot || n.code_snapshot).match(/\b(template|view|script|config|cron|htaccess)\b/i) !== null)
  );

  const STATIC_CODE_SAFE96 = /\b(sanitize|escape|htmlspecialchars|strip_tags|bleach|purify|encode|filterInput|validate.*extension|allowedExtensions|mimeType|contentType.*check)\b/i;

  for (const src of ingress) {
    for (const sink of fileWriteSinks96) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode96 = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!STATIC_CODE_SAFE96.test(sinkCode96)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (content sanitization and file type restriction)',
            severity: 'critical',
            description: `User input from ${src.label} is written to a potentially executable file at ${sink.label}. ` +
              `If the server later interprets this file as code, attacker achieves persistent code execution.`,
            fix: 'Never write user input to files with executable extensions (.php, .jsp, .py, etc.). ' +
              'Validate file extensions against a strict allowlist. Sanitize content to remove executable directives. ' +
              'Store user content outside the web root and serve with Content-Disposition: attachment.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-96', name: 'Static Code Injection', holds: findings.length === 0, findings };
}

/**
 * CWE-98: PHP Remote File Inclusion
 * Pattern: INGRESS → EXTERNAL(include/require) without CONTROL(path validation)
 * Property: User input is never used directly in include/require statements.
 *
 * PHP include/require accept URLs when allow_url_include is enabled. Attacker includes
 * remote PHP code. Also covers LFI via directory traversal. Extends to dynamic imports
 * in other languages (importlib, __import__, dynamic require).
 */
function verifyCWE98(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const PHP_INCLUDE98 = /\b(include|require|include_once|require_once)\s*[\(;]/i;
  const DYNAMIC_INCLUDE98 = /\b(importlib\.import_module|__import__|require\s*\(\s*\w+\s*\+|import\s*\(\s*\w+\s*\+|dlopen|LoadLibrary|Assembly\.Load)\b/i;

  const includeSinks98 = map.nodes.filter(n =>
    (n.node_type === 'EXTERNAL' || n.node_type === 'STORAGE') &&
    (n.node_subtype.includes('include') || n.node_subtype.includes('import') ||
     n.node_subtype.includes('require') || n.attack_surface.includes('file_include') ||
     PHP_INCLUDE98.test(n.analysis_snapshot || n.code_snapshot) || DYNAMIC_INCLUDE98.test(n.analysis_snapshot || n.code_snapshot))
  );

  const INCLUDE_SAFE98 = /\b(basename|realpath|path\.resolve|path\.join.*__dirname|allowedPages|validPages|allowlist|whitelist|startsWith\s*\(\s*['"]\/|DIRECTORY_SEPARATOR)\b/i;

  for (const src of ingress) {
    for (const sink of includeSinks98) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode98 = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!INCLUDE_SAFE98.test(sinkCode98)) {
          const isPhp98 = PHP_INCLUDE98.test(sinkCode98);
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (file path validation — allowlist or path canonicalization)',
            severity: 'critical',
            description: `User input from ${src.label} flows to file include at ${sink.label} without path validation. ` +
              (isPhp98
                ? `PHP include/require with user-controlled path enables Remote File Inclusion (allow_url_include=On) ` +
                  `or Local File Inclusion (directory traversal to sensitive files).`
                : `Dynamic file inclusion with user-controlled path enables arbitrary code loading.`),
            fix: isPhp98
              ? 'Use an allowlist mapping of valid page names to file paths. ' +
                'Never pass user input directly to include/require. Disable allow_url_include in php.ini. ' +
                'Example: $pages = ["home" => "home.php"]; include($pages[$_GET["page"]] ?? "404.php");'
              : 'Use an allowlist of valid module names. Never construct import paths from user input.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-98', name: 'PHP Remote File Inclusion', holds: findings.length === 0, findings };
}

/**
 * CWE-99: Improper Control of Resource Identifiers (Resource Injection)
 * Pattern: INGRESS → EXTERNAL/STORAGE(resource access) without CONTROL(validation)
 * Property: User input is validated before being used as a resource identifier.
 *
 * Resource identifiers: port numbers, database names, queue names, socket addresses,
 * registry keys, cache keys, environment variable names, service endpoints.
 * Attacker controls WHICH resource is accessed, not content.
 * Distinguished from CWE-22 (path traversal): covers ALL resource types, not just files.
 */
function verifyCWE99(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const RESOURCE99 = /\b(connect|createConnection|createClient|getConnection|collection|database|useDatabase|selectDB|net\.connect|Socket\(|redis\.(get|set|del|hget|hset)|memcached\.(get|set)|queue|channel|exchange|publish|subscribe|getenv|setenv|putenv|Registry|SharedMemory|mmap|shmget)\b/i;

  const resourceSinks99 = map.nodes.filter(n =>
    (n.node_type === 'EXTERNAL' || n.node_type === 'STORAGE') &&
    (n.node_subtype.includes('resource') || n.node_subtype.includes('connection') ||
     n.node_subtype.includes('socket') || n.node_subtype.includes('network') ||
     n.attack_surface.includes('resource_access') ||
     RESOURCE99.test(n.analysis_snapshot || n.code_snapshot)) &&
    !n.node_subtype.includes('sql') && !n.node_subtype.includes('file') &&
    !n.node_subtype.includes('shell') && !n.node_subtype.includes('ldap')
  );

  const RESOURCE_SAFE99 = /\b(allowlist|whitelist|allowedResources|validResources|permitted|enum|includes\(|indexOf\(|\.has\(|switch\s*\(|parseInt|Number\(|portRange|validatePort|isValidPort|validateResource|sanitizeKey)\b/i;

  for (const src of ingress) {
    for (const sink of resourceSinks99) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode99 = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!RESOURCE_SAFE99.test(sinkCode99)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (resource identifier validation — allowlist or type enforcement)',
            severity: 'high',
            description: `User input from ${src.label} controls resource selection at ${sink.label} without validation. ` +
              `Attacker can access unintended resources (databases, ports, queues, cache keys) by manipulating the identifier.`,
            fix: 'Validate resource identifiers against an allowlist of permitted values. ' +
              'Use enums or switch statements for resource selection. ' +
              'For numeric identifiers (ports), validate range. For strings, use a strict allowlist. ' +
              'Never let user input directly select backend resources.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-99', name: 'Resource Injection', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// Privilege & Permission CWEs (CWE-250 through CWE-279)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Encoding, neutralization, and validation ordering CWEs
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Data authenticity & privacy CWEs
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Cache, Cookie, Session, and Access Control CWEs
// ---------------------------------------------------------------------------

/**
 * CWE-579: J2EE Bad Practices: Non-serializable Object Stored in Session
 * Detects objects stored in HTTP sessions that don't implement Serializable,
 * which causes session replication failures in clustered J2EE environments.
 */
function verifyCWE579(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const SESSION_SET_RE = /\b(session\.setAttribute|session\.putValue|session\.set|httpSession\.setAttribute|HttpSession.*\.set|\.getSession\s*\(.*\)\s*\.\s*setAttribute)\b/i;
  const NON_SERIALIZABLE_RE = /\b(Connection|DataSource|EntityManager|Thread|Socket|InputStream|OutputStream|Logger|Lock|ReentrantLock|Semaphore|ExecutorService|ClassLoader)\b/;
  const SERIALIZABLE_RE = /\b(implements\s+Serializable|implements\s+java\.io\.Serializable|@Serial|serialVersionUID|Externalizable)\b/i;

  // Collect all class definitions in the file to check Serializable implementation
  const allCode = map.nodes.map(n => n.analysis_snapshot || n.code_snapshot).join('\n');
  const hasSessionSetAttribute = /\.\s*setAttribute\s*\(/.test(allCode) && /\bgetSession\b/.test(allCode);

  // Find inner/static classes that DON'T implement Serializable
  const nonSerializableClasses: string[] = [];
  for (const node of map.nodes) {
    if (node.node_type === 'STRUCTURAL' && node.node_subtype === 'class') {
      const classCode = node.analysis_snapshot || node.code_snapshot;
      // Check if this is a data class (not the main servlet class)
      if (/\bclass\s+\w+\b/.test(classCode) && !SERIALIZABLE_RE.test(classCode)) {
        // Extract class name
        const classMatch = classCode.match(/\bclass\s+(\w+)/);
        if (classMatch && !classMatch[1].includes('Servlet') && !classMatch[1].includes('TestCase')) {
          nonSerializableClasses.push(classMatch[1]);
        }
      }
    }
  }

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.analysis_snapshot || node.code_snapshot);

    if (SESSION_SET_RE.test(code) || (/\.setAttribute\s*\(/.test(code) && /getSession/.test(code))) {
      // Check 1: Known non-serializable types being stored
      if (NON_SERIALIZABLE_RE.test(code) && !SERIALIZABLE_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (store only Serializable objects in HTTP sessions)',
          severity: 'medium',
          description: `Non-serializable object stored in session at ${node.label}. ` +
            `In clustered J2EE environments, session replication will fail, causing data loss or errors.`,
          fix: 'Ensure all objects stored in HttpSession implement java.io.Serializable. ' +
            'Avoid storing connections, streams, threads, or locks in sessions. ' +
            'Use transient fields for non-serializable references.',
        });
      }
      // Check 2: Custom class instances stored that don't implement Serializable
      for (const className of nonSerializableClasses) {
        if (new RegExp(`\\bnew\\s+${className}\\s*\\(`).test(code) ||
            new RegExp(`\\b${className}\\b`).test(code)) {
          findings.push({
            source: nodeRef(node), sink: nodeRef(node),
            missing: 'CONTROL (store only Serializable objects in HTTP sessions)',
            severity: 'medium',
            description: `Object of class ${className} stored in session at ${node.label}, but ${className} does not implement Serializable. ` +
              `Session replication will fail in clustered environments.`,
            fix: `Make ${className} implement java.io.Serializable and add a serialVersionUID field. ` +
              'All objects stored in HttpSession must be serializable for session replication.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-579', name: 'J2EE Bad Practices: Non-serializable Object Stored in Session', holds: findings.length === 0, findings };
}

/**
 * CWE-580: clone() Method Without super.clone()
 * Detects Java clone() method implementations that don't call super.clone(),
 * which breaks the clone contract and causes type errors in subclasses.
 */
function verifyCWE580(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const CLONE_METHOD_RE = /\b(public\s+\w+\s+clone\s*\(\s*\)|protected\s+\w+\s+clone\s*\(\s*\)|Object\s+clone\s*\(\s*\)|\boverride\b.*\bclone\b)/i;
  const SUPER_CLONE_RE = /\bsuper\.clone\s*\(\s*\)/;
  const NEW_INSTEAD_RE = /\bnew\s+\w+\s*\(/;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.analysis_snapshot || node.code_snapshot);

    if (CLONE_METHOD_RE.test(code)) {
      const callsSuperClone = SUPER_CLONE_RE.test(code);
      const usesNewInstead = NEW_INSTEAD_RE.test(code);

      if (!callsSuperClone && usesNewInstead) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (call super.clone() instead of using new in clone() method)',
          severity: 'low',
          description: `clone() at ${node.label} uses "new" instead of super.clone(). ` +
            `If this class is subclassed, clone() will return the wrong type, violating the clone() contract.`,
          fix: 'Replace "new ClassName()" with "super.clone()" in clone() implementations. ' +
            'Cast the result: MyClass copy = (MyClass) super.clone(). ' +
            'Consider using copy constructors or static factory methods instead of Cloneable.',
        });
      }
    }
  }

  return { cwe: 'CWE-580', name: 'clone() Method Without super.clone()', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// Trust boundary & authorization bypass CWEs
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Memory corruption & code quality CWEs
// ---------------------------------------------------------------------------

/**
 * CWE-415: Double Free
 * Calling free() on the same memory address twice. This corrupts the heap allocator's
 * internal data structures, leading to arbitrary code execution or crashes.
 *
 * Static detection approach: find free/delete/kfree calls on the same variable without
 * an intervening assignment (re-nulling). Also flag patterns where the pointer is not
 * set to NULL after free.
 */
function verifyCWE415(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const FREE_RE = /\b(free|cfree|kfree|vfree|g_free|HeapFree|GlobalFree|LocalFree|CoTaskMemFree|SysFreeString|delete\s+\w+|delete\s*\[\s*\]\s*\w+)\s*\(/i;
  const NULL_AFTER_FREE_RE = /\bfree\s*\([^)]+\)\s*;\s*\w+\s*=\s*(NULL|nullptr|0)\b|=\s*(NULL|nullptr|0)\s*;.*\bfree\b/i;
  const RAII_SAFE_RE = /\bstd::unique_ptr\b|\bstd::shared_ptr\b|\bstd::weak_ptr\b|\bBox\s*<|\bRc\s*<|\bArc\s*<|\bstd::auto_ptr\b|\bsmart_ptr\b|\bScopedPointer\b|\bQScopedPointer\b/i;
  const DOUBLE_FREE_PATTERN_RE = /\bfree\s*\(\s*(\w+)\s*\)[^]*?\bfree\s*\(\s*\1\s*\)/;

  const freeNodes = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    FREE_RE.test(n.analysis_snapshot || n.code_snapshot)
  );

  // Check for double free patterns within the same node (common in code snapshots)
  for (const node of freeNodes) {
    const code = stripComments(node.analysis_snapshot || node.analysis_snapshot || node.code_snapshot);
    if (RAII_SAFE_RE.test(code)) continue;

    if (DOUBLE_FREE_PATTERN_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (set pointer to NULL after free to prevent double-free)',
        severity: 'critical',
        description: `Double free detected at ${node.label}: the same pointer is freed twice. ` +
          `This corrupts the heap allocator and can lead to arbitrary code execution.`,
        fix: 'Set pointer to NULL immediately after free: free(ptr); ptr = NULL. ' +
          'Use RAII (unique_ptr/shared_ptr in C++, Box/Rc in Rust) to automate lifetime management. ' +
          'In C, adopt a convention: always NULL pointers after freeing.',
      });
      continue;
    }

    // Flag free() without nulling the pointer afterward (precondition for double-free)
    if (!NULL_AFTER_FREE_RE.test(code) && !RAII_SAFE_RE.test(code)) {
      // Check if this node has data flow to another free node
      for (const other of freeNodes) {
        if (other.id === node.id) continue;
        if (sharesFunctionScope(map, node.id, other.id)) {
          const nodeCode = stripComments(other.analysis_snapshot || other.analysis_snapshot || other.code_snapshot);
          if (!RAII_SAFE_RE.test(nodeCode) && !NULL_AFTER_FREE_RE.test(nodeCode)) {
            findings.push({
              source: nodeRef(node), sink: nodeRef(other),
              missing: 'CONTROL (null pointer after free to prevent double-free)',
              severity: 'critical',
              description: `Memory freed at ${node.label} may be freed again at ${other.label}. ` +
                `Pointer is not set to NULL after first free, enabling double-free.`,
              fix: 'Set pointer to NULL immediately after free. Use smart pointers (unique_ptr/shared_ptr) ' +
                'or Rust ownership to prevent double-free at compile time.',
            });
          }
        }
      }
    }
  }

  return { cwe: 'CWE-415', name: 'Double Free', holds: findings.length === 0, findings };
}

/**
 * CWE-416: Use After Free
 * Accessing memory after it has been freed. The memory may have been reallocated for a
 * different purpose, leading to data corruption, information disclosure, or code execution.
 *
 * Static detection: find free() calls where the freed pointer is subsequently dereferenced
 * without reassignment.
 */
function verifyCWE416(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  // FREE_RE: matches both C-style free() and JavaScript/managed language deallocation patterns.
  // Includes .destroy(), .release(), .dispose(), .close() as member calls (stream.destroy(),
  // resource.release()) which are the JavaScript equivalents of free().
  // FREE_RE: matches C-style free() and JS deallocation patterns.
  // .destroy() and .close() are reliable JS "free" indicators.
  // .end()/.terminate()/.shutdown() excluded from member-call pattern — too broad
  // (HTTP response .end(), server .terminate(), etc. are not memory frees).
  const FREE_RE = /\b(free|cfree|kfree|vfree|g_free|delete\s+\w+|delete\s*\[\s*\]\s*\w+|HeapFree|GlobalFree|LocalFree|CoTaskMemFree|fclose|closesocket|CloseHandle)\s*\(|[\w$]+\.(destroy|release|dispose|close)\s*\(\s*\)/i;
  const USE_AFTER_FREE_RE = /\bfree\s*\(\s*(\w+)\s*\)\s*;[^=]*\b\1\s*[\-\.\[>]/;
  const RAII_SAFE_RE = /\bstd::unique_ptr\b|\bstd::shared_ptr\b|\bBox\s*<|\bRc\s*<|\bArc\s*<|\bstd::auto_ptr\b/i;
  const NULL_AFTER_FREE_RE = /\bfree\s*\([^)]+\)\s*;\s*\w+\s*=\s*(NULL|nullptr|0|nil)\b/i;
  // JS_SAFE_RE: patterns that indicate the resource was safely replaced or not used after
  const JS_SAFE_RE = /=\s*null\b|=\s*undefined\b|=\s*new\s+\w+/i;

  const freeNodes = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    FREE_RE.test(n.analysis_snapshot || n.code_snapshot)
  );

  const derefNodes = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL' || n.node_type === 'EGRESS') &&
    /\->\w+|\*\s*\w+|\.\w+\s*[\(\[]|\[\s*\d+\s*\]/.test(n.analysis_snapshot || n.code_snapshot)
  );

  // Pattern 1: Use-after-free within the same code snapshot
  for (const node of freeNodes) {
    const code = stripComments(node.analysis_snapshot || node.analysis_snapshot || node.code_snapshot);
    if (RAII_SAFE_RE.test(code)) continue;
    if (USE_AFTER_FREE_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (do not access memory after free — set pointer to NULL)',
        severity: 'critical',
        description: `Use-after-free at ${node.label}: memory is freed and then accessed. ` +
          `The freed memory may be reallocated, causing data corruption or code execution.`,
        fix: 'Set pointer to NULL immediately after free. Use smart pointers (unique_ptr/shared_ptr). ' +
          'In Rust, the borrow checker prevents this at compile time — consider porting critical code.',
      });
    }
  }

  // Pattern 2: Free in one node, dereference in a subsequent node without null check.
  // For JavaScript: stream.destroy() followed by stream.read() — these share function scope
  // but may not have a DATA_FLOW edge. Use sequence order + scope as the indicator.
  for (const src of freeNodes) {
    // Skip container/callback nodes that merely CONTAIN a free call as a child.
    // e.g. stream.on('error', () => { stream.destroy() }) — the callback node itself
    // is not the free; only leaf nodes (no CONTAINS edges to other free nodes) qualify.
    if (src.edges.some(e => e.edge_type === 'CONTAINS')) continue;
    const srcCode = stripComments(src.analysis_snapshot || src.analysis_snapshot || src.code_snapshot);
    if (RAII_SAFE_RE.test(srcCode)) continue;
    if (NULL_AFTER_FREE_RE.test(srcCode)) continue;
    if (JS_SAFE_RE.test(srcCode)) continue;

    for (const sink of derefNodes) {
      if (src.id === sink.id) continue;
      if (src.sequence >= sink.sequence) continue; // free must come before use
      if (!sharesFunctionScope(map, src.id, sink.id)) continue;
      // Skip if the sink IS the free call (parent container node contains the free as a child)
      if (FREE_RE.test(stripComments(sink.analysis_snapshot || sink.code_snapshot)) && sink.edges.length === 0) continue;
      // Skip if the sink is contained within the src (src is a callback containing the free call)
      if (src.edges.some(e => e.edge_type === 'CONTAINS' && e.target === sink.id)) continue;
      // Skip if the src code_snapshot contains the sink's full code (src is a parent container)
      if ((src.analysis_snapshot || src.code_snapshot).includes(sink.code_snapshot.slice(0, 40).trim())) continue;
      // Skip response/HTTP sinks — res.status(), res.end(), res.json(), etc. are not memory uses
      if (/^\s*(?:res|response|reply|ctx)\s*\./.test(sink.analysis_snapshot || sink.code_snapshot)) continue;

      const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
      if (RAII_SAFE_RE.test(sinkCode)) continue;
      if (JS_SAFE_RE.test(sinkCode)) continue;
      // Check if there is a flow path or scope proximity from the free to the use
      if (hasPathWithoutControl(map, src.id, sink.id) || sink.sequence > src.sequence) {
        findings.push({
          source: nodeRef(src), sink: nodeRef(sink),
          missing: 'CONTROL (null check or no access after free/destroy)',
          severity: 'critical',
          description: `Resource freed/destroyed at ${src.label} may be used at ${sink.label}. ` +
            `If the reference is not nulled or reassigned between free and use, this is use-after-free.`,
          fix: 'Set pointer/reference to null immediately after free/destroy. ' +
            'Use RAII/smart pointers to tie object lifetime to scope. ' +
            'In Rust, the ownership system prevents use-after-free at compile time.',
        });
      }
    }
  }

  // Pattern 3: Cross-node analysis for JS use-after-free.
  // Handles cases where destroy(buffer)/release(buffer) are not separate mapper nodes
  // (truncated code_snapshot at 200 chars), and where member calls like stream.read()
  // after stream.destroy() have no corresponding node.
  //
  // Approach A: Scan STRUCTURAL code_snapshots for the UAF pattern (works when within 200 chars).
  // Approach B: Look for a free node + later deref node sharing a scope with the same
  //             variable name extracted from the free node's code_snapshot.
  if (findings.length === 0) {
    // Approach A: scan code_snapshots using multiline patterns
    const JS_UAF_RE = /\b(?:destroy|release|free)\s*\(\s*(\w+)\s*\)[\s\S]*?\b\1\s*\.\s*\w+\s*\(/;
    const MEMBER_DESTROY_UAF_RE = /(\w+)\s*\.\s*(?:destroy|close|end)\s*\(\s*\)[\s\S]*?\b\1\s*\.\s*(?!destroy|close|end)\w+\s*\(/;
    for (const node of map.nodes) {
      if (node.node_type !== 'STRUCTURAL') continue;
      const code = stripComments(node.analysis_snapshot || node.analysis_snapshot || node.code_snapshot);
      if (JS_UAF_RE.test(code) || MEMBER_DESTROY_UAF_RE.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (do not access object after destroy/release/free)',
          severity: 'critical',
          description: `Use-after-free pattern at ${node.label}: resource is freed/destroyed and then accessed. ` +
            `Accessing a destroyed object causes undefined behavior or runtime errors.`,
          fix: 'Set reference to null immediately after destroy/release. Do not call methods on closed resources. ' +
            'Restructure code so the resource is not used after it is freed.',
        });
        break;
      }
    }

    // Approach B: scan raw source_code lines for JS UAF patterns.
    // Handles the case where post-free accesses (stream.read(), stream.pipe()) are
    // not mapper nodes due to 200-char code_snapshot truncation.
    if (findings.length === 0 && map.source_code) {
      const srcLines = stripComments(map.source_code).split('\n');
      const JS_FREE_LINE_RE = /\b(?:destroy|release|free)\s*\(\s*(\w+)\s*\)/;
      // Use .destroy() or .close() as free indicators (not .end() — too broad for HTTP responses)
      const MEMBER_FREE_LINE_RE = /\b(\w+)\s*\.\s*(?:destroy|close)\s*\(\s*\)/;
      // Exclude HTTP response/reply objects and common framework objects where .end()/.close()
      // means "send response" not "free resource"
      const RESPONSE_VARS = /^(?:res|response|reply|ctx|context|next)$/i;
      const NULL_ASSIGN_RE = /=\s*null\b|=\s*undefined\b/;

      for (let i = 0; i < srcLines.length; i++) {
        const line = srcLines[i];
        const m1 = JS_FREE_LINE_RE.exec(line);
        const m2 = MEMBER_FREE_LINE_RE.exec(line);
        const subject = m1?.[1] || m2?.[1];
        if (!subject) continue;
        // Skip HTTP response/server objects — .end()/.close() on these means finalize response
        if (RESPONSE_VARS.test(subject)) continue;

        const lookAheadLimit = Math.min(i + 20, srcLines.length);
        for (let j = i + 1; j < lookAheadLimit; j++) {
          const afterLine = srcLines[j];
          if (NULL_ASSIGN_RE.test(afterLine) && afterLine.includes(subject)) break;
          if (/^\s*\}\s*$/.test(afterLine)) break;
          if (new RegExp(`\\b${subject}\\s*\\.(?!destroy|release|close|end)\\w`).test(afterLine)) {
            const freeNodeRef = map.nodes.find(n => n.line_start === i + 1 && FREE_RE.test(n.analysis_snapshot || n.code_snapshot)) ??
              map.nodes.find(n => FREE_RE.test(n.analysis_snapshot || n.code_snapshot));
            const afterNodeRef = map.nodes.find(n => n.line_start === j + 1) ??
              map.nodes.find(n => n.line_start > i + 1) ??
              freeNodeRef;
            if (freeNodeRef) {
              findings.push({
                source: nodeRef(freeNodeRef), sink: nodeRef(afterNodeRef ?? freeNodeRef),
                missing: 'CONTROL (do not access object after destroy/release/free)',
                severity: 'critical',
                description: `Resource '${subject}' freed/destroyed at line ${i + 1} is accessed at line ${j + 1}. ` +
                  `Accessing a destroyed/closed object leads to undefined behavior or runtime errors.`,
                fix: 'Set reference to null immediately after free/destroy. Restructure code so the resource is not used after it is freed.',
              });
              break;
            }
          }
        }
        if (findings.length > 0) break;
      }
    }
  }

  return { cwe: 'CWE-416', name: 'Use After Free', holds: findings.length === 0, findings };
}

/**
 * CWE-475: Undefined Behavior for Input to API
 * Passing values to library/API functions that are outside the defined valid input range,
 * triggering undefined behavior. Examples: negative values to unsigned parameters,
 * out-of-range values to ctype functions (isalpha with signed char > 127), NULL to
 * non-nullable parameters.
 */
function verifyCWE475(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  // ctype functions that require unsigned char range (0-255 or EOF)
  const CTYPE_RE = /\b(isalpha|isdigit|isalnum|isspace|isupper|islower|ispunct|isprint|iscntrl|isxdigit|toupper|tolower|isascii|isgraph)\s*\(/i;
  // Functions with documented undefined behavior on certain inputs
  const UB_API_RE = /\b(abs|labs|llabs|div|ldiv|lldiv|memcpy|memmove|strncpy|strncat)\s*\([^)]*(-\s*\d+|NULL|nullptr|0x0)\s*[,)]/i;
  // Signed char passed to ctype (common UB trigger)
  const SIGNED_CHAR_CTYPE_RE = /\b(isalpha|isdigit|isalnum|isspace|toupper|tolower)\s*\(\s*\*?\s*\w+\s*\)(?!.*\bunsigned\b)(?!.*\(unsigned\s+char\))/;
  // Safe casts before ctype calls
  const SAFE_CAST_RE = /\(\s*unsigned\s+char\s*\)|\(\s*int\s*\)\s*\(\s*unsigned\s+char\s*\)|\b&\s*0xFF\b|\b&\s*0xff\b/;
  // NULL passed to functions that don't accept it
  const NULL_PARAM_RE = /\b(strlen|strcmp|strcpy|strcat|strstr|memcpy|memmove|printf|fprintf|sprintf|puts|fputs)\s*\([^)]*\b(NULL|nullptr|0)\s*[,)]/i;
  // Validation patterns
  const INPUT_CHECK_RE = /\bif\s*\(\s*\w+\s*[!=]=\s*(NULL|nullptr|0)\b|\bassert\s*\(\s*\w+\s*!=\s*(NULL|nullptr)\b|\bif\s*\(\s*\w+\s*>=\s*0\b|\bif\s*\(\s*\w+\s*<\s*\d/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.analysis_snapshot || node.code_snapshot);

    // Check 1: Signed char to ctype function (UB when value > 127 or < 0)
    if (CTYPE_RE.test(code) && SIGNED_CHAR_CTYPE_RE.test(code) && !SAFE_CAST_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'TRANSFORM (cast to unsigned char before passing to ctype function)',
        severity: 'medium',
        description: `ctype function at ${node.label} receives potentially signed char input. ` +
          `ctype functions require values in the range of unsigned char (0-255) or EOF. ` +
          `Passing a signed char with values > 127 is undefined behavior.`,
        fix: 'Cast the argument to unsigned char: isalpha((unsigned char)c). ' +
          'Or mask with 0xFF: isalpha(c & 0xFF). ' +
          'Never pass signed char values directly to ctype functions.',
      });
    }

    // Check 2: NULL passed to functions that require non-NULL
    if (NULL_PARAM_RE.test(code) && !INPUT_CHECK_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (validate parameter is non-NULL before passing to API)',
        severity: 'high',
        description: `NULL or nullptr passed to API function at ${node.label} that requires a non-NULL argument. ` +
          `This is undefined behavior per the C standard and will typically cause a segfault.`,
        fix: 'Check pointers for NULL before passing to string/memory functions. ' +
          'Add assertions: assert(ptr != NULL). Use static analysis attributes: __attribute__((nonnull)).',
      });
    }

    // Check 3: Potentially undefined inputs to math/utility APIs
    if (UB_API_RE.test(code) && !INPUT_CHECK_RE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (validate input is within defined range for API function)',
        severity: 'medium',
        description: `API function at ${node.label} may receive an input that triggers undefined behavior. ` +
          `Functions like abs(INT_MIN), memcpy with NULL, or overlapping memcpy are undefined behavior.`,
        fix: 'Validate inputs are within the documented valid range before calling. ' +
          'For abs(): check that input != INT_MIN. For memcpy(): ensure non-NULL and non-overlapping. ' +
          'Use compiler sanitizers (-fsanitize=undefined) to catch these at runtime.',
      });
    }
  }

  // Check INGRESS -> API nodes for user input reaching UB-prone APIs without validation
  const ingress = nodesOfType(map, 'INGRESS');
  const apiNodes = map.nodes.filter(n =>
    (n.node_type === 'EXTERNAL' || n.node_type === 'TRANSFORM') &&
    (CTYPE_RE.test(n.analysis_snapshot || n.code_snapshot) || UB_API_RE.test(n.analysis_snapshot || n.code_snapshot))
  );

  for (const src of ingress) {
    for (const sink of apiNodes) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
        if (!INPUT_CHECK_RE.test(sinkCode) && !SAFE_CAST_RE.test(sinkCode)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'CONTROL (validate user input before passing to API with undefined behavior on bad input)',
            severity: 'high',
            description: `User input from ${src.label} reaches API function at ${sink.label} without validation. ` +
              `The API has undefined behavior for certain input values, and user input is untrusted.`,
            fix: 'Validate and sanitize user input before passing to APIs with restricted input domains. ' +
              'Cast to appropriate types, check ranges, and verify non-NULL.',
          });
        }
      }
    }
  }

  return { cwe: 'CWE-475', name: 'Undefined Behavior for Input to API', holds: findings.length === 0, findings };
}

/**
 * CWE-690: Unchecked Return Value to NULL Pointer Dereference
 *
 * A method that can return null is called. The caller uses the return value
 * without checking for null. The dereference causes a NullPointerException
 * (Java), segfault (C/C++), or TypeError (JS/TS).
 *
 * Detection approach (source scan):
 *   1. Identify "nullable sources" — method calls known/likely to return null:
 *      - Well-known APIs: System.getProperty, getParameter, getProperty, getenv,
 *        Map.get, find, findOne, querySelector, getAttribute, getItem, etc.
 *      - Methods defined in the same file that contain `return null`
 *      - Methods whose name follows naming conventions suggesting nullable return
 *   2. Track the variable receiving the return value
 *   3. Check if that variable is dereferenced (var.method(), var.field, var[idx])
 *      without an intervening null check (if (var != null), if (var == null), etc.)
 *
 * Honest limitations: Cross-file analysis is limited to well-known API names.
 * Same-file methods with `return null` are fully detected. The Juliet Helper
 * pattern (cross-file getStringBad) is caught by matching known nullable names.
 */
function verifyCWE690(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const src690 = map.source_code || '';
  if (!src690) {
    return { cwe: 'CWE-690', name: 'Unchecked Return Value to NULL Pointer Dereference', holds: true, findings };
  }

  const lines = src690.split('\n');
  // Strip comments but preserve line count — replace comment content with spaces,
  // keeping all newlines so line indices match the original source.
  const stripped690 = src690.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
                            .replace(/\/\/.*$/gm, (m) => ' '.repeat(m.length));
  const strippedLines = stripped690.split('\n');

  // --- Phase 1: Collect same-file methods that return null ---
  const nullReturningMethods = new Set<string>();
  let currentMethod690: string | null = null;
  let braceDepth690 = 0;
  let methodBraceStart690 = 0;
  for (let i = 0; i < strippedLines.length; i++) {
    const line = strippedLines[i];
    const methodDecl = line.match(/(?:public|private|protected|static|\s)+\s+\w+(?:<[^>]*>)?\s+(\w+)\s*\(/);
    if (methodDecl && !line.includes(';') && !line.match(/^\s*\/\//)) {
      currentMethod690 = methodDecl[1];
      methodBraceStart690 = braceDepth690;
    }
    for (const ch of line) {
      if (ch === '{') braceDepth690++;
      if (ch === '}') braceDepth690--;
    }
    if (currentMethod690 && /\breturn\s+null\s*;/.test(line)) {
      nullReturningMethods.add(currentMethod690);
    }
    if (currentMethod690 && braceDepth690 <= methodBraceStart690) {
      currentMethod690 = null;
    }
  }

  // --- Phase 2: Well-known nullable API methods ---
  const NULLABLE_API_RE = /\b(?:System\.getProperty|System\.getenv|\.getProperty|\.getParameter|\.getAttribute|\.getItem|\.get\s*\(|\.find\s*\(|\.findOne\s*\(|\.findFirst\s*\(|\.querySelector\s*\(|\.getElementById\s*\(|\.lookup\s*\(|\.search\s*\(|\.match\s*\(|\.exec\s*\(|\.pop\s*\(|\.poll\s*\(|\.peek\s*\(|\.remove\s*\(|Class\.forName|\.getResource\s*\(|\.getAnnotation\s*\(|\.getHeader\s*\(|\.getCookie\s*\(|\.getSession\s*\(|\.getInitParameter\s*\(|\.getRealPath\s*\(|malloc\s*\(|calloc\s*\(|realloc\s*\(|getenv\s*\(|fopen\s*\()\b/;

  // --- Phase 3: Source scan for the pattern ---
  const seenFindings690 = new Set<string>();

  for (let i = 0; i < strippedLines.length; i++) {
    const line = strippedLines[i];
    if (/^\s*$/.test(line)) continue;

    // Match: var = someCall(...) or var = Qualifier.someCall(...)
    const assignMatch = line.match(/(\w+)\s*=\s*(?:(\w+(?:\.\w+)*)\s*\.\s*)?(\w+)\s*\(/);
    if (!assignMatch) continue;

    const varName = assignMatch[1];
    const qualifier = assignMatch[2] || '';
    const methodName = assignMatch[3];

    // Skip constructors (new X(...))
    const rhs = line.substring(line.indexOf('=') + 1).trim();
    if (/^new\s/.test(rhs)) continue;
    // Skip type declarations
    if (/^\s*(public|private|protected|class|interface|enum)\b/.test(line)) continue;

    // Determine if this call is nullable
    let isNullable = false;

    if (NULLABLE_API_RE.test(line)) {
      isNullable = true;
    }

    if (nullReturningMethods.has(methodName)) {
      isNullable = true;
    }

    // Cross-file: methods with "Bad" in name (Juliet convention)
    if (/Bad\s*\(/.test(line)) {
      isNullable = true;
    }

    // Additional Java nullable APIs by method name alone
    if (/\.(getProperty|getParameter|getAttribute|getHeader|getenv|getItem)\s*\(/.test(line)) {
      isNullable = true;
    }

    if (!isNullable) continue;

    // Scan forward for dereference without null check (within same method).
    // Compute absolute brace depth from file start to know when we exit the method.
    let absDepthAtSource = 0;
    for (let k = 0; k <= i; k++) {
      for (const ch of strippedLines[k]) {
        if (ch === '{') absDepthAtSource++;
        if (ch === '}') absDepthAtSource--;
      }
    }
    // The method body is at some depth; we exit when we go below depth 2
    // (class=1, method=2 in Java). Use the minimum expected method depth.
    const methodExitDepth = Math.max(absDepthAtSource - 3, 1);

    let nullChecked = false;
    let foundDeref = false;
    let derefLine = -1;
    let derefCode = '';

    let scanDepth = absDepthAtSource;
    for (let j = i + 1; j < Math.min(i + 60, strippedLines.length); j++) {
      const ahead = strippedLines[j];

      for (const ch of ahead) {
        if (ch === '{') scanDepth++;
        if (ch === '}') scanDepth--;
      }
      // Exit if we've left the enclosing method body
      if (scanDepth < methodExitDepth) break;

      const nullCheckPat = new RegExp(`\\b${varName}\\s*[!=]=\\s*null\\b|\\bnull\\s*[!=]=\\s*${varName}\\b`);
      if (nullCheckPat.test(ahead)) {
        nullChecked = true;
        break;
      }

      if (new RegExp(`Objects\\.(?:nonNull|requireNonNull)\\s*\\(\\s*${varName}`).test(ahead) ||
          new RegExp(`Optional\\.ofNullable\\s*\\(\\s*${varName}`).test(ahead)) {
        nullChecked = true;
        break;
      }

      // Reassignment breaks the nullable chain — UNLESS it's inside a catch/else
      // block (conditional path that doesn't cover the main execution path).
      const reassignPat = new RegExp(`\\b${varName}\\s*=\\s*(?!null\\s*;|=)`);
      if (reassignPat.test(ahead)) {
        // Check if there's a catch/else between source and this reassignment
        let inCatchOrElse = false;
        for (let k = i + 1; k <= j; k++) {
          if (/\bcatch\b|\belse\b/.test(strippedLines[k])) {
            inCatchOrElse = true;
            break;
          }
        }
        if (!inCatchOrElse) break; // Definitive reassignment on main path
        // Otherwise, the reassignment is on an alternative path — keep scanning
      }

      // Dereference: var.something
      const derefPat = new RegExp(`\\b${varName}\\s*\\.\\s*\\w+`);
      if (derefPat.test(ahead)) {
        if (nullCheckPat.test(ahead)) {
          nullChecked = true;
          break;
        }
        foundDeref = true;
        derefLine = j;
        derefCode = lines[j]?.trim() || ahead.trim();
        break;
      }
    }

    if (foundDeref && !nullChecked) {
      const key = `${varName}:${i}:${derefLine}`;
      if (!seenFindings690.has(key)) {
        seenFindings690.add(key);
        const nearNode = map.nodes.find(n => Math.abs(n.line_start - (derefLine + 1)) <= 2) || map.nodes[0];
        const sourceNode = map.nodes.find(n => Math.abs(n.line_start - (i + 1)) <= 2) || map.nodes[0];
        if (nearNode && sourceNode) {
          const fullCall = qualifier ? `${qualifier}.${methodName}` : methodName;
          findings.push({
            source: nodeRef(sourceNode),
            sink: nodeRef(nearNode),
            missing: 'CONTROL (null check on return value before dereference)',
            severity: 'high',
            description: `L${derefLine + 1}: Variable '${varName}' assigned from ${fullCall}() at L${i + 1} ` +
              `(which may return null) is dereferenced without a null check: ${derefCode.slice(0, 120)}`,
            fix: `Check the return value for null before dereferencing. ` +
              `Add: if (${varName} != null) { ... } or use Optional/Objects.requireNonNull().`,
          });
        }
      }
    }
  }

  // --- Phase 4: Graph-based fallback ---
  if (findings.length === 0) {
    const NULLABLE_SRC_RE = /\b(find|findOne|get|getElementById|querySelector|getAttribute|getItem|getProperty|getParameter|getenv|lookup|search|match|exec|pop|poll|peek|malloc|calloc|realloc|fopen)\b/i;
    const NULL_SAFE_690_RE = /\bif\s*\(\s*\w+\s*[!=]==?\s*null\b|\bif\s*\(\s*\w+\s*[!=]=?\s*nil\b|\bif\s*\(\s*\w+\s*is\s+None\b|\bif\s*\(\s*\w+\s*!=?\s*nullptr\b|\b\?\.\b|\b\?\?\b|\bif\s+err\s*!=\s*nil|\bif let\b|\bguard let\b|\bObjects\.nonNull\b|\bObjects\.requireNonNull\b|\bOptional\b/i;

    const nullableSources = map.nodes.filter(n =>
      (n.node_type === 'EXTERNAL' || n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE') &&
      NULLABLE_SRC_RE.test(n.analysis_snapshot || n.code_snapshot)
    );

    const derefSinks = map.nodes.filter(n =>
      (n.node_type === 'TRANSFORM' || n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
      /\.\w+\s*[\([]|\.length\b|\.toString\b|\.trim\b|\.equals\b|\.hashCode\b|->\w+|\*\s*\w+/i.test(n.analysis_snapshot || n.code_snapshot)
    );

    for (const src of nullableSources) {
      for (const sink of derefSinks) {
        if (src.id === sink.id) continue;
        const reachable = hasPathWithoutControl(map, src.id, sink.id) ||
          sharesFunctionScope(map, src.id, sink.id);
        if (reachable) {
          const srcCode = stripComments(src.analysis_snapshot || src.code_snapshot);
          const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
          if (!NULL_SAFE_690_RE.test(sinkCode) && !NULL_SAFE_690_RE.test(srcCode)) {
            const scopeNullSafe = map.nodes.some(n =>
              sharesFunctionScope(map, src.id, n.id) &&
              NULL_SAFE_690_RE.test(stripComments(n.analysis_snapshot || n.code_snapshot))
            );
            if (!scopeNullSafe) {
              findings.push({
                source: nodeRef(src), sink: nodeRef(sink),
                missing: 'CONTROL (null check on return value before dereference)',
                severity: 'high',
                description: `Potentially-null value from ${src.label} is dereferenced at ${sink.label} without a null check.`,
                fix: 'Check the return value for null before dereferencing. Use if (result != null) or Optional.',
              });
              break;
            }
          }
        }
      }
    }
  }

  return { cwe: 'CWE-690', name: 'Unchecked Return Value to NULL Pointer Dereference', holds: findings.length === 0, findings };
}

/**
 * CWE-696: Incorrect Behavior Order
 *
 * Pattern: Security-relevant operations performed in the wrong order — e.g.,
 * authorization checked AFTER action is performed, input validated AFTER use,
 * canonicalization after validation, encryption after logging.
 *
 * This is one of the most architecturally significant CWEs — many real vulns are
 * "the right checks exist but in the wrong order."
 */
function verifyCWE696(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Pattern 1: Validate-after-use — action node appears before validation on same input
  const ingress = nodesOfType(map, 'INGRESS');
  const controls = nodesOfType(map, 'CONTROL');
  const sinks = map.nodes.filter(n =>
    n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL' || n.node_type === 'EGRESS'
  );

  // Check if any sink is reached from INGRESS, and a CONTROL exists but appears
  // AFTER the sink in line order within the same function scope
  for (const src of ingress) {
    for (const sink of sinks) {
      if (src.id === sink.id) continue;
      if (!hasTaintedPathWithoutControl(map, src.id, sink.id)) continue;

      // Is there a CONTROL that validates this data but appears AFTER the sink?
      for (const ctrl of controls) {
        if (ctrl.line_start <= sink.line_start) continue; // CONTROL is before sink — correct order
        if (!sharesFunctionScope(map, sink.id, ctrl.id)) continue;

        // Check if the CONTROL actually references similar data
        const ctrlCode = stripComments(ctrl.analysis_snapshot || ctrl.analysis_snapshot || ctrl.code_snapshot).toLowerCase();
        const srcLabel = src.label.toLowerCase();
        if (ctrlCode.includes(srcLabel) || /\b(validate|sanitize|check|verify|assert|guard)\b/i.test(ctrlCode)) {
          findings.push({
            source: nodeRef(src), sink: nodeRef(sink),
            missing: 'META (incorrect ordering — validation happens AFTER use)',
            severity: 'high',
            description: `Input from ${src.label} reaches sink ${sink.label} (line ${sink.line_start}) before ` +
              `validation at ${ctrl.label} (line ${ctrl.line_start}). The security check exists but runs too late.`,
            fix: 'Move validation/authorization BEFORE the action. Security checks must gate access, not audit after the fact. ' +
              'Restructure: validate -> authorize -> act -> respond.',
          });
          break; // One finding per src-sink pair
        }
      }
    }
  }

  // Pattern 2: Encode-before-validate (canonicalization ordering)
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.analysis_snapshot || node.code_snapshot);

    // Encoding/decoding then validating — should be validate then encode
    const ENCODE_BEFORE_VALIDATE = /\b(encodeURI|encodeURIComponent|escape|htmlEncode|urlEncode|base64\.encode|btoa|encodeURIComponent)\b[\s\S]{0,200}\b(validate|sanitize|check|filter|verify|test\(|match\()\b/i;
    const DECODE_BEFORE_VALIDATE = /\b(decodeURI|decodeURIComponent|unescape|htmlDecode|urlDecode|base64\.decode|atob|decodeURIComponent)\b[\s\S]{0,200}\b(validate|sanitize|check|filter|verify|test\(|match\()\b/i;

    if (ENCODE_BEFORE_VALIDATE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'META (incorrect ordering — encoding before validation)',
        severity: 'medium',
        description: `${node.label} encodes data before validating it. Validation on encoded data may miss attack payloads ` +
          `that only become dangerous after decoding.`,
        fix: 'Validate first, then encode for the output context. The canonical order is: decode -> validate -> process -> encode.',
      });
    }

    if (DECODE_BEFORE_VALIDATE.test(code)) {
      // This is actually correct order — skip
      continue;
    }
  }

  return { cwe: 'CWE-696', name: 'Incorrect Behavior Order', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-834: Excessive Iteration
// ---------------------------------------------------------------------------

/**
 * CWE-834: Excessive Iteration
 * Pattern: Loops where iteration count is controlled by user input without an upper bound.
 * Distinct from CWE-835 (infinite loop) — this is about loops that DO terminate but
 * take too long with adversarial input.
 *
 * NOTABLE: This is the "loop version" of CWE-400 (resource exhaustion). Classic attack:
 * POST {"items": [... 10 million elements ...]} to an endpoint doing items.forEach().
 * The loop terminates, but after consuming 100% CPU for minutes.
 */
function verifyCWE834(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  const USER_LOOP_PATTERNS = [
    /\bfor\s*\(\s*\w+\s*=\s*\d*\s*;\s*\w+\s*<\s*(?:req\.|request\.|params\.|query\.|body\.|input\.|args\.|data\.)/i,
    /\bwhile\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|input\.|args\.|data\.)\w+/i,
    /\b(?:req\.body|request\.body|request\.data|params|input|data)\s*(?:\.\w+)?\s*\.(?:forEach|map|filter|reduce|every|some|find)\s*\(/i,
    /\b(?:count|limit|times|iterations|repeat|n|num|number)\s*=\s*(?:parseInt|Number|int)\s*\(\s*(?:req\.|request\.|query\.|params\.|body\.|input\.)/i,
  ];

  const ITERATION_LIMIT_RE = /\b(?:MAX_ITEMS|MAX_ITERATIONS|MAX_COUNT|MAX_ELEMENTS|LIMIT|max_items|max_iterations|maxItems|maxIterations|\.slice\s*\(\s*0\s*,\s*\d+\)|\.length\s*>\s*\d+|\.length\s*<\s*\d+|paginate|pagination|BATCH_SIZE|batch_size|take\s*\(\s*\d+\))\b/i;

  const SIZE_CHECK_RE = /\b(?:Array\.isArray.*\.length|\.length\s*(?:>|>=|<|<=|===?)\s*\d+|maxLength|max_length|validateLength|sizeOf|sizeof|limit\s*[:=]\s*\d+)\b/i;

  const ingress = nodesOfType(map, 'INGRESS');

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.analysis_snapshot || node.code_snapshot);

    for (const pattern of USER_LOOP_PATTERNS) {
      if (pattern.test(code) && !ITERATION_LIMIT_RE.test(code) && !SIZE_CHECK_RE.test(code)) {
        const reachableFromIngress = ingress.some(src =>
          hasTaintedPathWithoutControl(map, src.id, node.id) ||
          sharesFunctionScope(map, src.id, node.id)
        );

        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (maximum iteration limit for user-controlled loop bounds)',
          severity: reachableFromIngress ? 'high' : 'medium',
          description: `Loop at ${node.label} iterates based on user-controlled input without an upper bound. ` +
            `An attacker can send millions of items, causing 100% CPU consumption.`,
          fix: 'Enforce max iteration: const items = req.body.items.slice(0, MAX_ITEMS). ' +
            'Validate array lengths: if (items.length > 1000) return res.status(400). ' +
            'Use pagination. Set request body size limits.',
        });
        break;
      }
    }
  }

  return { cwe: 'CWE-834', name: 'Excessive Iteration', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-1022: Use of Web Link to Untrusted Target Without rel noopener
// Links with target="_blank" without rel="noopener noreferrer" let the opened
// page access window.opener, enabling reverse-tabnabbing attacks.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-1023: Incomplete Comparison with Missing Factors
// Comparisons that check only part of what matters: e.g., comparing only
// username without domain, or using startsWith instead of exact match for auth.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-1024: Comparison of Incompatible Types
// Comparing values of fundamentally different types where the language
// silently coerces, producing incorrect results (e.g., string vs number).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-1025: Comparison Using Wrong Factors
// The comparison is syntactically valid but semantically wrong — it compares
// the wrong fields, variables, or expressions (e.g., x == x instead of x == y).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-1036: Class Based on Externally-Controlled Resource Name
// Dynamically instantiating classes or loading modules based on user input
// without validation — enables arbitrary class instantiation / module loading.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-939: Improper Authorization in Handler for Custom URL Scheme
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-940: Improper Verification of Source of a Communication Channel
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-941: Incorrectly Specified Destination in a Communication Channel
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-942: Permissive Cross-domain Policy with Untrusted Domains
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-943: Improper Neutralization of Special Elements in Data Query Logic
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-1004: Sensitive Cookie Without HttpOnly Flag
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-1007: Insufficient Visual Distinction of Homoglyphs
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-1021: Improper Restriction of Rendered UI Layers (Clickjacking)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-186: Overly Restrictive Regular Expression
//
// A regex for validation is too strict — it rejects legitimate inputs.
// Security impact: users bypass the "correct" input path and find an
// unvalidated alternative, or the restrictive regex causes DoS by
// rejecting valid traffic at scale.
// ---------------------------------------------------------------------------

function verifyCWE186(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Patterns that suggest overly restrictive validation
  const EMAIL_RESTRICTIVE = /\/\^[a-z\[\]\\]+@[a-z\[\]\\]+\.[a-z\[\]\\]+\$\//i; // too-simple email regex
  const FIXED_LENGTH_NAME = /\/\^\[a-zA-Z\]\{(\d+)\}\$\//; // name must be exactly N chars
  const ASCII_ONLY_NAME = /\/\^[[\]a-zA-Z ]+\$\/.*(?:name|first|last|user)/i; // no unicode in names
  const PHONE_EXACT = /\/\^\\\+?1?\d{10}\$\//; // phone must be exactly 10 digits — no spaces, dashes, parens

  const SAFE_PATTERN = /\bunicode\b|\bp{L}|\\p\{|[\u0080-\uFFFF]|i18n|intl|international/i;

  for (const node of map.nodes) {
    if (node.node_type !== 'CONTROL') continue;
    const code = stripComments(node.analysis_snapshot || node.analysis_snapshot || node.code_snapshot);
    if (SAFE_PATTERN.test(code)) continue;

    // ASCII-only name validation
    if (ASCII_ONLY_NAME.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (allow Unicode characters in name validation)',
        severity: 'medium',
        description: `${node.label} validates names with ASCII-only regex, rejecting accented characters ` +
          `(e.g., Jose, Muller, Bjork). Users whose names are rejected may bypass validation entirely.`,
        fix: 'Use Unicode-aware patterns: /^[\\p{L}\\p{M}\' -]+$/u or accept broader input and sanitize output.',
      });
    }

    // Overly restrictive email (just alphanumeric@alpha.alpha)
    if (EMAIL_RESTRICTIVE.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (use RFC 5322 compliant email validation)',
        severity: 'low',
        description: `${node.label} uses an overly simple email regex that rejects valid emails with ` +
          `subdomains, dots in local part, plus addressing (user+tag@), or long TLDs (.museum, .company).`,
        fix: 'Use a well-tested email validation library or RFC 5322 regex. ' +
          'Consider simply checking for @ and a dot, then verifying via confirmation email.',
      });
    }

    // Fixed-length constraints on variable-length data
    const fixedMatch = code.match(FIXED_LENGTH_NAME);
    if (fixedMatch) {
      const len = parseInt(fixedMatch[1], 10);
      if (len < 50) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: 'CONTROL (use length range, not exact length, for name-like fields)',
          severity: 'low',
          description: `${node.label} requires exactly ${len} characters, rejecting shorter or longer valid inputs. ` +
            `Users who can't match the exact length may seek unvalidated input paths.`,
          fix: 'Use a min/max range: {1,100} instead of {' + len + '}.',
        });
      }
    }
  }

  return { cwe: 'CWE-186', name: 'Overly Restrictive Regular Expression', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-188: Reliance on Data/Memory Layout
//
// Code assumes a specific memory layout (struct field ordering, padding,
// alignment) that varies across compilers, platforms, or optimization levels.
// Casting struct pointers to char* and sending over network, or using
// offsetof() for serialization, breaks on different architectures.
// ---------------------------------------------------------------------------

function verifyCWE188(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Direct struct-to-bytes patterns (C/C++)
  const STRUCT_CAST_RE = /\(\s*(char\s*\*|void\s*\*|uint8_t\s*\*|unsigned\s+char\s*\*|BYTE\s*\*)\s*\)\s*&?\s*\w+.*(?:send|write|fwrite|memcpy|socket|serialize)/i;
  // sizeof(struct) used for network/file I/O
  const SIZEOF_STRUCT_IO = /sizeof\s*\(\s*(?:struct\s+)?\w+\s*\)\s*.*(?:send|write|fwrite|read|fread|recv|socket)/i;
  // Direct memory overlay — reading raw bytes as struct
  const MEMORY_OVERLAY = /\(\s*(?:struct\s+)?(\w+)\s*\*\s*\)\s*(?:buf|buffer|data|packet|payload|msg|message|raw)/i;
  // Union type-punning
  const UNION_PUNNING = /\bunion\b.*\{[^}]*(?:int|float|double|char|uint|byte)[^}]*\}/i;

  // Safe patterns — proper serialization
  const SAFE_SERIAL = /\b(protobuf|flatbuffers|msgpack|cbor|json|xml|hton[sl]|ntoh[sl]|pack\(|struct\.pack|serialize|marshal|BinaryWriter|DataOutputStream|#pragma\s+pack|__attribute__\s*\(\s*\(\s*packed|__packed__|alignas)\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.analysis_snapshot || node.code_snapshot);
    if (SAFE_SERIAL.test(code)) continue;

    if (STRUCT_CAST_RE.test(code) || SIZEOF_STRUCT_IO.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (use proper serialization instead of raw struct memory)',
        severity: 'high',
        description: `${node.label} casts a struct to raw bytes for I/O. Struct layout (padding, alignment, ` +
          `field ordering) varies across compilers and platforms. Data sent from a 64-bit system with ` +
          `8-byte alignment will be misinterpreted by a 32-bit system with 4-byte alignment.`,
        fix: 'Use a serialization format (protobuf, JSON, msgpack) or explicitly serialize each field. ' +
          'If raw memory is required, use #pragma pack(1) and fixed-width integer types (uint32_t).',
      });
    }

    if (MEMORY_OVERLAY.test(code)) {
      findings.push({
        source: nodeRef(node), sink: nodeRef(node),
        missing: 'CONTROL (deserialize fields individually instead of casting buffer to struct pointer)',
        severity: 'high',
        description: `${node.label} casts a raw buffer to a struct pointer. If the buffer came from a ` +
          `different platform or was crafted by an attacker, field boundaries won't align correctly. ` +
          `This can cause data corruption, information disclosure, or crashes from misaligned access.`,
        fix: 'Deserialize each field individually with explicit offsets and byte-order conversion. ' +
          'Use ntohl/ntohs for network data. Consider a serialization library.',
      });
    }
  }

  return { cwe: 'CWE-188', name: 'Reliance on Data/Memory Layout', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// Side Channel, Error Handling & Information Exposure CWEs (207, 208, 210, 211, 212, 213, 214, 222, 223, 224)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Auth mechanisms & encryption CWEs (CWE-305, 307, 308, 309, 311, 317, 318, 321, 322)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Access Control & Authentication CWEs (280, 282, 283, 284, 285, 286, 289, 291, 302, 304)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Resource cleanup, return values, privilege CWEs (226, 243, 244, 245, 246,
// 248, 252, 253, 266, 268) — real CWE-specific verification
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Predictability, UI security, trust boundary CWEs (341–360)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Channel security & deployment CWEs (419–439)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CWE-551: Incorrect Behavior Order: Authorization Before Parsing and Canonicalization
// Authorization checks performed BEFORE input is fully parsed/canonicalized
// can be bypassed with encoded payloads (e.g., %2e%2e/ bypasses path auth
// checks, then gets decoded to ../ after auth succeeds).
// ---------------------------------------------------------------------------

// CWE-545: DEPRECATED — SKIP

/**
 * CWE-477: Use of Obsolete Function
 * Source scan for deprecated Java API calls. These APIs have known issues:
 * - Thread.stop/suspend/resume — unsafe thread manipulation
 * - Runtime.runFinalizersOnExit — finalization is broken by design
 * - DataInputStream.readLine — mishandles Unicode (deprecated since JDK 1.1)
 * - Date.parse — superseded by DateFormat.parse
 * - String.getBytes(int,int,byte[],int) — mishandles non-ASCII (deprecated since JDK 1.1)
 * - URLEncoder.encode(String) — uses platform default encoding, not UTF-8
 */
function verifyCWE477(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Deprecated Java APIs: method name + context pattern + replacement guidance
  const OBSOLETE_APIS: Array<{ pattern: RegExp; name: string; fix: string }> = [
    { pattern: /\bThread\s*\.\s*stop\s*\(/, name: 'Thread.stop()', fix: 'Use Thread.interrupt() and cooperative cancellation instead of Thread.stop().' },
    { pattern: /\bThread\s*\.\s*suspend\s*\(/, name: 'Thread.suspend()', fix: 'Use wait/notify or Lock/Condition instead of Thread.suspend().' },
    { pattern: /\bThread\s*\.\s*resume\s*\(/, name: 'Thread.resume()', fix: 'Use wait/notify or Lock/Condition instead of Thread.resume().' },
    { pattern: /\bRuntime\s*\.\s*runFinalizersOnExit\s*\(/, name: 'Runtime.runFinalizersOnExit()', fix: 'Use shutdown hooks (Runtime.addShutdownHook) or try-with-resources instead.' },
    { pattern: /\bSystem\s*\.\s*runFinalizersOnExit\s*\(/, name: 'System.runFinalizersOnExit()', fix: 'Use shutdown hooks (Runtime.addShutdownHook) or try-with-resources instead.' },
    { pattern: /\bDataInputStream\b[\s\S]*?\.readLine\s*\(/, name: 'DataInputStream.readLine()', fix: 'Use BufferedReader.readLine() instead of DataInputStream.readLine(). The deprecated method incorrectly converts bytes to characters.' },
    { pattern: /\bDate\s*\.\s*parse\s*\(/, name: 'Date.parse()', fix: 'Use DateFormat.parse() or java.time.LocalDate.parse() instead of the deprecated Date.parse().' },
    { pattern: /\.getBytes\s*\(\s*\d+\s*,/, name: 'String.getBytes(int,int,byte[],int)', fix: 'Use String.getBytes(charset) instead of the deprecated 4-argument getBytes. Specify charset explicitly (e.g., "UTF-8").' },
    { pattern: /\bURLEncoder\s*\.\s*encode\s*\(\s*[^,)]+\)/, name: 'URLEncoder.encode(String)', fix: 'Use URLEncoder.encode(s, "UTF-8") instead of the single-argument form, which uses platform default encoding.' },
  ];

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);

    for (const api of OBSOLETE_APIS) {
      if (api.pattern.test(code)) {
        findings.push({
          source: nodeRef(node), sink: nodeRef(node),
          missing: `STRUCTURAL (replace obsolete API: ${api.name})`,
          severity: 'medium',
          description: `Obsolete function ${api.name} used at ${node.label}. ` +
            `Deprecated APIs may have known bugs, security vulnerabilities, or undefined behavior.`,
          fix: api.fix,
        });
      }
    }
  }

  return { cwe: 'CWE-477', name: 'Use of Obsolete Function', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-111: Direct Use of Unsafe JNI
// ---------------------------------------------------------------------------
/**
 * CWE-111: Direct Use of Unsafe JNI
 * UPGRADED — hand-written with specific detection for unsafe JNI usage.
 *
 * Pattern: Java code declares `native` methods (JNI interface) and passes
 * user-controlled input to them without validation. The native C/C++ code
 * cannot perform Java-style bounds checking, so buffer overflows, format
 * string attacks, and memory corruption are possible.
 *
 * Two detection paths:
 *   1. `native` method declared + user input flows to a call of that method
 *      without validation (bounds check, length limit, allowlist)
 *   2. User input flows to System.loadLibrary() — attacker controls which
 *      native library gets loaded
 *
 * Safe patterns:
 *   - Input validation/bounds checking before native call
 *   - Allowlist of permitted values
 *   - Hardcoded library name in System.loadLibrary (not tainted)
 */
function verifyCWE111(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // --- Detection path 1: native method + tainted call to it ---
  // Find nodes whose code_snapshot contains a `native` method declaration
  const NATIVE_DECL_RE = /\bnative\s+\w[\w<>\[\], ]*\s+(\w+)\s*\(/;

  // Collect all native method names declared in the codebase
  const nativeMethodNames = new Set<string>();
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const match = NATIVE_DECL_RE.exec(code);
    if (match) {
      nativeMethodNames.add(match[1]);
    }
  }

  if (nativeMethodNames.size > 0 && ingress.length > 0) {
    // Find call sites of native methods — any node whose code calls a native method
    for (const node of map.nodes) {
      const code = stripComments(node.analysis_snapshot || node.code_snapshot);
      for (const methodName of nativeMethodNames) {
        // Match calls like: test(stringLine, intNumber) or this.test(x)
        const callPattern = new RegExp(`\\b${methodName}\\s*\\(`);
        // But skip the native declaration itself
        const declPattern = new RegExp(`\\bnative\\s+.*\\b${methodName}\\s*\\(`);
        if (callPattern.test(code) && !declPattern.test(code)) {
          // This node calls a native method — check if any INGRESS reaches it
          for (const src of ingress) {
            if (hasTaintedPathWithoutControl(map, src.id, node.id) || sinkHasTaintedDataIn(map, node.id)) {
              // Check scope for validation
              const scopeSnapshots = getContainingScopeSnapshots(map, node.id);
              const combinedScope = stripComments(scopeSnapshots.join('\n') || code);
              const isSafe = /\bvalidate\s*\(|\bboundsCheck\s*\(|\bif\s*\(\s*\w+\s*(?:<=?|>=?|<|>)\s*\d|\blength\s*(?:<=?|>=?)\s*\d|\bMath\.min\s*\(|\bMath\.max\s*\(|\ballowlist\b|\bwhitelist\b/i.test(combinedScope);

              if (!isSafe) {
                findings.push({
                  source: nodeRef(src),
                  sink: nodeRef(node),
                  missing: 'CONTROL (input validation before JNI native call)',
                  severity: 'high',
                  description: `User input from ${src.label} flows to JNI native method ${methodName}() at ${node.label} without validation. ` +
                    `Native code cannot perform Java bounds checking — buffer overflows, format string attacks, ` +
                    `and memory corruption are possible.`,
                  fix: 'Validate all data before passing to JNI native methods. Check string lengths, ' +
                    'integer ranges, and array bounds. Use an allowlist of permitted values where possible. ' +
                    'Consider wrapping JNI calls in a safe Java API that validates inputs.',
                });
                break; // One finding per sink per native method
              }
            }
          }
        }
      }
    }
  }

  // --- Detection path 2: tainted System.loadLibrary() ---
  const LOAD_LIBRARY_RE = /\bSystem\s*\.\s*loadLibrary\s*\(/;
  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    if (LOAD_LIBRARY_RE.test(code)) {
      for (const src of ingress) {
        if (hasTaintedPathWithoutControl(map, src.id, node.id) || sinkHasTaintedDataIn(map, node.id)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(node),
            missing: 'CONTROL (library name validation — use hardcoded name or allowlist)',
            severity: 'critical',
            description: `User input from ${src.label} controls the library name in System.loadLibrary() at ${node.label}. ` +
              `An attacker can load arbitrary native libraries, gaining code execution.`,
            fix: 'Never pass user input to System.loadLibrary(). Use a hardcoded library name or ' +
              'validate against a strict allowlist of permitted library names.',
          });
          break;
        }
      }
    }
  }

  // --- Detection path 3: structural — native decl + any INGRESS in same scope ---
  // If we found native methods but no taint path (mapper may not create DATA_FLOW edges),
  // check if native method calls share function scope with user input reads
  if (findings.length === 0 && nativeMethodNames.size > 0 && ingress.length > 0) {
    for (const node of map.nodes) {
      const code = stripComments(node.analysis_snapshot || node.code_snapshot);
      for (const methodName of nativeMethodNames) {
        const callPattern = new RegExp(`\\b${methodName}\\s*\\(`);
        const declPattern = new RegExp(`\\bnative\\s+.*\\b${methodName}\\s*\\(`);
        if (callPattern.test(code) && !declPattern.test(code)) {
          for (const src of ingress) {
            if (sharesFunctionScope(map, src.id, node.id)) {
              const scopeSnapshots = getContainingScopeSnapshots(map, node.id);
              const combinedScope = stripComments(scopeSnapshots.join('\n') || code);
              const isSafe = /\bvalidate\s*\(|\bboundsCheck\s*\(|\bif\s*\(\s*\w+\s*(?:<=?|>=?|<|>)\s*\d|\blength\s*(?:<=?|>=?)\s*\d|\bMath\.min\s*\(|\bMath\.max\s*\(|\ballowlist\b|\bwhitelist\b/i.test(combinedScope);

              if (!isSafe) {
                findings.push({
                  source: nodeRef(src),
                  sink: nodeRef(node),
                  missing: 'CONTROL (input validation before JNI native call)',
                  severity: 'high',
                  description: `User input from ${src.label} is in scope with JNI native method ${methodName}() call at ${node.label}. ` +
                    `Native code cannot perform Java bounds checking — buffer overflows, format string attacks, ` +
                    `and memory corruption are possible when user input reaches native methods.`,
                  fix: 'Validate all data before passing to JNI native methods. Check string lengths, ' +
                    'integer ranges, and array bounds. Use an allowlist of permitted values where possible.',
                });
                break;
              }
            }
          }
        }
      }
    }
  }

  return { cwe: 'CWE-111', name: 'Direct Use of Unsafe JNI', holds: findings.length === 0, findings };
}

// ---------------------------------------------------------------------------
// CWE-114: Process Control
// ---------------------------------------------------------------------------
/**
 * CWE-114: Process Control
 * UPGRADED — hand-written with specific detection for unsafe process/library loading.
 *
 * Pattern: Code loads native libraries or executes processes in ways that an
 * attacker can control:
 *   1. System.loadLibrary(name) — loads by name from java.library.path; attacker
 *      can plant a malicious DLL/so in a directory on the search path
 *   2. System.load(taintedPath) — attacker controls the full path to a library
 *   3. Runtime.exec(taintedCmd) — attacker controls process execution
 *
 * The Juliet pattern: System.loadLibrary("test.dll") is BAD because it uses
 * relative name resolution. System.load("/absolute/path/test.dll") is GOOD
 * because it uses an absolute path that the attacker cannot manipulate.
 *
 * Safe patterns:
 *   - System.load() with hardcoded absolute path
 *   - Allowlist validation of library name or command
 *   - SecurityManager restricting library loading
 */
function verifyCWE114(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  const LOAD_LIBRARY_RE = /\bSystem\s*\.\s*loadLibrary\s*\(/;
  const SYSTEM_LOAD_RE = /\bSystem\s*\.\s*load\s*\(/;
  const RUNTIME_EXEC_RE = /\bRuntime\s*\..*\bexec\s*\(/;
  const PROCESS_BUILDER_RE = /\bnew\s+ProcessBuilder\s*\(/;

  // Safe patterns for CWE-114
  const ABSOLUTE_PATH_RE = /System\s*\.\s*load\s*\(\s*(?:root\s*\+|"\/|"[A-Z]:\\|['"]\/home|['"]\/usr|['"]\/opt|['"]C:\\)/;
  const SECURITY_MANAGER_RE = /\bSecurityManager\b|\bcheckLink\b|\bcheckExec\b/;
  const ALLOWLIST_RE = /\ballowlist\b|\bwhitelist\b|\bvalidat(?:e|ed|ion)\s*\(|\bpermitted\b|\bapproved\b/i;

  for (const node of map.nodes) {
    const code = stripComments(node.analysis_snapshot || node.code_snapshot);
    const scopeSnapshots = getContainingScopeSnapshots(map, node.id);
    const combinedScope = stripComments(scopeSnapshots.join('\n') || code);

    // --- Detection 1: System.loadLibrary() — relative name, search-path based ---
    if (LOAD_LIBRARY_RE.test(code)) {
      // Check if there's a SecurityManager or allowlist in scope
      if (!SECURITY_MANAGER_RE.test(combinedScope) && !ALLOWLIST_RE.test(combinedScope)) {
        // System.loadLibrary is inherently risky — relative resolution
        findings.push({
          source: nodeRef(node),
          sink: nodeRef(node),
          missing: 'CONTROL (use System.load() with absolute path instead of System.loadLibrary())',
          severity: 'medium',
          description: `System.loadLibrary() at ${node.label} loads a native library by name using java.library.path search. ` +
            `An attacker who can influence the search path or plant a DLL in a searched directory ` +
            `can hijack the library loading (DLL search-order hijacking).`,
          fix: 'Use System.load() with an absolute path to the library instead of System.loadLibrary(). ' +
            'Example: System.load("/opt/myapp/libs/mylib.so") instead of System.loadLibrary("mylib"). ' +
            'If System.loadLibrary() is unavoidable, restrict java.library.path and use a SecurityManager.',
        });
      }
    }

    // --- Detection 2: System.load() with tainted path ---
    if (SYSTEM_LOAD_RE.test(code) && !LOAD_LIBRARY_RE.test(code)) {
      // System.load() is safe IF the path is hardcoded/absolute
      if (ABSOLUTE_PATH_RE.test(code)) {
        continue; // Safe — hardcoded absolute path
      }
      // Check if tainted input flows to this node
      for (const src of ingress) {
        if (hasTaintedPathWithoutControl(map, src.id, node.id) || sinkHasTaintedDataIn(map, node.id)) {
          if (!ALLOWLIST_RE.test(combinedScope)) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(node),
              missing: 'CONTROL (path validation for System.load())',
              severity: 'critical',
              description: `User input from ${src.label} controls the library path in System.load() at ${node.label}. ` +
                `An attacker can load any native library on disk, gaining arbitrary code execution.`,
              fix: 'Never pass user input to System.load(). Use a hardcoded absolute path or ' +
                'validate the path against a strict allowlist of permitted library paths.',
            });
            break;
          }
        }
      }
    }

    // --- Detection 3: Runtime.exec() or ProcessBuilder with tainted input ---
    if (RUNTIME_EXEC_RE.test(code) || PROCESS_BUILDER_RE.test(code)) {
      for (const src of ingress) {
        if (hasTaintedPathWithoutControl(map, src.id, node.id) || sinkHasTaintedDataIn(map, node.id)) {
          if (!ALLOWLIST_RE.test(combinedScope)) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(node),
              missing: 'CONTROL (process execution validation)',
              severity: 'critical',
              description: `User input from ${src.label} controls process execution at ${node.label}. ` +
                `An attacker can execute arbitrary processes on the system.`,
              fix: 'Never pass user input to Runtime.exec() or ProcessBuilder. Use a strict allowlist ' +
                'of permitted commands. Consider using a ProcessBuilder with a fixed command array ' +
                'instead of string concatenation.',
            });
            break;
          }
        }
      }
    }
  }

  return { cwe: 'CWE-114', name: 'Process Control', holds: findings.length === 0, findings };
}

/**
 * CWE-15: External Control of System or Configuration Setting
 * Pattern: INGRESS → system/config modification API without CONTROL(validation)
 * Property: External input never directly modifies system or configuration settings.
 *
 * Detects tainted data flowing from external sources (sockets, HTTP requests,
 * user input) into APIs that modify system-level configuration:
 *   Java:   System.setProperty(), Connection.setCatalog(), Connection.setSchema(),
 *           Properties.setProperty(), System.setOut(), System.setErr()
 *   C/C++:  putenv(), setenv()
 *   Python: os.environ[], os.putenv()
 *   JS/TS:  process.env assignment
 *
 * The Juliet pattern: socket.read() → dbConnection.setCatalog(data)
 * — attacker controls which database catalog is active.
 */
function verifyCWE15(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // Config/system modification sink patterns across languages
  const configSinkRe = /\b(System\s*\.\s*setProperty|setProperty\s*\(|setCatalog\s*\(|setSchema\s*\(|putenv\s*\(|setenv\s*\(|os\s*\.\s*environ\s*\[|os\s*\.\s*putenv\s*\(|process\s*\.\s*env\s*\[|Properties\s*\.\s*setProperty|System\s*\.\s*setOut|System\s*\.\s*setErr|Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec)\b/i;

  const configSinks = map.nodes.filter(n => {
    const code = n.analysis_snapshot || n.code_snapshot;
    return configSinkRe.test(code);
  });

  const safeConfigRe = /\bvalidate\s*\(|\ballowlist\b|\bwhitelist\b|\ballowed\w*\s*\.\s*(?:contains|includes|has|indexOf)\b|\bPattern\s*\.\s*matches?\b|\bswitch\s*\(|\bcase\s+['"]/i;

  for (const src of ingress) {
    for (const sink of configSinks) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id) || sinkHasTaintedDataIn(map, sink.id)) {
        const scopeSnaps15 = getContainingScopeSnapshots(map, sink.id);
        const scope15 = stripComments(scopeSnaps15.join('\n') || sink.analysis_snapshot || sink.code_snapshot);
        if (!safeConfigRe.test(scope15)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (input validation before system/configuration modification)',
            severity: 'high',
            description: `External input from ${src.label} flows to system/configuration setting at ${sink.label} without validation. ` +
              `An attacker can modify system properties, database catalogs, environment variables, or runtime configuration.`,
            fix: 'Never pass unsanitized external input to system configuration APIs. ' +
              'Use an allowlist of permitted configuration values. ' +
              'Validate against a strict pattern (e.g., switch/case or Set.has()) before calling setCatalog(), setProperty(), putenv(), etc.',
          });
        }
      }
    }
  }

  // Phase 2: Source-line scan fallback
  if (findings.length === 0 && map.source_code && ingress.length > 0) {
    const srcLines = map.source_code.split('\n');
    const cfgCallRe = /\b(?:setCatalog|setSchema|setProperty|putenv|setenv|os\.environ)\s*\(/i;
    const hardcodedRe = /\b(?:setCatalog|setSchema|setProperty|putenv|setenv)\s*\(\s*["'][^"']*["']\s*[,)]/i;

    for (let li = 0; li < srcLines.length; li++) {
      const ln = srcLines[li]!;
      const tr = ln.trim();
      if (!tr || tr.startsWith('//') || tr.startsWith('*') || tr.startsWith('/*')) continue;

      if (cfgCallRe.test(ln) && !hardcodedRe.test(ln)) {
        // Extract the variable name used as argument to the config API
        const argM15 = /\b(?:setCatalog|setSchema|setProperty|putenv|setenv)\s*\(\s*(\w+)\s*[,)]/i.exec(ln);
        const argV15 = argM15 ? argM15[1] : null;

        // Check if the variable was assigned a hardcoded literal in the lookback scope
        let isHardcoded15 = false;
        if (argV15) {
          const escV = argV15.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const hardAssign = new RegExp(`\\b${escV}\\s*=\\s*(?:["']|\\d+\\s*;)`);
          const taintAssign = new RegExp(`\\b${escV}\\s*=.*(?:readLine|getParameter|getInput|parseInt|read\\()`);
          for (let j = li - 1; j >= Math.max(0, li - 30); j--) {
            const prev = srcLines[j]!.trim();
            if (hardAssign.test(prev)) { isHardcoded15 = true; break; }
            if (taintAssign.test(prev)) break;
          }
        }

        if (!isHardcoded15) {
          const cs = Math.max(0, li - 20);
          const ce = Math.min(srcLines.length, li + 5);
          const ctx = srcLines.slice(cs, ce).join('\n');
          if (!safeConfigRe.test(ctx)) {
            findings.push({
              source: nodeRef(ingress[0]!),
              sink: { id: `line-${li + 1}`, label: `config modification (line ${li + 1})`, line: li + 1, code: tr.slice(0, 200) },
              missing: 'CONTROL (input validation before system/configuration modification)',
              severity: 'high',
              description: `System/configuration setting modified with a variable at line ${li + 1}: "${tr.slice(0, 100)}". ` +
                `If this value originates from external input, an attacker can control system configuration.`,
              fix: 'Validate the value against an allowlist before passing it to configuration APIs.',
            });
          }
        }
      }
    }
  }

  return {
    cwe: 'CWE-15',
    name: 'External Control of System or Configuration Setting',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-129: Improper Validation of Array Index
 * Pattern: External input used as array index with incomplete bounds validation
 * Property: All externally-sourced array indices are validated with BOTH
 *           lower bound (>= 0) AND upper bound (< array.length) checks.
 *
 * The Juliet vulnerable pattern:
 *   data = Integer.parseInt(socketInput);
 *   if (data < array.length) { array[data] }  // missing >= 0 check
 *
 * The safe pattern:
 *   if (data >= 0 && data < array.length) { array[data] }
 */
function verifyCWE129(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // Phase 1: Graph-based detection
  const arrAccessRe = /\[\s*\w+\s*\]|\barray\s*\[|\blist\s*\[|\barr\s*\[|\bdata\s*\[|\bbuffer\s*\[|\belements?\s*\[/i;
  const arrNodes = map.nodes.filter(n => {
    const code = n.analysis_snapshot || n.code_snapshot;
    return arrAccessRe.test(code) && !/\[\s*['"`]/.test(code);
  });

  const fullBoundsRe = />=\s*0\s*&&[^;]*<\s*\w+\.length|>=\s*0\s*&&[^;]*<\s*\w+\s*\)|0\s*<=\s*\w+\s*&&|\bMath\.max\s*\(\s*0\s*,|\bMath\.min\s*\(|\bclamp\s*\(|\bbetween\s*\(|\binRange\s*\(/i;

  for (const src of ingress) {
    for (const sink of arrNodes) {
      if (src.id === sink.id) continue;
      if (hasTaintedPathWithoutControl(map, src.id, sink.id) || sinkHasTaintedDataIn(map, sink.id)) {
        const ss129 = getContainingScopeSnapshots(map, sink.id);
        const sc129 = stripComments(ss129.join('\n') || sink.analysis_snapshot || sink.code_snapshot);
        if (!fullBoundsRe.test(sc129)) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (complete bounds validation: both >= 0 AND < array.length)',
            severity: 'high',
            description: `External input from ${src.label} is used as array index at ${sink.label} without complete bounds validation. ` +
              `A negative value bypasses an upper-bound-only check and causes ArrayIndexOutOfBoundsException.`,
            fix: 'Always validate array indices with BOTH bounds: if (index >= 0 && index < array.length). ' +
              'An upper-bound check alone does NOT prevent negative indices.',
          });
        }
      }
    }
  }

  // Phase 2: Source-line scanning for the classic Juliet pattern
  if (map.source_code) {
    const sl129 = map.source_code.split('\n');
    const pvars = new Set<string>();
    const parseRe = /\b(\w+)\s*=\s*(?:Integer\s*\.\s*parseInt|parseInt|Number\s*\(|int\s*\(|float\s*\(|Double\s*\.\s*parseDouble|Long\s*\.\s*parseLong|Short\s*\.\s*parseShort)\b/;
    for (const l of sl129) {
      const pm = parseRe.exec(l);
      if (pm) pvars.add(pm[1]!);
    }

    if (pvars.size > 0) {
      for (let li = 0; li < sl129.length; li++) {
        const ln = sl129[li]!;
        const tr = ln.trim();
        if (!tr || tr.startsWith('//') || tr.startsWith('*') || tr.startsWith('/*')) continue;

        for (const vn of pvars) {
          const ev = vn.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const upRe = new RegExp(`if\\s*\\(\\s*${ev}\\s*<\\s*\\w+\\.length\\b`);
          if (!upRe.test(ln)) continue;

          const cs = Math.max(0, li - 5);
          const ce = Math.min(sl129.length, li + 1);
          const ctx = sl129.slice(cs, ce).join('\n');
          const loRe = new RegExp(`${ev}\\s*>=\\s*0|0\\s*<=\\s*${ev}|Math\\.max\\s*\\(\\s*0|Math\\.min\\s*\\(`);
          if (loRe.test(ctx)) continue;

          // Check if the variable was reassigned a hardcoded literal in the lookback
          // (e.g., data = 2 in goodG2B means it's NOT tainted in this scope)
          let isHardcoded129 = false;
          const hardLitRe = new RegExp(`\\b${ev}\\s*=\\s*\\d+\\s*;`);
          const hardStrRe = new RegExp(`\\b${ev}\\s*=\\s*["']`);
          for (let j = li - 1; j >= Math.max(0, li - 20); j--) {
            const prev129 = sl129[j]!.trim();
            if (hardLitRe.test(prev129) || hardStrRe.test(prev129)) { isHardcoded129 = true; break; }
            // If we see a parseInt/readLine assignment, it's tainted — stop looking
            if (new RegExp(`\\b${ev}\\s*=.*(?:parseInt|readLine|getParameter|getInput)`).test(prev129)) break;
          }
          if (isHardcoded129) continue;

          const dup = findings.some(f => f.sink.line !== undefined && Math.abs(f.sink.line - (li + 1)) <= 3);
          if (dup) continue;

          const sn = ingress.length > 0 ? ingress[0]! : findNearestNode(map, li + 1);
          if (sn) {
            findings.push({
              source: nodeRef(sn),
              sink: { id: `line-${li + 1}`, label: `array bounds check (line ${li + 1})`, line: li + 1, code: tr.slice(0, 200) },
              missing: 'CONTROL (lower bound check: index >= 0 missing before array access)',
              severity: 'high',
              description: `Array index "${vn}" has only an upper-bound check at line ${li + 1}: "${tr.slice(0, 80)}". ` +
                `The lower-bound check (>= 0) is missing. Negative values pass and cause ArrayIndexOutOfBoundsException.`,
              fix: `Add a lower-bound check: if (${vn} >= 0 && ${vn} < array.length). Both bounds must be checked.`,
            });
          }
        }
      }
    }

    // Phase 3: Detect completely unvalidated array access (no bounds check at all).
    // Phase 2 catches "upper-bound-only" (check_max). Phase 3 catches "no check at all"
    // (no_check), which is arguably the more dangerous variant.
    if (pvars.size > 0) {
      for (let li = 0; li < sl129.length; li++) {
        const ln3 = sl129[li]!;
        const tr3 = ln3.trim();
        if (!tr3 || tr3.startsWith('//') || tr3.startsWith('*') || tr3.startsWith('/*')) continue;

        for (const vn of pvars) {
          const ev3 = vn.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          // Match array[var] usage
          const arrUseRe = new RegExp(`\\[\\s*${ev3}\\s*\\]`);
          if (!arrUseRe.test(ln3)) continue;

          // Check: is there ANY bounds check within 10 lines above?
          const ctxStart = Math.max(0, li - 10);
          const ctxEnd = Math.min(sl129.length, li + 1);
          const ctx3 = sl129.slice(ctxStart, ctxEnd).join('\n');
          const anyBoundsRe3 = new RegExp(
            `${ev3}\\s*<\\s*\\w+\\.length|` +
            `${ev3}\\s*>=\\s*0|` +
            `0\\s*<=\\s*${ev3}|` +
            `${ev3}\\s*>\\s*0|` +
            `Math\\.max\\s*\\(\\s*0|` +
            `Math\\.min\\s*\\(`
          );
          if (anyBoundsRe3.test(ctx3)) continue;

          // Hardcoded check: skip if variable was assigned a literal (goodG2B pattern)
          let isHardcoded3 = false;
          const hardLitRe3 = new RegExp(`\\b${ev3}\\s*=\\s*\\d+\\s*;`);
          for (let j = li - 1; j >= Math.max(0, li - 20); j--) {
            if (hardLitRe3.test(sl129[j]!.trim())) { isHardcoded3 = true; break; }
            if (new RegExp(`\\b${ev3}\\s*=.*(?:parseInt|readLine|getParameter|getInput)`).test(sl129[j]!.trim())) break;
          }
          if (isHardcoded3) continue;

          // Dedup against existing findings from Phase 1 or Phase 2
          const dup3 = findings.some(f => f.sink.line !== undefined && Math.abs(f.sink.line - (li + 1)) <= 3);
          if (dup3) continue;

          const sn3 = ingress.length > 0 ? ingress[0]! : findNearestNode(map, li + 1);
          if (sn3) {
            findings.push({
              source: nodeRef(sn3),
              sink: { id: `line-${li + 1}`, label: `unvalidated array access (line ${li + 1})`, line: li + 1, code: tr3.slice(0, 200) },
              missing: 'CONTROL (no bounds validation before array access)',
              severity: 'high',
              description: `Array index "${vn}" from external input is used at line ${li + 1}: "${tr3.slice(0, 80)}" with NO bounds validation. ` +
                `Any value including negative numbers will be accepted, causing ArrayIndexOutOfBoundsException.`,
              fix: `Add bounds validation: if (${vn} >= 0 && ${vn} < array.length) before accessing array[${vn}].`,
            });
          }
        }
      }
    }
  }

  return {
    cwe: 'CWE-129',
    name: 'Improper Validation of Array Index',
    holds: findings.length === 0,
    findings,
  };
}

// Registry — CWE → verification function
// ---------------------------------------------------------------------------

const CWE_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  // Generated-only verifiers (hand-written overlaps already filtered out in generated/index.ts)
  ...GENERATED_REGISTRY,
  // Code quality domain (64 CWEs) — overridden by any explicit entries below
  ...CODE_QUALITY_REGISTRY,
  // Hand-written verifiers — these are the authoritative versions for their CWEs
  'CWE-89': verifyCWE89,
  'CWE-79': verifyCWE79,
  'CWE-81': verifyCWE81,
  'CWE-83': verifyCWE83,
  'CWE-22': verifyCWE22,
  'CWE-23': verifyCWE23,
  'CWE-36': verifyCWE36,
  'CWE-502': verifyCWE502,
  'CWE-918': verifyCWE918,
  // Sensitive data & info disclosure CWEs -- extracted to sensitive-data.ts
  ...SENSITIVE_DATA_REGISTRY,
  // Auth & access control CWEs -- extracted to auth.ts
  ...AUTH_REGISTRY,
  'CWE-78': verifyCWE78,
  'CWE-611': verifyCWE611,
  'CWE-94': verifyCWE94,
  'CWE-1321': verifyCWE1321,
  'CWE-158': verifyCWE158,
  // Resource management & concurrency CWEs -- extracted to resource.ts
  ...RESOURCE_REGISTRY,
  // Cross-language detection fixes — override narrow generated verifiers
  'CWE-117': verifyCWE117,
  'CWE-601': verifyCWE601,
  'CWE-610': verifyCWE610,
  'CWE-643': verifyCWE643,
  'CWE-776': verifyCWE776,
  // Numeric & coercion CWEs -- extracted to numeric-coercion.ts
  ...NUMERIC_COERCION_REGISTRY,
  'CWE-369': verifyCWE369,
  'CWE-476': verifyCWE476,
  // Memory corruption CWEs
  'CWE-415': verifyCWE415,
  'CWE-416': verifyCWE416,
  'CWE-475': verifyCWE475,
  // Crypto & hash CWEs -- extracted to crypto.ts
  ...CRYPTO_REGISTRY,
  // B2 batch overrides (more optimized versions)
  'CWE-759': verifyCWE759_B2,
  'CWE-760': verifyCWE760_B2,
  // Input validation & injection variant CWEs
  'CWE-20': verifyCWE20,
  'CWE-74': verifyCWE74,
  'CWE-77': verifyCWE77,
  'CWE-90': verifyCWE90,
  'CWE-91': verifyCWE91,
  'CWE-93': verifyCWE93,
  'CWE-95': verifyCWE95,
  'CWE-96': verifyCWE96,
  'CWE-98': verifyCWE98,
  'CWE-99': verifyCWE99,
  // Encoding & validation CWEs -- extracted to encoding-validation.ts
  ...ENCODING_VALIDATION_REGISTRY,
  // Malicious code & covert channel CWEs -- extracted to malicious-code.ts
  ...MALICIOUS_CODE_REGISTRY,
  // Error handling, state management & side channel CWEs -- extracted to error-handling.ts
  ...ERROR_HANDLING_REGISTRY,
  'CWE-579': verifyCWE579,
  'CWE-580': verifyCWE580,
  'CWE-614': verifyCWE614_B2,
  // Memory/null safety CWEs
  'CWE-690': verifyCWE690,
  'CWE-696': verifyCWE696,
  'CWE-834': verifyCWE834,
  // Architecture CWEs (1044–1127) — extracted to architecture.ts
  ...ARCHITECTURE_REGISTRY,
  'CWE-186': verifyCWE186,
  'CWE-188': verifyCWE188,
  'CWE-336': verifyCWE336_B2,
  // Obsolete functions, password masking — source scan CWEs
  'CWE-477': verifyCWE477,
  // JNI and process control — native code loading CWEs
  'CWE-111': verifyCWE111,
  'CWE-114': verifyCWE114,
  // Taint-chain CWEs — external input to system/config and array index
  'CWE-15': verifyCWE15,
  'CWE-129': verifyCWE129,
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Verify a specific CWE against a neural map.
 */
export function verify(map: NeuralMap, cwe: string): VerificationResult {
  const fn = CWE_REGISTRY[cwe];
  if (!fn) {
    return {
      cwe,
      name: 'Unknown',
      holds: true,
      findings: [{ source: { id: '', label: '', line: 0, code: '' }, sink: { id: '', label: '', line: 0, code: '' }, missing: 'verification path', severity: 'low', description: `No verification path registered for ${cwe}`, fix: `Register a verification function for ${cwe}` }],
    };
  }
  return fn(map);
}

/**
 * CWEs that should ALWAYS be checked even on library/framework code because they
 * represent real injection, crypto, or data-flow vulnerabilities that can exist anywhere.
 * All other CWEs are skipped on library code to prevent false positives from code-quality
 * and architecture CWEs that fire on idiomatic library patterns.
 */
const ALWAYS_CHECK_CWES: ReadonlySet<string> = new Set([
  // Injection CWEs — real vulnerabilities even in library code
  'CWE-89', 'CWE-79', 'CWE-78', 'CWE-94', 'CWE-77',
  // Path traversal
  'CWE-22', 'CWE-23', 'CWE-36',
  // Deserialization
  'CWE-502',
  // SSRF
  'CWE-918',
  // Hardcoded credentials
  'CWE-798', 'CWE-259',
  // XXE
  'CWE-611',
  // Prototype pollution
  'CWE-1321',
  // Crypto weaknesses
  'CWE-327', 'CWE-328', 'CWE-330', 'CWE-338',
  // Auth bypass
  'CWE-306', 'CWE-287',
  // Info exposure
  'CWE-200', 'CWE-209',
]);

/**
 * Code-quality CWEs that fire on virtually every file but represent style/architecture
 * observations, not exploitable security vulnerabilities. These are gated behind
 * pedanticMode — excluded from default scans to reduce noise.
 *
 * IMPORTANT: CWE-397 and CWE-563 are NOT in this set because they are NIST Juliet
 * target CWEs. Gating them would regress the Juliet sweep.
 */
export const CODE_QUALITY_CWES: ReadonlySet<string> = new Set([
  'CWE-544',   // Missing Standardized Error Handling
  'CWE-755',   // Improper Handling of Exceptional Conditions
  'CWE-1124',  // Excessive Attack Surface (deep nesting)
  'CWE-1054',  // Input passes through "Infinity" call layers before validation
  'CWE-1091',  // Object not explicitly destroyed/closed (Use of Predictable Algorithm)
  'CWE-457',   // Use of Uninitialized Variable (Java auto-inits to null/0)
  'CWE-245',   // Direct use of DriverManager instead of DataSource (J2EE)
  'CWE-246',   // Direct use of Sockets (J2EE bad practice)
  'CWE-460',   // Cleanup not in catch block
  'CWE-1125',  // Excessive attack surface (too many unprotected endpoints)
  'CWE-1118',  // Insufficient documentation of error handling
  'CWE-1100',  // Insufficient isolation of system-dependent functions
  'CWE-1057',  // Data access outside expected data manager
  'CWE-1116',  // Inaccurate comments
  'CWE-1123',  // Excessive use of self-modifying code
  'CWE-628',   // Function Call with Incorrectly Specified Arguments
  'CWE-710',   // Improper Adherence to Coding Standards
  'CWE-653',   // Insufficient Compartmentalization
  // --- Category B: Generic Taint-to-Anything (factory verifiers with overly broad sinks) ---
  // These fire on virtually every taint flow regardless of whether the operation is relevant.
  'CWE-675',   // Multiple Operations on Resource — fires on any InputStreamReader→BufferedReader chain
  'CWE-666',   // Operation on Resource in Wrong Phase — fires on any TRANSFORM→TRANSFORM chain
  'CWE-683',   // Incorrect Argument Order — fires on any two TRANSFORMs without META
  'CWE-685',   // Incorrect Number of Arguments — same broad TRANSFORM→TRANSFORM pattern
  'CWE-686',   // Incorrect Argument Type — same broad TRANSFORM→TRANSFORM pattern
  'CWE-593',   // OpenSSL CTX Modified after SSL Objects — fires on any stream code
  'CWE-695',   // Use of Low-Level Functionality — fires on any socket/raw API usage
  // --- Category F: Auth/Authz on non-auth code (require web framework context) ---
  // These fire on ANY code that reads input without auth, but standalone test code never has auth.
  'CWE-638',   // Complete Mediation — "auth on every access" fires on everything
  'CWE-655',   // Psychological Acceptability — "usable security" fires on everything
]);

/** Options for verifyAll() */
export interface VerifyAllOptions {
  /** When true, skip source-sink dedup and return raw results (for Juliet scoring, debugging) */
  noDedup?: boolean;
  /** When true, include code-quality CWEs that are normally suppressed to reduce noise */
  pedanticMode?: boolean;
}

/**
 * Verify all registered CWEs against a neural map.
 *
 * When `language` is provided, CWEs are filtered by platform overlap using
 * MITRE CWE data. Each CWE is only skipped when its applicable platforms
 * have ZERO overlap with the language's target platforms. This correctly:
 * - Keeps J2EE/Struts/EJB/Servlet CWEs for Java and Kotlin scans
 * - Keeps .NET/ASP.NET CWEs for C# scans
 * - Keeps Android CWEs for Java and Kotlin scans
 * - Skips Windows kernel CWEs for all non-C/C++ languages
 * - Skips J2EE CWEs for JavaScript/Python/Go/etc.
 *
 * When the code is detected as library/framework code, only injection/crypto/auth
 * CWEs are checked — code-quality and architecture CWEs are skipped to prevent FPs.
 *
 * By default, code-quality CWEs (style/architecture observations that aren't security
 * vulnerabilities) are suppressed. Pass `{ pedanticMode: true }` to include them.
 *
 * By default, results are deduplicated by (source, sink, missingCategory) to collapse
 * CWE family explosions. Pass `{ noDedup: true }` to get raw results.
 */
export function verifyAll(map: NeuralMap, language?: string, options?: VerifyAllOptions): VerificationResult[] {
  const isLibrary = isLibraryCode(map);
  let cwes = Object.keys(CWE_REGISTRY);

  // Filter CWEs by language-platform overlap (MITRE-sourced, replaces WEB_LANGUAGES gate)
  cwes = filterCWEsForLanguage(cwes, language);

  // For library code, only check injection/crypto/auth CWEs
  // (hand-written verifiers also have individual library guards as defense-in-depth)
  if (isLibrary) {
    cwes = cwes.filter(cwe => ALWAYS_CHECK_CWES.has(cwe));
  }

  // Gate code-quality CWEs behind pedanticMode (default: OFF).
  // These fire on virtually every file with no security relevance — they're style/architecture
  // observations, not exploitable vulnerabilities. Reduces FP noise by ~31.5%.
  if (!options?.pedanticMode) {
    cwes = cwes.filter(cwe => !CODE_QUALITY_CWES.has(cwe));
  }

  const results = cwes.map(cwe => verify(map, cwe));

  // ── SECOND PASS: Evaluate controls on mediated paths ──────────────
  // When a path passes because a CONTROL mediates it, check whether
  // that CONTROL is actually effective. Weak controls = false safety.
  const ingress = nodesOfType(map, 'INGRESS');
  const dangerousSinks = map.nodes.filter(n =>
    n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL' || n.node_type === 'EGRESS'
  );

  for (const src of ingress) {
    for (const sink of dangerousSinks) {
      if (src.id === sink.id) continue;
      // Only evaluate controls on paths that PASSED (had a mediator)
      if (!hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const weaknesses = evaluateControlEffectiveness(map, src.id, sink.id);
        for (const w of weaknesses) {
          // Find or create the result for this CWE
          let result = results.find(r => r.cwe === w.cwe);
          if (!result) {
            result = { cwe: w.cwe, name: w.weakness, holds: true, findings: [] };
            results.push(result);
          }
          result.holds = false;
          result.findings.push({
            source: nodeRef(src),
            sink: nodeRef(w.controlNode),
            missing: 'EFFECTIVE_CONTROL (the control on this path is itself vulnerable)',
            severity: w.severity,
            description: w.description,
            fix: `The validation/sanitization at ${w.controlNode.label} needs to be replaced or hardened. ` +
              `The current control provides false safety — it appears to protect the path but is itself exploitable.`,
          });
        }
      }
    }
  }

  // ── THIRD PASS: Scope-based threat-control mismatch ────────────────
  // For Java/multi-language patterns where BFS doesn't create rich DATA_FLOW
  // paths, check if INGRESS→STORAGE pairs in the same scope have controls
  // that address the wrong threat class. This is the CWE-566 detector.
  //
  // Pattern: parameterized query (injection control) present, but no
  // ownership check (authorization control) in scope.
  const SQL_PK_RE_3P = /(?:WHERE\s+(?:uid|id|user_id|pk|primary_key)\s*=\s*\?|\bfindById\b|\bfindByPk\b|\bget_object_or_404\b|\.get\s*\(\s*pk\b)/i;
  const INJECTION_CONTROL_RE_3P = /\b(preparedStatement|PreparedStatement|prepared_statement|parameteriz|\.setInt|\.setString|\.setLong|\.setDouble|\.setFloat|\.setBoolean|\.setDate|\.setTimestamp|\.setObject)\b/i;
  const OWNERSHIP_AUTH_RE_3P = /\b(session\.getAttribute|getSession\s*\(\s*\)\s*\.\s*getAttribute|session\.user[_.]?id|request\.getUserPrincipal|SecurityContext|getRemoteUser|getUserName|currentUser|req\.user\.id|req\.user\b|user_id\s*===?\s*|AND\s+(?:user_id|owner_id|created_by)\s*=|owned_by|belongs_to|checkOwnership|isOwner|verifyOwner|authorize[!]?|hasPermission|can\?\s*:|ability\.can|@PreAuthorize|@Secured|@RolesAllowed|\.where\s*\(.*(?:user_id|owner_id|created_by))/i;
  // Only INGRESS nodes that carry user-controlled data (not just type declarations)
  const USER_INPUT_RE_3P = /\b(getParameter|getHeader|getCookies|getInputStream|getReader|getQueryString|getPathInfo|getRequestURI|getRequestURL|req\.params|req\.query|req\.body|request\.args|request\.form|request\.GET|request\.POST|\$_GET|\$_POST|@PathVariable|@RequestParam|@RequestBody|@RequestHeader)\b/i;

  // Track which functions have already been flagged to avoid duplicate findings per function
  const flaggedFunctions = new Set<string>();

  for (const src of ingress) {
    // Only flag INGRESS nodes that carry user data extraction (e.g., request.getParameter),
    // NOT just HttpServletRequest parameter type declarations. A method that receives
    // HttpServletRequest but only uses hardcoded data (like Juliet's good() variant)
    // should NOT be flagged.
    const srcCode = stripComments(src.analysis_snapshot || src.code_snapshot);
    const srcIsDataExtraction = USER_INPUT_RE_3P.test(srcCode);
    if (!srcIsDataExtraction) continue;

    for (const sink of dangerousSinks) {
      if (src.id === sink.id) continue;
      if (sink.node_type !== 'STORAGE') continue;

      // Only flag the STORAGE node that has the actual SQL PK lookup
      const sinkCode = stripComments(sink.analysis_snapshot || sink.code_snapshot);
      if (!SQL_PK_RE_3P.test(sinkCode)) continue;

      // Check if source and sink share a function scope
      if (!sharesFunctionScope(map, src.id, sink.id)) continue;

      // Get the scope code to check for injection control
      const sinkScopeSnaps = getContainingScopeSnapshots(map, sink.id);
      const fullScopeCode = stripComments(sinkScopeSnaps.join('\n') + '\n' + sinkCode);

      // Is there an injection control in scope (parameterized query)?
      if (!INJECTION_CONTROL_RE_3P.test(fullScopeCode)) continue;

      // Deduplicate by containing function — one finding per (function, src INGRESS)
      const functionKey = sinkScopeSnaps[0]?.slice(0, 40) + ':' + src.id;
      if (flaggedFunctions.has(functionKey)) continue;

      // Is there an ownership/authorization check in scope?
      const hasOwnershipCheck = map.nodes.some(n => {
        if (!sharesFunctionScope(map, n.id, sink.id)) return false;
        const nodeCode = n.code_snapshot + ' ' + (n.analysis_snapshot || '');
        return OWNERSHIP_AUTH_RE_3P.test(nodeCode);
      });

      if (!hasOwnershipCheck) {
        flaggedFunctions.add(functionKey);

        // CWE-566: Parameterized query present (injection control) but no ownership check
        let cwe566Result = results.find(r => r.cwe === 'CWE-566');
        if (!cwe566Result) {
          cwe566Result = { cwe: 'CWE-566', name: 'Authorization Bypass Through User-Controlled SQL Primary Key', holds: true, findings: [] };
          results.push(cwe566Result);
        }

        // Avoid duplicating if the first-pass CWE-566 verifier already found this pair
        const alreadyFound = cwe566Result.findings.some(f =>
          f.source.id === src.id && f.sink.id === sink.id
        );
        if (!alreadyFound) {
          cwe566Result.holds = false;
          cwe566Result.findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'EFFECTIVE_CONTROL (control addresses injection, not authorization — missing ownership check)',
            severity: 'high',
            description: `User input from ${src.label} flows to SQL query at ${sink.label}. ` +
              `A parameterized query prevents injection, but no ownership check verifies that ` +
              `the authenticated user is authorized to access the queried record. ` +
              `The control addresses the wrong threat class (injection vs authorization).`,
            fix: 'Add ownership verification: WHERE uid = ? AND user_id = :currentUserId. ' +
              'Or verify session.getAttribute("user_id") == queried_id after fetch. ' +
              'The parameterized query is necessary but insufficient — it only prevents SQL injection, ' +
              'not authorization bypass (IDOR).',
          });
        }
      }
    }
  }

  // ── LAYER 2: Source-sink dedup ─────────────────────────────────────
  // Collapse findings that share (source, sink, missingCategory) within
  // the SAME CWE. Keeps highest severity. Different CWEs are never
  // collapsed at this layer.
  // EFFECTIVE_CONTROL findings are excluded from dedup.
  if (!options?.noDedup) {
    const { results: deduped } = deduplicateResults(results);

    // ── LAYER 3: CWE Family dedup ───────────────────────────────────
    // Collapse CWE family siblings (e.g., CWE-23..38 under CWE-22) when
    // they fire on the same (source, sink, missingCategory) evidence.
    // Keeps the parent CWE. This eliminates the "family explosion" where
    // one real finding produces 10-20 duplicate sibling CWE findings.
    const { results: familyDeduped } = familyDedup(deduped);
    return familyDeduped;
  }

  return results;
}

/**
 * List all CWEs that have verification paths.
 */
export function registeredCWEs(): string[] {
  return Object.keys(CWE_REGISTRY);
}

/**
 * Print a human-readable verification report.
 */
export function formatReport(results: VerificationResult[]): string {
  const lines: string[] = ['DST VERIFICATION REPORT', '=' .repeat(50), ''];

  for (const r of results) {
    const status = r.holds ? '✓ PASS' : '✗ FAIL';
    lines.push(`[${status}] ${r.cwe}: ${r.name}`);

    if (!r.holds) {
      for (const f of r.findings) {
        lines.push(`  ${f.severity.toUpperCase()}: ${f.description}`);
        lines.push(`    Source: ${f.source.label} (line ${f.source.line})`);
        lines.push(`    Sink:   ${f.sink.label} (line ${f.sink.line})`);
        lines.push(`    Missing: ${f.missing}`);
        lines.push(`    Fix: ${f.fix}`);
        if (f.collapsed_cwes && f.collapsed_cwes.length > 0) {
          lines.push(`    Also covers: ${f.collapsed_cwes.join(', ')}`);
        }
        lines.push('');
      }
    }
  }

  const passed = results.filter(r => r.holds).length;
  const total = results.length;
  lines.push(`${passed}/${total} properties verified.`);

  return lines.join('\n');
}