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

import type { NeuralMap, NeuralMapNode, NodeType } from './types';
import { GENERATED_REGISTRY } from './generated/index.js';

// ---------------------------------------------------------------------------
// Verification result types
// ---------------------------------------------------------------------------

export interface VerificationResult {
  /** CWE identifier */
  cwe: string;
  /** Human-readable name */
  name: string;
  /** Whether the property holds */
  holds: boolean;
  /** Specific findings — empty if property holds */
  findings: Finding[];
}

export interface Finding {
  /** The source node (where tainted data originates) */
  source: NodeRef;
  /** The sink node (where tainted data arrives without control) */
  sink: NodeRef;
  /** What's missing between source and sink */
  missing: string;
  /** Severity */
  severity: 'critical' | 'high' | 'medium' | 'low';
  /** Plain-language description */
  description: string;
  /** Remediation guidance */
  fix: string;
}

export interface NodeRef {
  id: string;
  label: string;
  line: number;
  code: string;
}

// ---------------------------------------------------------------------------
// Graph traversal helpers
// ---------------------------------------------------------------------------

function nodeRef(node: NeuralMapNode): NodeRef {
  return {
    id: node.id,
    label: node.label,
    line: node.line_start,
    code: node.code_snapshot.slice(0, 200),
  };
}

/** Find all nodes of a given type */
function nodesOfType(map: NeuralMap, type: NodeType): NeuralMapNode[] {
  return map.nodes.filter(n => n.node_type === type);
}

/** Find all nodes with a specific subtype */
function nodesOfSubtype(map: NeuralMap, subtype: string): NeuralMapNode[] {
  return map.nodes.filter(n => n.node_subtype === subtype);
}

/** Find all nodes with a specific attack surface tag */
function nodesWithSurface(map: NeuralMap, surface: string): NeuralMapNode[] {
  return map.nodes.filter(n => n.attack_surface.includes(surface));
}

/** Check if tainted data flows from source to sink without passing through a CONTROL node */
function hasTaintedPathWithoutControl(
  map: NeuralMap,
  sourceId: string,
  sinkId: string,
): boolean {
  // BFS from source, following edges, tracking whether we pass through CONTROL
  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));
  const visited = new Set<string>();
  const queue: Array<{ nodeId: string; passedControl: boolean }> = [
    { nodeId: sourceId, passedControl: false },
  ];

  while (queue.length > 0) {
    const { nodeId, passedControl } = queue.shift()!;
    if (visited.has(nodeId)) continue;
    visited.add(nodeId);

    const node = nodeMap.get(nodeId);
    if (!node) continue;

    // Check if this node is CONTROL (validation/sanitization)
    const isControl = node.node_type === 'CONTROL';
    const controlNow = passedControl || isControl;

    // Reached the sink
    if (nodeId === sinkId) {
      // If we got here WITHOUT passing through CONTROL, the path is vulnerable
      return !controlNow;
    }

    // Follow edges
    for (const edge of node.edges) {
      if (!visited.has(edge.target)) {
        queue.push({ nodeId: edge.target, passedControl: controlNow });
      }
    }
  }

  // No path found — not vulnerable via this source→sink pair
  return false;
}

/** Check if any data_in on the sink has tainted=true from a source */
function sinkReceivesTaintedData(sink: NeuralMapNode): boolean {
  return sink.data_in.some(d => d.tainted);
}

/**
 * Check if tainted data flows from source to sink without passing through an AUTH node.
 * Same BFS as hasTaintedPathWithoutControl but gates on AUTH instead of CONTROL.
 */
function hasTaintedPathWithoutAuth(
  map: NeuralMap,
  sourceId: string,
  sinkId: string,
): boolean {
  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));
  const visited = new Set<string>();
  const queue: Array<{ nodeId: string; passedAuth: boolean }> = [
    { nodeId: sourceId, passedAuth: false },
  ];

  while (queue.length > 0) {
    const { nodeId, passedAuth } = queue.shift()!;
    if (visited.has(nodeId)) continue;
    visited.add(nodeId);

    const node = nodeMap.get(nodeId);
    if (!node) continue;

    const isAuth = node.node_type === 'AUTH';
    const authNow = passedAuth || isAuth;

    if (nodeId === sinkId) {
      return !authNow;
    }

    for (const edge of node.edges) {
      if (!visited.has(edge.target)) {
        queue.push({ nodeId: edge.target, passedAuth: authNow });
      }
    }
  }

  return false;
}

/**
 * Check if there is ANY path from source to sink without passing through a CONTROL node.
 * Unlike hasTaintedPathWithoutControl, this does not require taint — it checks structural flow.
 * Used for CWE-200 where the source is STORAGE (not user input).
 */
function hasPathWithoutControl(
  map: NeuralMap,
  sourceId: string,
  sinkId: string,
): boolean {
  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));
  const visited = new Set<string>();
  const queue: Array<{ nodeId: string; passedControl: boolean }> = [
    { nodeId: sourceId, passedControl: false },
  ];

  while (queue.length > 0) {
    const { nodeId, passedControl } = queue.shift()!;
    if (visited.has(nodeId)) continue;
    visited.add(nodeId);

    const node = nodeMap.get(nodeId);
    if (!node) continue;

    const isControl = node.node_type === 'CONTROL';
    const controlNow = passedControl || isControl;

    if (nodeId === sinkId) {
      return !controlNow;
    }

    for (const edge of node.edges) {
      if (!visited.has(edge.target)) {
        queue.push({ nodeId: edge.target, passedControl: controlNow });
      }
    }
  }

  return false;
}

/**
 * Find the containing function (STRUCTURAL node) for a given node by walking
 * CONTAINS edges backwards. Returns the STRUCTURAL parent's id, or null.
 */
function findContainingFunction(map: NeuralMap, nodeId: string): string | null {
  // Look for a STRUCTURAL node that has a CONTAINS edge pointing to this node
  for (const n of map.nodes) {
    if (n.node_type === 'STRUCTURAL') {
      for (const edge of n.edges) {
        if (edge.target === nodeId && edge.edge_type === 'CONTAINS') {
          return n.id;
        }
      }
    }
  }
  return null;
}

/**
 * Check if two nodes share a common function scope.
 * Uses two strategies:
 *   1. Direct CONTAINS edge matching (both contained by the same STRUCTURAL node)
 *   2. Line-range containment (both within the line range of the same function STRUCTURAL node)
 * Strategy 2 handles cases where destructured parameters create INGRESS nodes
 * that aren't properly linked via CONTAINS edges.
 */
function sharesFunctionScope(map: NeuralMap, nodeIdA: string, nodeIdB: string): boolean {
  const nodeMap = new Map(map.nodes.map(n => [n.id, n]));
  const nodeA = nodeMap.get(nodeIdA);
  const nodeB = nodeMap.get(nodeIdB);
  if (!nodeA || !nodeB) return false;

  // Strategy 1: Direct CONTAINS edge matching
  const getAncestors = (nodeId: string): Set<string> => {
    const ancestors = new Set<string>();
    for (const n of map.nodes) {
      if (n.node_type === 'STRUCTURAL') {
        for (const edge of n.edges) {
          if (edge.target === nodeId && edge.edge_type === 'CONTAINS') {
            ancestors.add(n.id);
          }
        }
      }
    }
    return ancestors;
  };

  const ancestorsA = getAncestors(nodeIdA);
  const ancestorsB = getAncestors(nodeIdB);
  for (const a of ancestorsA) {
    if (ancestorsB.has(a)) return true;
  }

  // Strategy 2: Line-range containment
  // Find STRUCTURAL/function nodes whose line range encompasses both nodes
  const funcNodes = map.nodes.filter(n =>
    n.node_type === 'STRUCTURAL' &&
    (n.node_subtype === 'function' || n.node_subtype === 'route_def' ||
     n.code_snapshot.match(/\bfunction\b|\b=>\b/i) !== null)
  );

  for (const func of funcNodes) {
    const funcStart = func.line_start;
    const funcEnd = func.line_end;

    // Both nodes must be within the function's line range
    if (nodeA.line_start >= funcStart && nodeA.line_start <= funcEnd &&
        nodeB.line_start >= funcStart && nodeB.line_start <= funcEnd) {
      return true;
    }
  }

  return false;
}

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
  const storage = map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('sql') || n.node_subtype.includes('query') ||
     n.attack_surface.includes('sql_sink') ||
     n.code_snapshot.match(/\b(query|exec|execute|prepare|raw)\s*\(/i) !== null)
  );

  for (const src of ingress) {
    for (const sink of storage) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        // Check if the sink uses parameterized queries
        const isParameterized = sink.code_snapshot.match(
          /\$\d|\?\s*[,)]|\bprepare\b|\bparameterized\b|\bplaceholder/i
        ) !== null;

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
     n.node_subtype.includes('render') || n.attack_surface.includes('html_output') ||
     n.code_snapshot.match(/\b(innerHTML|render|send|write|res\.send|\.body\s*\()\b/i) !== null)) ||
    // EXTERNAL nodes that produce HTML via template engines (render_template_string, Jinja2, etc.)
    (n.node_type === 'EXTERNAL' &&
    (n.node_subtype.includes('template_exec') ||
     n.code_snapshot.match(/\b(render_template_string|render_template|Template)\b/i) !== null))
  );

  for (const src of ingress) {
    for (const sink of egress) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const isEncoded = sink.code_snapshot.match(
          /\bescape\b|\bencode\b|\bsanitize\b|\bDOMPurify\b|\btextContent\b/i
        ) !== null;

        if (!isEncoded) {
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
      n.attack_surface.includes('file_access') ||
      n.code_snapshot.match(/\b(readFile|writeFile|createReadStream|open|unlink|readdir)\b/i) !== null)) ||
    // Python: open(filename) is classified as INGRESS/file_read, not STORAGE/file
    (n.node_type === 'INGRESS' && n.node_subtype === 'file_read') ||
    // Go: http.ServeFile serves file content from a user-controlled path
    (n.node_type === 'EGRESS' && n.node_subtype === 'file_serve')
  );

  for (const src of ingress) {
    for (const sink of fileOps) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const isValidated = sink.code_snapshot.match(
          /\bpath\.resolve\b|\bpath\.normalize\b|\bstartsWith\b|\b\.\.\/\b|\bsanitize.*path/i
        ) !== null;

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

  return {
    cwe: 'CWE-22',
    name: 'Path Traversal',
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
      n.code_snapshot.match(/\b(unserialize|pickle\.load|yaml\.load|eval|JSON\.parse)\b/i) !== null)) ||
    // Python: pickle.loads is classified as EXTERNAL/deserialize, not TRANSFORM
    (n.node_type === 'EXTERNAL' && n.node_subtype === 'deserialize') ||
    // Rust: serde_json::from_str etc. are classified as INGRESS/deserialize
    (n.node_type === 'INGRESS' && n.node_subtype === 'deserialize')
  );

  for (const src of ingress) {
    for (const sink of deserialize) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        // EXTERNAL/deserialize nodes are inherently dangerous (yaml.load, pickle.loads, etc.)
        // TRANSFORM/parse nodes need code_snapshot check to distinguish safe vs unsafe
        const isDangerous =
          (sink.node_type === 'EXTERNAL' && sink.node_subtype === 'deserialize') ||
          // Rust: serde_json::from_str/from_value/from_slice on untrusted INGRESS data
          (sink.node_type === 'INGRESS' && sink.node_subtype === 'deserialize') ||
          sink.code_snapshot.match(
            /\b(unserialize|pickle\.load|yaml\.load|yaml\.loadAll|eval|Function\s*\(|deserialize|serde_json::from_str|serde_json::from_value|serde_json::from_slice)\b/i
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
     n.code_snapshot.match(/\b(fetch|axios|request|http\.get|https\.get|got|requests\.get|requests\.post|requests\.put|requests\.delete|urllib\.request)\b/i) !== null)
  );

  for (const src of ingress) {
    for (const sink of external) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const isValidated = sink.code_snapshot.match(
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

  return {
    cwe: 'CWE-918',
    name: 'Server-Side Request Forgery (SSRF)',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-798: Hardcoded Credentials
 * Pattern: META missing — secrets embedded directly in source code
 * Property: No hardcoded passwords, API keys, or tokens in source code
 *
 * Unlike flow-based CWEs, this is a static scan: walk all nodes looking
 * for credential patterns in code_snapshot, flagging any node that lacks
 * a corresponding META(env_ref) node indicating the value comes from
 * an external secret store.
 */
function verifyCWE798(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Patterns that indicate hardcoded secrets
  const secretPatterns = [
    /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{4,}['"]/i,
    /(?:api[_-]?key|apikey)\s*[:=]\s*['"][^'"]{8,}['"]/i,
    /(?:secret|token)\s*[:=]\s*['"][^'"]{8,}['"]/i,
    /(?:access[_-]?key|auth[_-]?token)\s*[:=]\s*['"][^'"]{8,}['"]/i,
    /(?:private[_-]?key)\s*[:=]\s*['"][^'"]{8,}['"]/i,
    /(?:connection[_-]?string)\s*[:=]\s*['"][^'"]{8,}['"]/i,
    // Rust: const/static string declarations with credential-like names
    /(?:const|static)\s+(?:DATABASE_)?(?:PASSWORD|SECRET|API_KEY|TOKEN|AUTH_TOKEN|PRIVATE_KEY|ACCESS_KEY)\s*:\s*&?str\s*=\s*"[^"]{4,}"/i,
  ];

  // Check if there's a META node that marks this value as env-sourced
  const metaNodes = nodesOfType(map, 'META');
  const envRefs = new Set(
    metaNodes
      .filter(n => n.node_subtype.includes('env_ref') || n.node_subtype.includes('secret_ref') ||
        n.code_snapshot.match(/\bprocess\.env\b|\benv\(\b|\bvault\b|\bsecretManager/i) !== null)
      .flatMap(n => n.edges.map(e => e.target))
  );

  for (const node of map.nodes) {
    // Skip META nodes — except config_value nodes which may contain hardcoded creds
    if (node.node_type === 'META' && node.node_subtype !== 'config_value') continue;
    // Skip nodes that are known to source from env
    if (envRefs.has(node.id)) continue;

    for (const pattern of secretPatterns) {
      if (pattern.test(node.code_snapshot)) {
        findings.push({
          source: nodeRef(node),
          sink: nodeRef(node),
          missing: 'META (external secret reference — environment variable, vault, or secret manager)',
          severity: 'critical',
          description: `Hardcoded credential found in ${node.label}. ` +
            `Secrets in source code can be leaked via version control, logs, or build artifacts.`,
          fix: 'Move secrets to environment variables or a secret manager. ' +
            'Use process.env.SECRET_NAME or a vault client. ' +
            'Never commit secrets to source control.',
        });
        break; // One finding per node is enough
      }
    }
  }

  return {
    cwe: 'CWE-798',
    name: 'Hardcoded Credentials',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-306: Missing Authentication
 * Pattern: INGRESS → sensitive operation (STORAGE/EXTERNAL) without AUTH
 * Property: All sensitive operations are gated by authentication checks
 *
 * Similar to CONTROL-gating but checks specifically for AUTH nodes.
 */
function verifyCWE306(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const sensitive = map.nodes.filter(n =>
    (n.node_type === 'STORAGE' || n.node_type === 'EXTERNAL') &&
    (n.attack_surface.includes('sensitive') || n.attack_surface.includes('admin') ||
     n.attack_surface.includes('write') || n.attack_surface.includes('delete') ||
     n.node_subtype.includes('write') || n.node_subtype.includes('delete') ||
     n.node_subtype.includes('admin') || n.node_subtype.includes('update') ||
     n.code_snapshot.match(/\b(delete|remove|update|insert|drop|admin|modify|destroy)\b/i) !== null)
  );

  for (const src of ingress) {
    for (const sink of sensitive) {
      if (hasTaintedPathWithoutAuth(map, src.id, sink.id)) {
        findings.push({
          source: nodeRef(src),
          sink: nodeRef(sink),
          missing: 'AUTH (authentication check before sensitive operation)',
          severity: 'critical',
          description: `Request from ${src.label} reaches sensitive operation ${sink.label} without authentication. ` +
            `An unauthenticated attacker can perform privileged actions.`,
          fix: 'Add authentication middleware before sensitive routes. ' +
            'Use session tokens, JWTs, or API keys to verify identity. ' +
            'Example: app.delete("/users/:id", requireAuth, handler)',
        });
      }
    }
  }

  return {
    cwe: 'CWE-306',
    name: 'Missing Authentication',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-200: Information Exposure
 * Pattern: STORAGE → EGRESS without CONTROL (data filtering/redaction)
 * Property: Sensitive data from storage is filtered before being sent to clients
 */
function verifyCWE200(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const storage = map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.data_out.some(d => d.sensitivity !== 'NONE') ||
     n.attack_surface.includes('sensitive_data') ||
     n.code_snapshot.match(/\b(password|ssn|credit.?card|token|secret|private|hash)\b/i) !== null)
  );
  const egress = nodesOfType(map, 'EGRESS');

  for (const src of storage) {
    for (const sink of egress) {
      if (hasPathWithoutControl(map, src.id, sink.id)) {
        // Check if the egress node filters fields
        const isFiltered = sink.code_snapshot.match(
          /\bselect\b|\bpick\b|\bomit\b|\bfilter\b|\bredact\b|\bexclude\b|\bsanitize\b|\btoJSON\b|\b\.map\b/i
        ) !== null;

        if (!isFiltered) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (data filtering or field redaction)',
            severity: 'high',
            description: `Sensitive data from ${src.label} flows to ${sink.label} without filtering. ` +
              `Internal fields (passwords, tokens, PII) may be exposed to clients.`,
            fix: 'Explicitly select which fields to return (allowlist pattern). ' +
              'Use DTO/view models to strip sensitive fields before sending. ' +
              'Never send raw database records directly to clients.',
          });
        }
      }
    }
  }

  return {
    cwe: 'CWE-200',
    name: 'Information Exposure',
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
     n.code_snapshot.match(/\b(exec|execSync|spawn|system|child_process|popen|shell_exec)\b/i) !== null)
  );

  for (const src of ingress) {
    for (const sink of shellExec) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        // Check if the command uses safe patterns
        const isSafe = sink.code_snapshot.match(
          /\bexecFile\b|\bspawn\b.*\[|\bshellEscape\b|\bescapeShell\b|\bsanitize\b/i
        ) !== null;

        if (!isSafe) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
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
  const xmlParsers = map.nodes.filter(n =>
    (n.node_type === 'TRANSFORM' || n.node_type === 'EXTERNAL' || n.node_type === 'STORAGE') &&
    (n.node_subtype.includes('xml') || n.node_subtype.includes('xpath') ||
     n.attack_surface.includes('xml_parse') ||
     xmlParserPattern.test(n.code_snapshot))
  );

  // Dangerous XML parser configurations that ENABLE XXE
  // libxmljs: parseXmlString(data, {noent:true}) — noent:true substitutes entities (DANGEROUS)
  // xml2js: explicitCharkey enables character key processing (DANGEROUS with crafted XML)
  const dangerousXmlConfigPattern = /noent\s*:\s*true|explicitCharkey/i;

  for (const src of ingress) {
    for (const sink of xmlParsers) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        // Check if the parser is configured dangerously (explicit XXE-enabling config)
        const hasDangerousConfig = dangerousXmlConfigPattern.test(sink.code_snapshot);

        // Check if external entities are properly disabled
        const isSecure = !hasDangerousConfig && sink.code_snapshot.match(
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
      xmlParserPattern.test(n.code_snapshot) &&
      dangerousXmlConfigPattern.test(n.code_snapshot)
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
    vmExecPattern.test(n.code_snapshot)
  );

  for (const src of ingress) {
    for (const sink of codeExec) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        // "sandbox" and "safeEval" are NOT safe for vm.runInContext --
        // vm modules execute arbitrary code even inside sandbox contexts.
        // Only treat as safe if it's ast.literal_eval or JSON.parse (truly safe parsers).
        const isVmExec = /\bvm\.|runInContext|runInNewContext|runInThisContext|compileFunction\b/i.test(sink.code_snapshot);
        const isSafe = !isVmExec && sink.code_snapshot.match(
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
      /\bvm\.|runInContext|runInNewContext|runInThisContext\b/i.test(n.code_snapshot)
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
      /\bvm\.|runInContext|runInNewContext|runInThisContext\b/i.test(n.code_snapshot)
    );

    for (const vmNode of vmNodes) {
      // Find the containing function by line range
      const containingFunc = map.nodes.find(n =>
        n.node_type === 'STRUCTURAL' &&
        n.node_subtype === 'function' &&
        n.line_start <= vmNode.line_start &&
        n.line_end >= vmNode.line_start &&
        // Must be an Express-like handler (references body, params, query, req)
        /\b(body|params|query|req\b|Request)\b/i.test(n.code_snapshot)
      );

      if (containingFunc) {
        // Check if any sibling node in the same function references request data
        const requestDataPattern = /\bbody\.([\w]+)|\breq\.(body|params|query|headers)\b|\brequest\.(body|params|query)\b/i;
        const hasRequestData = map.nodes.some(n =>
          n.line_start >= containingFunc.line_start &&
          n.line_start <= containingFunc.line_end &&
          requestDataPattern.test(n.code_snapshot)
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
 * CWE-352: Cross-Site Request Forgery (CSRF)
 * Pattern: INGRESS → STORAGE(write) without CONTROL(csrf)
 * Property: All state-changing operations from user requests are protected by CSRF tokens
 */
function verifyCWE352(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const stateChanging = map.nodes.filter(n =>
    n.node_type === 'STORAGE' &&
    (n.node_subtype.includes('write') || n.node_subtype.includes('delete') ||
     n.node_subtype.includes('update') || n.node_subtype.includes('insert') ||
     n.code_snapshot.match(/\b(INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE)\b/i) !== null)
  );

  // CSRF-specific CONTROL check: look for CONTROL nodes with csrf-related labels
  function hasCsrfControl(map: NeuralMap, sourceId: string, sinkId: string): boolean {
    const nodeMap = new Map(map.nodes.map(n => [n.id, n]));
    const visited = new Set<string>();
    const queue: Array<{ nodeId: string; passedCsrf: boolean }> = [
      { nodeId: sourceId, passedCsrf: false },
    ];

    while (queue.length > 0) {
      const { nodeId, passedCsrf } = queue.shift()!;
      if (visited.has(nodeId)) continue;
      visited.add(nodeId);

      const node = nodeMap.get(nodeId);
      if (!node) continue;

      const isCsrf = node.node_type === 'CONTROL' &&
        (node.node_subtype.includes('csrf') || node.label.match(/csrf/i) !== null ||
         node.code_snapshot.match(/\bcsrf\b|\b_token\b|\bCSRFProtect\b|\bcsurf\b/i) !== null);
      const csrfNow = passedCsrf || isCsrf;

      if (nodeId === sinkId) {
        return csrfNow;
      }

      for (const edge of node.edges) {
        if (!visited.has(edge.target)) {
          queue.push({ nodeId: edge.target, passedCsrf: csrfNow });
        }
      }
    }

    return false;
  }

  for (const src of ingress) {
    // Only check ingress from HTTP POST/PUT/DELETE (state-changing methods)
    const isStateChangingIngress = src.code_snapshot.match(
      /\b(post|put|delete|patch)\b/i
    ) !== null || src.node_subtype.includes('http');

    if (!isStateChangingIngress) continue;

    for (const sink of stateChanging) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id) && !hasCsrfControl(map, src.id, sink.id)) {
        findings.push({
          source: nodeRef(src),
          sink: nodeRef(sink),
          missing: 'CONTROL (CSRF token validation)',
          severity: 'high',
          description: `State-changing request from ${src.label} modifies data at ${sink.label} without CSRF protection. ` +
            `An attacker can forge requests from a victim's browser to perform unauthorized actions.`,
          fix: 'Add CSRF token validation middleware. Use csurf (Express), CSRFProtect (Flask), ' +
            'or framework-provided CSRF protection. Ensure all state-changing endpoints verify the token.',
        });
      }
    }
  }

  return {
    cwe: 'CWE-352',
    name: 'Cross-Site Request Forgery (CSRF)',
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
  const massAssign = map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('mass_assignment') || n.node_subtype.includes('merge') ||
     n.node_subtype.includes('assign') ||
     n.code_snapshot.match(/\bObject\.assign\b|\b\.merge\b|\b\.extend\b|\b\.\.\.\s*req\b|\bdeepMerge\b|\bdefaultsDeep\b/i) !== null)
  );

  for (const src of ingress) {
    for (const sink of massAssign) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const isSafe = sink.code_snapshot.match(
          /\ballowlist\b|\bwhitelist\b|\bpick\b|\bsanitize\b|\bObject\.create\(null\)/i
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
    fileValidationPattern.test(n.code_snapshot) ||
    fileValidationFnPattern.test(n.code_snapshot)
  );

  // Find nodes that do null byte sanitization
  const sanitizeNodes = map.nodes.filter(n =>
    nullByteSanitizePattern.test(n.code_snapshot)
  );

  // File operation sinks
  const fileOps = map.nodes.filter(n =>
    (n.node_type === 'EGRESS' || n.node_type === 'INGRESS' || n.node_type === 'STORAGE') &&
    (n.node_subtype.includes('file') ||
     n.code_snapshot.match(/\b(sendFile|readFile|createReadStream|createWriteStream|writeFile|unlink|open|access|stat|path\.resolve)\s*\(/i) !== null)
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

/**
 * CWE-384: Session Fixation
 * Pattern: AUTH(login/authenticate) → STORAGE/EGRESS(session write/redirect) without
 *          TRANSFORM(session regeneration like req.session.regenerate)
 * When a user authenticates, the session ID should be regenerated to prevent
 * an attacker from fixing the session ID before authentication.
 */
function verifyCWE384(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Auth/login patterns - look for authentication actions
  const authNodes = map.nodes.filter(n =>
    (n.node_type === 'AUTH' ||
     // Also check STRUCTURAL nodes that define login/auth routes
     (n.node_type === 'STRUCTURAL' && n.node_subtype === 'route_def')) &&
    n.code_snapshot.match(/\b(login|authenticate|passport\.authenticate|sign\s*in|logIn|createSession|doLogin)\b/i) !== null
  );

  // Also check for direct passport strategy patterns
  const passportStrategies = map.nodes.filter(n =>
    n.code_snapshot.match(/\bpassport\.use\s*\(\s*['"]login['"]/i) !== null ||
    n.code_snapshot.match(/\bLocalStrategy\b/i) !== null ||
    n.code_snapshot.match(/\bdone\s*\(\s*null\s*,\s*user\b/i) !== null
  );

  // Session regeneration patterns
  const sessionRegenPattern = /\b(regenerate|session\.regenerate|req\.session\.regenerate|session\.destroy|rotateSession|newSession|req\.session\.destroy\s*\(\s*\)\s*.*session)/i;

  // Check if there are auth nodes but no session regeneration anywhere in the map
  const allAuthNodes = [...authNodes, ...passportStrategies];

  if (allAuthNodes.length > 0) {
    // Check if session regeneration exists anywhere in the graph
    const hasSessionRegen = map.nodes.some(n =>
      sessionRegenPattern.test(n.code_snapshot)
    );

    if (!hasSessionRegen) {
      // Authentication happens but no session regeneration found
      for (const authNode of allAuthNodes) {
        // Check if this auth node leads to a successful login (done(null, user) or res.redirect)
        const hasSuccessPath = authNode.code_snapshot.match(
          /\bdone\s*\(\s*null\s*,\s*user\b|\bres\.\s*(redirect|json|send)\b|\breq\.login\b|\breq\.logIn\b|\bpassport\.authenticate\b/i
        ) !== null;

        if (hasSuccessPath) {
          // Build a reasonable sink - find the closest session/redirect action
          const loginSuccess = map.nodes.find(n =>
            n.line_start >= authNode.line_start &&
            n.code_snapshot.match(/\bdone\s*\(\s*null\s*,\s*user\b|\bres\.\s*(redirect|json|send)\b/i) !== null
          ) ?? authNode;

          findings.push({
            source: nodeRef(authNode),
            sink: nodeRef(loginSuccess),
            missing: 'TRANSFORM (session ID regeneration after authentication)',
            severity: 'high',
            description: `Authentication at ${authNode.label} succeeds without regenerating the session ID. ` +
              `An attacker who knows or sets the session ID before login can hijack the authenticated session.`,
            fix: 'Call req.session.regenerate() after successful authentication. ' +
              'This creates a new session ID while preserving session data. ' +
              'Example: req.session.regenerate((err) => { req.session.userId = user.id; ... }). ' +
              'For Passport.js, add session regeneration in the login callback.',
          });
          break; // One finding per auth flow is sufficient
        }
      }
    }
  }

  return {
    cwe: 'CWE-384',
    name: 'Session Fixation',
    holds: findings.length === 0,
    findings,
  };
}

// ---------------------------------------------------------------------------
// RESOURCE CWE Verification Paths
// ---------------------------------------------------------------------------

/**
 * CWE-400: Uncontrolled Resource Consumption
 * Pattern: INGRESS → RESOURCE[any] without CONTROL[limit_check]
 * Property: All resource allocations driven by user input have bounded limits
 *
 * R1: Unbounded resource consumption from user input.
 * Detects when tainted data flows to a RESOURCE node without a CONTROL
 * (validation, size limit, rate limiter) in between.
 */
function verifyCWE400(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const resources = nodesOfType(map, 'RESOURCE');

  for (const src of ingress) {
    for (const sink of resources) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        // Check if the resource call has built-in bounds in code_snapshot
        const isBounded = sink.code_snapshot.match(
          /\bmax\b|\blimit\b|\bcap\b|\bMAX_|\bLIMIT_|\bmaxSize|\bmaxLength|\bslice\s*\(\s*\d|\bsubstring\s*\(\s*\d/i
        ) !== null;

        if (!isBounded) {
          const subtypeLabel = sink.node_subtype || 'unknown';
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (input size validation or resource limit)',
            severity: subtypeLabel === 'cpu' ? 'high' : 'medium',
            description: `User input from ${src.label} controls ${subtypeLabel} resource allocation at ${sink.label} without bounds. ` +
              `An attacker can exhaust server ${subtypeLabel} resources causing denial of service.`,
            fix: `Validate and limit user input before passing to resource allocation. ` +
              `Add size/count limits: check input length, cap allocation size, use timeouts. ` +
              (subtypeLabel === 'cpu'
                ? 'For regex: use a safe regex library (re2) or limit input length. For crypto: cap iteration counts.'
                : subtypeLabel === 'memory'
                ? 'Cap buffer sizes. Limit request body size. Stream large inputs instead of buffering.'
                : subtypeLabel === 'connections'
                ? 'Use connection pooling with max limits. Set request timeouts. Add rate limiting.'
                : subtypeLabel === 'file_descriptors'
                ? 'Limit concurrent file operations. Close files in finally blocks.'
                : 'Add appropriate resource limits and rate limiting.'),
          });
        }
      }
    }
  }

  // Secondary check: INGRESS → RESOURCE via shared function scope (for patterns where
  // taint flows through local variables without explicit DATA_FLOW edges)
  if (findings.length === 0 && ingress.length > 0 && resources.length > 0) {
    for (const res of resources) {
      for (const src of ingress) {
        if (sharesFunctionScope(map, src.id, res.id)) {
          // Check if there's a CONTROL node in the same scope
          const controlInScope = map.nodes.some(n =>
            n.node_type === 'CONTROL' && sharesFunctionScope(map, n.id, res.id)
          );
          if (!controlInScope) {
            const isBounded = res.code_snapshot.match(
              /\bmax\b|\blimit\b|\bcap\b|\bMAX_|\bLIMIT_/i
            ) !== null;
            if (!isBounded) {
              const subtypeLabel = res.node_subtype || 'unknown';
              findings.push({
                source: nodeRef(src),
                sink: nodeRef(res),
                missing: 'CONTROL (input size validation or resource limit)',
                severity: 'medium',
                description: `User input from ${src.label} is accessible in the same scope as ${subtypeLabel} resource allocation at ${res.label} without bounds checking.`,
                fix: 'Add input validation or resource limits between user input and resource allocation.',
              });
            }
          }
        }
      }
    }
  }

  return {
    cwe: 'CWE-400',
    name: 'Uncontrolled Resource Consumption',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-770: Allocation of Resources Without Limits or Throttling
 * Pattern: Multiple INGRESS paths → same RESOURCE without CONTROL[rate_limit]
 * Property: Resource-consuming endpoints have rate limiting
 *
 * R3: DoS via multiple unthrottled paths to the same resource.
 * Checks if RESOURCE nodes reachable from INGRESS have rate limiting applied.
 */
function verifyCWE770(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');
  const resources = nodesOfType(map, 'RESOURCE');

  // Check for rate limiting: CONTROL nodes with rate_limit or rate_limiter subtypes
  const hasRateLimiter = map.nodes.some(n =>
    n.node_type === 'CONTROL' &&
    (n.node_subtype.includes('rate_limit') || n.node_subtype.includes('throttle') ||
     n.code_snapshot.match(/\brate.?limit\b|\bthrottle\b|\brateLimit\b/i) !== null)
  );

  if (hasRateLimiter) {
    return {
      cwe: 'CWE-770',
      name: 'Allocation of Resources Without Limits or Throttling',
      holds: true,
      findings: [],
    };
  }

  // Count how many INGRESS paths reach each RESOURCE
  for (const res of resources) {
    const reachingIngress: NeuralMapNode[] = [];
    for (const src of ingress) {
      // Check if there's any path (tainted or not) from ingress to resource
      const nodeMap = new Map(map.nodes.map(n => [n.id, n]));
      const visited = new Set<string>();
      const queue = [src.id];
      let found = false;

      while (queue.length > 0 && !found) {
        const nodeId = queue.shift()!;
        if (visited.has(nodeId)) continue;
        visited.add(nodeId);

        if (nodeId === res.id) { found = true; break; }

        const node = nodeMap.get(nodeId);
        if (!node) continue;
        for (const edge of node.edges) {
          if (!visited.has(edge.target)) queue.push(edge.target);
        }
      }
      if (found) reachingIngress.push(src);
    }

    // Also check via function scope proximity
    if (reachingIngress.length === 0) {
      for (const src of ingress) {
        if (sharesFunctionScope(map, src.id, res.id)) {
          reachingIngress.push(src);
        }
      }
    }

    if (reachingIngress.length > 0) {
      const subtypeLabel = res.node_subtype || 'unknown';
      findings.push({
        source: nodeRef(reachingIngress[0]),
        sink: nodeRef(res),
        missing: 'CONTROL (rate limiting or request throttling)',
        severity: 'medium',
        description: `${reachingIngress.length} ingress path(s) reach ${subtypeLabel} resource at ${res.label} without rate limiting. ` +
          `An attacker can send many requests to exhaust the resource pool.`,
        fix: 'Add rate limiting middleware (e.g., express-rate-limit) to endpoints that consume shared resources. ' +
          'Set per-IP and global request limits. Use connection pool limits.',
      });
    }
  }

  return {
    cwe: 'CWE-770',
    name: 'Allocation of Resources Without Limits or Throttling',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-1333: Inefficient Regular Expression Complexity (ReDoS)
 * Pattern: INGRESS → RESOURCE[cpu] where code contains new RegExp(tainted)
 * Property: User input is never used to construct regular expressions without safe guards
 *
 * R4: ReDoS via user-controlled regex patterns.
 * Also detects regex constructed from user input even without explicit RESOURCE nodes,
 * by scanning code_snapshots for new RegExp(tainted) patterns.
 */
function verifyCWE1333(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];
  const ingress = nodesOfType(map, 'INGRESS');

  // Strategy 1: RESOURCE/cpu nodes with regex in code_snapshot
  const regexResources = map.nodes.filter(n =>
    n.node_type === 'RESOURCE' && n.node_subtype === 'cpu' &&
    /\bRegExp\b|\bregex\b|\bnew\s+RegExp\b/i.test(n.code_snapshot)
  );

  for (const src of ingress) {
    for (const sink of regexResources) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        findings.push({
          source: nodeRef(src),
          sink: nodeRef(sink),
          missing: 'CONTROL (regex input validation or safe regex library)',
          severity: 'high',
          description: `User input from ${src.label} is used to construct a regular expression at ${sink.label}. ` +
            `A crafted input like (a+)+$ can cause catastrophic backtracking (ReDoS), freezing the server.`,
          fix: 'Never pass user input directly to new RegExp(). Options: ' +
            '(1) Use a safe regex library like re2. ' +
            '(2) Escape user input with escapeRegExp() before constructing. ' +
            '(3) Set a timeout on regex execution. ' +
            '(4) Limit input length before regex construction.',
        });
      }
    }
  }

  // Strategy 2: Code-snapshot scan for regex construction patterns across all nodes
  // (catches cases where the mapper didn't create a RESOURCE node but regex is built from taint)
  if (findings.length === 0 && ingress.length > 0) {
    const regexNodes = map.nodes.filter(n =>
      n.node_type !== 'STRUCTURAL' && n.node_type !== 'META' &&
      /\bnew\s+RegExp\s*\(/.test(n.code_snapshot)
    );

    for (const regNode of regexNodes) {
      for (const src of ingress) {
        if (hasTaintedPathWithoutControl(map, src.id, regNode.id) ||
            sharesFunctionScope(map, src.id, regNode.id)) {
          const isEscaped = regNode.code_snapshot.match(
            /\bescapeRegExp\b|\bescape\b|\bsanitize\b|\bre2\b|\bsafe.*regex/i
          ) !== null;

          if (!isEscaped) {
            findings.push({
              source: nodeRef(src),
              sink: nodeRef(regNode),
              missing: 'CONTROL (regex input escaping or safe regex library)',
              severity: 'high',
              description: `User input from ${src.label} may reach regex construction at ${regNode.label}. ` +
                `Crafted patterns can cause catastrophic backtracking (ReDoS).`,
              fix: 'Escape user input before passing to new RegExp(), or use the re2 library for safe regex.',
            });
            break;
          }
        }
      }
    }
  }

  return {
    cwe: 'CWE-1333',
    name: 'Inefficient Regular Expression Complexity (ReDoS)',
    holds: findings.length === 0,
    findings,
  };
}

/**
 * CWE-404: Improper Resource Shutdown or Release
 * Pattern: RESOURCE[acquire] on error path without RESOURCE[release]
 * Property: All resource acquisitions have corresponding releases on all paths
 *
 * R2: Resource leak detection.
 * Checks if RESOURCE nodes (connections, file descriptors) are properly released
 * by looking for matching release patterns in the same function scope.
 */
function verifyCWE404(map: NeuralMap): VerificationResult {
  const findings: Finding[] = [];

  // Resource acquire patterns — node_subtype + code_snapshot checks
  const acquirePatterns = /\b(open|createReadStream|createWriteStream|getConnection|acquire|connect|createServer|createConnection)\b/i;
  const releasePatterns = /\b(close|end|release|destroy|releaseConnection|disconnect|shutdown|unref)\b/i;

  const resourceNodes = nodesOfType(map, 'RESOURCE');

  for (const res of resourceNodes) {
    // Only check acquirable resources (connections, file descriptors)
    if (res.node_subtype !== 'connections' && res.node_subtype !== 'file_descriptors') continue;

    // Check if this is an acquire operation
    if (!acquirePatterns.test(res.code_snapshot)) continue;

    // Find the containing function
    const containingFunc = findContainingFunction(map, res.id);
    if (!containingFunc) continue;

    // Look for a matching release in the same function
    const funcNode = map.nodes.find(n => n.id === containingFunc);
    if (!funcNode) continue;

    // Gather all nodes contained in the same function
    const containedNodeIds = new Set<string>();
    const queue = [containingFunc];
    while (queue.length > 0) {
      const id = queue.shift()!;
      const node = map.nodes.find(n => n.id === id);
      if (!node) continue;
      for (const edge of node.edges) {
        if (edge.edge_type === 'CONTAINS' && !containedNodeIds.has(edge.target)) {
          containedNodeIds.add(edge.target);
          queue.push(edge.target);
        }
      }
    }

    // Check if any contained node has a release pattern
    const hasRelease = map.nodes.some(n =>
      containedNodeIds.has(n.id) && releasePatterns.test(n.code_snapshot)
    );

    // Also check code_snapshot of the containing function itself for finally/release
    const funcHasRelease = releasePatterns.test(funcNode.code_snapshot) ||
      /\bfinally\b/.test(funcNode.code_snapshot);

    if (!hasRelease && !funcHasRelease) {
      findings.push({
        source: nodeRef(res),
        sink: nodeRef(res),
        missing: 'RESOURCE (release/close/end on all code paths including error paths)',
        severity: 'medium',
        description: `${res.node_subtype} resource acquired at ${res.label} may not be released on all code paths. ` +
          `This can lead to resource leaks (${res.node_subtype === 'connections' ? 'connection pool exhaustion' : 'file descriptor exhaustion'}).`,
        fix: `Ensure resources are released in a finally block or using a try-with-resources pattern. ` +
          `For connections: always call release() or end() in a finally block. ` +
          `For files: use fs.promises with try/finally, or streams that auto-close.`,
      });
    }
  }

  return {
    cwe: 'CWE-404',
    name: 'Improper Resource Shutdown or Release',
    holds: findings.length === 0,
    findings,
  };
}

// ---------------------------------------------------------------------------
// Platform-specific CWE filtering
// ---------------------------------------------------------------------------

/**
 * CWEs that only apply to specific platforms. When scanning web languages
 * (JavaScript, TypeScript, Python), these are skipped because their graph
 * patterns (e.g., INGRESS->TRANSFORM without AUTH) fire on generic web code
 * but the actual vulnerability class is OS/framework-specific.
 *
 * This eliminates the 15-20% false positive rate from platform-irrelevant CWEs.
 */
export const PLATFORM_SPECIFIC_CWES: ReadonlySet<string> = new Set([
  // --- Windows ---
  'CWE-422',  // Unprotected Windows Messaging Channel (Shatter)
  'CWE-782',  // Exposed IOCTL with Insufficient Access Control
  'CWE-781',  // Improper Address Validation in IOCTL with METHOD_NEITHER
  'CWE-40',   // Path Traversal: Windows UNC
  'CWE-39',   // Path Traversal: 'C:dirname'
  'CWE-58',   // Path Equivalence: Windows 8.3 Filename
  'CWE-64',   // Windows Shortcut Following (.LNK)
  'CWE-65',   // Windows Hard Link
  'CWE-67',   // Improper Handling of Windows Device Names
  'CWE-69',   // Improper Handling of Windows ::DATA Alternate Data Stream

  // --- Android ---
  'CWE-925',  // Improper Verification of Intent by Broadcast Receiver
  'CWE-926',  // Improper Export of Android Application Components

  // --- .NET / ASP.NET ---
  'CWE-11',   // ASP.NET Misconfiguration: Creating Debug Binary
  'CWE-12',   // ASP.NET Misconfiguration: Missing Custom Error Page
  'CWE-13',   // ASP.NET Misconfiguration: Password in Configuration File
  'CWE-520',  // .NET Misconfiguration: Use of Impersonation
  'CWE-554',  // ASP.NET Misconfiguration: Not Using Input Validation Framework
  'CWE-556',  // ASP.NET Misconfiguration: Use of Identity Impersonation

  // --- J2EE / Struts / EJB ---
  'CWE-5',    // J2EE Misconfiguration: Data Transmission Without Encryption
  'CWE-6',    // J2EE Misconfiguration: Insufficient Session-ID Length
  'CWE-7',    // J2EE Misconfiguration: Missing Custom Error Handling
  'CWE-8',    // J2EE Misconfiguration: Entity Bean Declared Remote
  'CWE-9',    // J2EE Misconfiguration: Weak Access Permissions for EJB Methods
  'CWE-102',  // Struts: Duplicate Validation Forms
  'CWE-103',  // Struts: Incomplete validate() Method Definition
  'CWE-104',  // Struts: Form Bean Does Not Extend Validation Class
  'CWE-105',  // Struts: Form Field Without Validator
  'CWE-106',  // Struts: Plug-in Framework Not In Use
  'CWE-107',  // Struts: Unused Validation Form
  'CWE-108',  // Struts: Unverified Action Form
  'CWE-109',  // Struts: Validator Turned Off
  'CWE-110',  // Struts: Validator Without Form Field
  'CWE-111',  // Direct Use of Unsafe JNI
  'CWE-245',  // J2EE Bad Practices: Direct Management of Connections
  'CWE-246',  // J2EE Bad Practices: Direct Use of Sockets
  'CWE-382',  // J2EE Bad Practices: Use of System.exit()
  'CWE-383',  // J2EE Bad Practices: Direct Use of Threads
  'CWE-555',  // J2EE Misconfiguration: Plaintext Password in Configuration File
  'CWE-574',  // EJB Bad Practices: Use of Synchronization Primitives
  'CWE-575',  // EJB Bad Practices: Use of AWT Swing
  'CWE-576',  // EJB Bad Practices: Use of Java I/O
  'CWE-577',  // EJB Bad Practices: Use of Sockets
  'CWE-578',  // EJB Bad Practices: Use of Class Loader
  'CWE-579',  // J2EE Bad Practices: Non-serializable Object Stored in Session
  'CWE-594',  // J2EE Framework: Saving Unserializable Objects to Disk
  'CWE-600',  // Uncaught Exception in Servlet
  'CWE-608',  // Struts: Non-private Field in ActionForm Class

  // --- ActiveX / COM ---
  'CWE-618',  // Exposed Unsafe ActiveX Method
  'CWE-623',  // Unsafe ActiveX Control Marked Safe For Scripting

  // --- Servlet ---
  'CWE-536',  // Exposure of Information Through Servlet Runtime Error Message
]);

/**
 * Languages where platform-specific CWEs should be suppressed.
 * These are web/scripting languages that cannot contain Windows kernel code,
 * Android broadcast receivers, J2EE beans, or ActiveX controls.
 */
const WEB_LANGUAGES: ReadonlySet<string> = new Set([
  'javascript', 'python',
]);

// ---------------------------------------------------------------------------
// Registry — CWE → verification function
// ---------------------------------------------------------------------------

const CWE_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  // Generated verifiers first — hand-written overrides below take precedence
  ...GENERATED_REGISTRY,
  // Hand-written verifiers override generated where both exist (e.g. CWE-798)
  'CWE-89': verifyCWE89,
  'CWE-79': verifyCWE79,
  'CWE-22': verifyCWE22,
  'CWE-502': verifyCWE502,
  'CWE-918': verifyCWE918,
  'CWE-798': verifyCWE798,
  'CWE-306': verifyCWE306,
  'CWE-200': verifyCWE200,
  'CWE-78': verifyCWE78,
  'CWE-611': verifyCWE611,
  'CWE-94': verifyCWE94,
  'CWE-352': verifyCWE352,
  'CWE-1321': verifyCWE1321,
  'CWE-158': verifyCWE158,
  'CWE-384': verifyCWE384,
  // RESOURCE CWEs — finite capacity exhaustion
  'CWE-400': verifyCWE400,
  'CWE-770': verifyCWE770,
  'CWE-1333': verifyCWE1333,
  'CWE-404': verifyCWE404,
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
 * Verify all registered CWEs against a neural map.
 *
 * When `language` is provided and is a web language (javascript, python),
 * platform-specific CWEs (Windows, Android, .NET, J2EE, ActiveX, etc.)
 * are automatically skipped to prevent false positives.
 */
export function verifyAll(map: NeuralMap, language?: string): VerificationResult[] {
  const skipPlatform = language != null && WEB_LANGUAGES.has(language);
  const cwes = Object.keys(CWE_REGISTRY);

  if (!skipPlatform) {
    return cwes.map(cwe => verify(map, cwe));
  }

  return cwes
    .filter(cwe => !PLATFORM_SPECIFIC_CWES.has(cwe))
    .map(cwe => verify(map, cwe));
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
        lines.push('');
      }
    }
  }

  const passed = results.filter(r => r.holds).length;
  const total = results.length;
  lines.push(`${passed}/${total} properties verified.`);

  return lines.join('\n');
}
