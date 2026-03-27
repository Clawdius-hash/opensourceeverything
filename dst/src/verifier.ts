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
    n.node_type === 'EGRESS' &&
    (n.node_subtype.includes('html') || n.node_subtype.includes('response') ||
     n.node_subtype.includes('render') || n.attack_surface.includes('html_output') ||
     n.code_snapshot.match(/\b(innerHTML|render|send|write|res\.send)\b/i) !== null)
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
    (n.node_type === 'INGRESS' && n.node_subtype === 'file_read')
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
    (n.node_type === 'EXTERNAL' && n.node_subtype === 'deserialize')
  );

  for (const src of ingress) {
    for (const sink of deserialize) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        // JSON.parse is generally safe, flag the dangerous ones
        const isDangerous = sink.code_snapshot.match(
          /\b(unserialize|pickle\.load|yaml\.load|eval|Function\s*\(|deserialize)\b/i
        ) !== null;

        if (isDangerous) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (safe deserialization with type constraints)',
            severity: 'critical',
            description: `User input from ${src.label} is deserialized at ${sink.label} using an unsafe method. ` +
              `This can lead to arbitrary code execution.`,
            fix: 'Use safe parsers: JSON.parse for JSON, yaml.safe_load for YAML. ' +
              'Never use eval, unserialize, or pickle.load on untrusted data. ' +
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
    // Skip META nodes themselves
    if (node.node_type === 'META') continue;
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
  const xmlParsers = map.nodes.filter(n =>
    n.node_type === 'TRANSFORM' &&
    (n.node_subtype.includes('xml') || n.node_subtype.includes('xpath') ||
     n.attack_surface.includes('xml_parse') ||
     n.code_snapshot.match(/\b(parseXML|DOMParser|SAXParser|xml2js|libxml|etree\.parse|etree\.fromstring|xml\.sax|minidom\.parseString|XmlReader|ElementTree\.parse|lxml\.etree)\b/i) !== null)
  );

  for (const src of ingress) {
    for (const sink of xmlParsers) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        // Check if external entities are disabled
        const isSecure = sink.code_snapshot.match(
          /\bnoent\b|\bdisable.*entity\b|\bresolveEntities\s*:\s*false\b|\bXMLReader.*FEATURE.*external.*false\b|\bdefusedxml\b|\bsafe.*parse/i
        ) !== null;

        if (!isSecure) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (XML parser security configuration — disable external entities)',
            severity: 'high',
            description: `User-supplied XML from ${src.label} is parsed at ${sink.label} without disabling external entities. ` +
              `An attacker can read local files, perform SSRF, or cause denial of service via entity expansion.`,
            fix: 'Disable external entity processing in the XML parser configuration. ' +
              'Use defusedxml (Python), set resolveEntities: false, or use noent: false. ' +
              'Consider using JSON instead of XML where possible.',
          });
        }
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
  const codeExec = map.nodes.filter(n =>
    n.node_type === 'EXTERNAL' &&
    (n.node_subtype.includes('system_exec') || n.node_subtype.includes('exec') ||
     n.node_subtype.includes('eval')) &&
    n.code_snapshot.match(/\b(eval|exec|compile|Function\s*\(|execScript|setInterval|setTimeout)\b/i) !== null
  );

  for (const src of ingress) {
    for (const sink of codeExec) {
      if (hasTaintedPathWithoutControl(map, src.id, sink.id)) {
        const isSafe = sink.code_snapshot.match(
          /\bsandbox\b|\bsafe.*eval\b|\bast\.literal_eval\b|\bJSON\.parse\b/i
        ) !== null;

        if (!isSafe) {
          findings.push({
            source: nodeRef(src),
            sink: nodeRef(sink),
            missing: 'CONTROL (input validation or sandboxed evaluation)',
            severity: 'critical',
            description: `User input from ${src.label} flows to code evaluation at ${sink.label} without sanitization. ` +
              `An attacker can execute arbitrary code on the server.`,
            fix: 'Never pass user input to eval(), exec(), or Function(). ' +
              'Use ast.literal_eval() for Python or JSON.parse() for JSON data. ' +
              'If dynamic evaluation is required, use a sandboxed environment with strict allowlists.',
          });
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

// ---------------------------------------------------------------------------
// Registry — CWE → verification function
// ---------------------------------------------------------------------------

const CWE_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
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
 */
export function verifyAll(map: NeuralMap): VerificationResult[] {
  return Object.keys(CWE_REGISTRY).map(cwe => verify(map, cwe));
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
