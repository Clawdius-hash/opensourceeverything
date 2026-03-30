/**
 * JavaProfile — the fifth LanguageProfile implementation.
 *
 * Every piece of Java-specific logic lives here: AST node type names (from
 * tree-sitter-java grammar), field access patterns, scope rules, callee
 * resolution via the Java phoneme dictionary, taint extraction, and node
 * classification.
 *
 * Key differences from JavaScript:
 *   - `method_declaration` not `function_declaration` — Java has no top-level functions
 *   - `method_invocation` not `call_expression` (fields: `object`, `name`, `arguments`)
 *   - `field_access` not `member_expression` (fields: `object`, `field`)
 *   - `local_variable_declaration` not `lexical_declaration`
 *   - `class_declaration` creates class scope — everything is inside a class
 *   - `constructor_declaration` for constructors
 *   - `lambda_expression` for Java 8+ lambdas
 *   - `enhanced_for_statement` (for-each) + `for_statement`
 *   - `try_with_resources_statement` for auto-closeable resources
 *   - `annotation` and `marker_annotation` carry semantic meaning
 *   - `synchronized_statement` for thread-safe blocks
 *   - `throw_statement` for exception flow
 *   - `record_declaration` for Java 14+ records
 *   - `interface_declaration` for interfaces
 *   - `enum_declaration` for enums
 *   - `import_declaration` not `import_statement`
 *   - `program` is the root node
 *
 * tree-sitter-java AST reference: https://github.com/tree-sitter/tree-sitter-java
 */

import type { Node as SyntaxNode } from 'web-tree-sitter';
import type {
  LanguageProfile,
  MapperContextLike,
  TaintSourceResult,
  ResolvedCalleeResult,
  ResolvedPropertyResult,
  StructuralAnalysisResult,
} from '../languageProfile.js';
import type { ScopeType, VariableInfo } from '../mapper.js';
import type { CalleePattern } from '../calleePatterns.js';
import { createNode } from '../types.js';
import { lookupCallee as _lookupJavaCallee } from '../languages/java.js';

// ---------------------------------------------------------------------------
// Anti-evasion: constant folding for Java
// Attackers split dangerous strings across concatenation, StringBuilder,
// new String(byte[]), Character.toString, String.format to dodge static analysis.
// We fold them back.
// ---------------------------------------------------------------------------

function resolveJavaEscapes(s: string): string {
  return s
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\n/g, '\n').replace(/\\r/g, '\r').replace(/\\t/g, '\t')
    .replace(/\\\\/g, '\\');
}

function tryFoldConstant(n: SyntaxNode): string | null {
  // String literals: "eval" → eval
  if (n.type === 'string_literal') {
    const raw = n.text.replace(/^"|"$/g, '');
    return resolveJavaEscapes(raw);
  }
  // Character literals: 'e' → e
  if (n.type === 'character_literal') {
    const raw = n.text.replace(/^'|'$/g, '');
    return resolveJavaEscapes(raw);
  }
  // Numeric literals (for byte array / charcode patterns)
  if (n.type === 'decimal_integer_literal' || n.type === 'integer_literal') {
    return n.text;
  }
  // Hex integer literal
  if (n.type === 'hex_integer_literal') {
    return String(parseInt(n.text, 16));
  }
  // Binary expression: "ev" + "al" → "eval"
  if (n.type === 'binary_expression') {
    const op = n.childForFieldName('operator')?.text;
    if (op === '+') {
      const left = n.childForFieldName('left');
      const right = n.childForFieldName('right');
      if (left && right) {
        const lv = tryFoldConstant(left);
        const rv = tryFoldConstant(right);
        if (lv !== null && rv !== null) return lv + rv;
      }
    }
  }
  // Parenthesized: ("ev" + "al") → "eval"
  if (n.type === 'parenthesized_expression') {
    const inner = n.namedChild(0);
    return inner ? tryFoldConstant(inner) : null;
  }
  // Ternary constant folding: cond ? "a" : "a" → "a"
  if (n.type === 'ternary_expression') {
    const consequence = n.childForFieldName('consequence');
    const alternative = n.childForFieldName('alternative');
    if (consequence && alternative) {
      const cv = tryFoldConstant(consequence);
      const av = tryFoldConstant(alternative);
      if (cv !== null && av !== null && cv === av) return cv;
    }
  }
  // Cast expression: (char)101 → skip the cast and fold inner
  if (n.type === 'cast_expression') {
    const value = n.childForFieldName('value');
    return value ? tryFoldConstant(value) : null;
  }
  // ── METHOD INVOCATIONS that produce constant strings ──
  if (n.type === 'method_invocation') {
    const obj = n.childForFieldName('object');
    const name = n.childForFieldName('name');
    const args = n.childForFieldName('arguments');
    if (obj && name && args) {
      // StringBuilder: new StringBuilder().append("ev").append("al").toString()
      // Detected when .toString() is called on a chain of .append() calls
      if (name.text === 'toString' && obj.type === 'method_invocation') {
        const folded = tryFoldStringBuilderChain(obj);
        if (folded !== null) return folded;
      }
      // String.format("%s%s", "ev", "al") → "eval"
      if (name.text === 'format' && obj.text === 'String') {
        return tryFoldStringFormat(args);
      }
      // String.valueOf(char) / String.valueOf(int)
      if (name.text === 'valueOf' && obj.text === 'String') {
        const firstArg = args.namedChild(0);
        if (firstArg) {
          const v = tryFoldConstant(firstArg);
          if (v !== null) {
            // If it's a number, treat as charcode
            const num = parseInt(v, 10);
            if (!isNaN(num) && num >= 0 && num < 0x110000) {
              return String.fromCharCode(num);
            }
            return v;
          }
        }
      }
      // Character.toString((char)101)
      if (name.text === 'toString' && obj.text === 'Character') {
        const firstArg = args.namedChild(0);
        if (firstArg) {
          const v = tryFoldConstant(firstArg);
          if (v !== null) {
            const num = parseInt(v, 10);
            if (!isNaN(num) && num >= 0 && num < 0x110000) {
              return String.fromCharCode(num);
            }
            return v;
          }
        }
      }
    }
  }
  // new String(new byte[]{101,118,97,108}) → "eval"
  if (n.type === 'object_creation_expression') {
    const typeNode = n.childForFieldName('type');
    const args = n.childForFieldName('arguments');
    if (typeNode?.text === 'String' && args) {
      const firstArg = args.namedChild(0);
      if (firstArg?.type === 'array_creation_expression') {
        const init = firstArg.childForFieldName('value');
        if (init?.type === 'array_initializer') {
          return tryFoldByteArray(init);
        }
      }
      // new String(new byte[]{...}) where the array is an array_initializer directly
      if (firstArg?.type === 'object_creation_expression') {
        // nested: new String(new byte[]{101,...})
        for (let i = 0; i < firstArg.namedChildCount; i++) {
          const child = firstArg.namedChild(i);
          if (child?.type === 'array_initializer') {
            return tryFoldByteArray(child);
          }
        }
      }
    }
  }
  return null;
}

/** Fold StringBuilder chain: .append("ev").append("al") → "eval" */
function tryFoldStringBuilderChain(node: SyntaxNode): string | null {
  // Walk the chain from right to left collecting append arguments
  const parts: string[] = [];
  let current: SyntaxNode | null = node;

  while (current?.type === 'method_invocation') {
    const name = current.childForFieldName('name');
    const args = current.childForFieldName('arguments');
    const obj = current.childForFieldName('object');

    if (name?.text === 'append' && args) {
      const firstArg = args.namedChild(0);
      if (firstArg) {
        const v = tryFoldConstant(firstArg);
        if (v !== null) {
          parts.unshift(v);
        } else {
          return null; // non-constant arg, bail
        }
      }
      current = obj ?? null;
    } else {
      break;
    }
  }

  // Current should now be the StringBuilder constructor (new StringBuilder())
  if (current?.type === 'object_creation_expression') {
    const typeNode = current.childForFieldName('type');
    if (typeNode?.text === 'StringBuilder' || typeNode?.text === 'StringBuffer') {
      // Check if constructor has an initial string argument
      const ctorArgs = current.childForFieldName('arguments');
      if (ctorArgs && ctorArgs.namedChildCount > 0) {
        const initArg = ctorArgs.namedChild(0);
        if (initArg) {
          const initVal = tryFoldConstant(initArg);
          if (initVal !== null) parts.unshift(initVal);
          else return null;
        }
      }
      return parts.join('');
    }
  }
  return null;
}

/** Fold String.format("%s%s", "ev", "al") → "eval" */
function tryFoldStringFormat(args: SyntaxNode): string | null {
  if (args.namedChildCount < 2) return null;
  const fmtArg = args.namedChild(0);
  if (!fmtArg) return null;
  const fmt = tryFoldConstant(fmtArg);
  if (fmt === null) return null;

  // Only handle simple %s patterns
  const placeholders = fmt.match(/%s/g);
  if (!placeholders) return null;
  if (placeholders.length !== args.namedChildCount - 1) return null;

  const values: string[] = [];
  for (let i = 1; i < args.namedChildCount; i++) {
    const arg = args.namedChild(i);
    if (!arg) return null;
    const v = tryFoldConstant(arg);
    if (v === null) return null;
    values.push(v);
  }

  let result = fmt;
  for (const v of values) {
    result = result.replace('%s', v);
  }
  return result;
}

/** Fold byte array initializer: {101, 118, 97, 108} → "eval" */
function tryFoldByteArray(init: SyntaxNode): string | null {
  const codes: number[] = [];
  for (let i = 0; i < init.namedChildCount; i++) {
    const el = init.namedChild(i);
    if (!el) return null;
    const v = tryFoldConstant(el);
    if (v === null) return null;
    const num = parseInt(v, 10);
    if (isNaN(num)) return null;
    codes.push(num);
  }
  if (codes.length === 0) return null;
  return String.fromCharCode(...codes);
}

// ---------------------------------------------------------------------------
// AST Node Type Sets (tree-sitter-java)
// ---------------------------------------------------------------------------

const FUNCTION_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'method_declaration',
  'constructor_declaration',
  'lambda_expression',
]);

const BLOCK_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'for_statement',
  'enhanced_for_statement',
  'while_statement',
  'do_statement',
  'if_statement',
  'switch_expression',
  'switch_block',
  'try_statement',
  'try_with_resources_statement',
  'catch_clause',
  'finally_clause',
  'synchronized_statement',
  'block',
]);

const CLASS_SCOPE_TYPES: ReadonlySet<string> = new Set([
  'class_declaration',
  'interface_declaration',
  'enum_declaration',
  'record_declaration',
]);

const VARIABLE_DECLARATION_TYPES: ReadonlySet<string> = new Set([
  'local_variable_declaration',
  'field_declaration',
]);

const FUNCTION_DECLARATION_TYPES: ReadonlySet<string> = new Set([
  'method_declaration',
  'constructor_declaration',
]);

// Tainted paths for Java Servlet/Spring request objects
const TAINTED_PATHS: ReadonlySet<string> = new Set([
  // HttpServletRequest
  'request.getParameter', 'request.getParameterMap', 'request.getParameterValues',
  'request.getHeader', 'request.getHeaders', 'request.getCookies',
  'request.getInputStream', 'request.getReader', 'request.getRequestURI',
  'request.getRequestURL', 'request.getQueryString', 'request.getPathInfo',
  'request.getRemoteAddr', 'request.getContentType', 'request.getMethod',
  'request.getSession', 'request.getAttribute', 'request.getPart',
  'request.getParts',
  // Short aliases (req, httpRequest)
  'req.getParameter', 'req.getHeader', 'req.getCookies',
  'req.getInputStream', 'req.getReader', 'req.getQueryString',
  'req.getRequestURI', 'req.getRequestURL', 'req.getPathInfo',
  'req.getRemoteAddr', 'req.getAttribute', 'req.getPart',
  'req.getParameterMap', 'req.getParameterValues', 'req.getHeaders',
  'httpRequest.getParameter', 'httpRequest.getHeader',
  'httpRequest.getCookies', 'httpRequest.getQueryString',
  'httpRequest.getInputStream', 'httpRequest.getRequestURI',
  'servletRequest.getParameter', 'servletRequest.getHeader',
  'servletRequest.getQueryString',
  // Scanner
  'scanner.nextLine', 'scanner.next', 'scanner.nextInt',
  // STEP 3: Environment variables treated as tainted (attacker-controlled in containers)
  'System.getenv', 'System.getProperty',
  // Network socket reads (Juliet connect_tcp pattern)
  'socket.getInputStream', 'Socket.getInputStream',
  'readerBuffered.readLine', 'readerInputStream.read',
]);

// Spring annotation names that mark parameters as tainted INGRESS sources
const SPRING_TAINT_ANNOTATIONS: ReadonlySet<string> = new Set([
  'RequestBody', 'PathVariable', 'RequestParam',
  'RequestHeader', 'CookieValue', 'ModelAttribute',
  'RequestPart',
]);

// Spring routing annotations (for structural analysis)
const SPRING_ROUTE_ANNOTATIONS: ReadonlySet<string> = new Set([
  'RequestMapping', 'GetMapping', 'PostMapping',
  'PutMapping', 'DeleteMapping', 'PatchMapping',
]);

// Spring security annotations
const SPRING_SECURITY_ANNOTATIONS: ReadonlySet<string> = new Set([
  'PreAuthorize', 'Secured', 'RolesAllowed',
]);

// Validation annotations
const VALIDATION_ANNOTATIONS: ReadonlySet<string> = new Set([
  'Valid', 'NotNull', 'NotBlank', 'NotEmpty',
  'Size', 'Min', 'Max', 'Pattern', 'Email',
  'Positive', 'PositiveOrZero', 'Negative', 'NegativeOrZero',
  'Past', 'Future', 'Digits',
]);

// Conventional request parameter names in Java handlers
const JAVA_REQUEST_PARAM_NAMES: ReadonlySet<string> = new Set([
  'request', 'req', 'httpRequest', 'servletRequest',
]);

// Response parameter names
const JAVA_RESPONSE_PARAM_NAMES: ReadonlySet<string> = new Set([
  'response', 'resp', 'httpResponse', 'servletResponse',
]);

// Request type names that indicate tainted params
const JAVA_HTTP_REQUEST_TYPES: ReadonlySet<string> = new Set([
  'HttpServletRequest', 'ServletRequest',
  'WebRequest', 'NativeWebRequest',
  'ServerHttpRequest', 'HttpRequest',
]);

// ---------------------------------------------------------------------------
// Helper: extract callee chain from Java AST nodes
// ---------------------------------------------------------------------------

/**
 * Extract the callee chain from a Java expression.
 * Handles:
 *   - identifier: `foo` -> ['foo']
 *   - field_access: `request.getParameter` -> ['request', 'getParameter']
 *   - method_invocation chains: `obj.method().chain()` -> resolves terminal
 *   - scoped_identifier: `System.out` -> ['System', 'out']
 */
function extractCalleeChain(node: SyntaxNode): string[] {
  if (node.type === 'identifier') {
    return [node.text];
  }

  if (node.type === 'field_access') {
    const obj = node.childForFieldName('object');
    const field = node.childForFieldName('field');
    if (obj && field) {
      const chain = extractCalleeChain(obj);
      chain.push(field.text);
      return chain;
    }
  }

  if (node.type === 'scoped_identifier') {
    // e.g., System.out, Runtime.getRuntime
    const parts: string[] = [];
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child && child.type !== '.') {
        if (child.type === 'scoped_identifier') {
          parts.push(...extractCalleeChain(child));
        } else {
          parts.push(child.text);
        }
      }
    }
    return parts;
  }

  // method_invocation: obj.method(args) — extract object chain + method name
  if (node.type === 'method_invocation') {
    const obj = node.childForFieldName('object');
    const name = node.childForFieldName('name');
    if (obj && name) {
      const chain = extractCalleeChain(obj);
      chain.push(name.text);
      return chain;
    }
    if (name) {
      return [name.text];
    }
  }

  return [node.text.slice(0, 50)];
}

// ---------------------------------------------------------------------------
// STEP 1: Servlet taint method names — recognised regardless of receiver variable name.
// These are unmistakably HttpServletRequest API methods. If lookup by full chain
// fails AND the method name is in this set, we classify as INGRESS/http_request
// with tainted=true. This handles any alias: req, request, httpReq, etc.
// ---------------------------------------------------------------------------
const SERVLET_TAINT_METHODS: ReadonlySet<string> = new Set([
  'getParameter', 'getParameterMap', 'getParameterValues',
  'getHeader', 'getHeaders', 'getCookies',
  'getInputStream', 'getReader', 'getRequestURI',
  'getRequestURL', 'getQueryString', 'getPathInfo',
  'getRemoteAddr', 'getAttribute', 'getPart', 'getParts',
]);

// ---------------------------------------------------------------------------
// Helper: resolve callee from a method_invocation or object_creation_expression
// ---------------------------------------------------------------------------

function resolveCallee(node: SyntaxNode): ResolvedCalleeResult | null {
  // method_invocation: obj.method(args) or method(args)
  if (node.type === 'method_invocation') {
    const obj = node.childForFieldName('object');
    const name = node.childForFieldName('name');

    if (obj && name) {
      const chain = extractCalleeChain(obj);
      chain.push(name.text);
      const pattern = _lookupJavaCallee(chain);
      if (pattern) {
        return {
          nodeType: pattern.nodeType,
          subtype: pattern.subtype,
          tainted: pattern.tainted,
          chain,
        };
      }
      // STEP 1 fallback: if method name alone is a known servlet taint method,
      // treat as INGRESS/http_request regardless of receiver variable name.
      if (chain.length === 2 && SERVLET_TAINT_METHODS.has(chain[1])) {
        return {
          nodeType: 'INGRESS',
          subtype: 'http_request',
          tainted: true,
          chain,
        };
      }
    } else if (name) {
      // Bare method call — check direct call patterns
      const chain = [name.text];
      const pattern = _lookupJavaCallee(chain);
      if (pattern) {
        return {
          nodeType: pattern.nodeType,
          subtype: pattern.subtype,
          tainted: pattern.tainted,
          chain,
        };
      }
    }

    // ── Anti-evasion: Class.forName with constant-folded argument ──
    // Class.forName("ev" + "al") or Class.forName(constructed) → reflection
    if (obj && name?.text === 'forName' && obj.text === 'Class') {
      const args = node.childForFieldName('arguments');
      const firstArg = args?.namedChild(0);
      if (firstArg) {
        const folded = tryFoldConstant(firstArg);
        // Whether we can fold or not, Class.forName is always reflection
        return {
          nodeType: 'EXTERNAL',
          subtype: 'reflection',
          tainted: folded === null, // tainted if we can't resolve the constant
          chain: ['Class', 'forName'],
        };
      }
    }

    // ── Anti-evasion: Method.invoke — reflective invocation ──
    if (name?.text === 'invoke' && obj) {
      const objChain = extractCalleeChain(obj);
      const last = objChain[objChain.length - 1];
      // .getMethod(...).invoke(...) or variable.invoke(...)
      if (last === 'invoke' || objChain.some(p => p === 'getMethod' || p === 'getDeclaredMethod')) {
        return {
          nodeType: 'EXTERNAL',
          subtype: 'reflection',
          tainted: true,
          chain: [...objChain, 'invoke'],
        };
      }
      // Fallback: any .invoke() call on an unknown receiver could be reflective
      // Only flag if the receiver comes from getMethod/getDeclaredMethod chain
    }

    return null;
  }

  // object_creation_expression: new ClassName(args)
  if (node.type === 'object_creation_expression') {
    const typeNode = node.childForFieldName('type');
    if (typeNode) {
      const typeName = typeNode.text;
      const chain = [typeName];
      const pattern = _lookupJavaCallee(chain);
      if (pattern) {
        return {
          nodeType: pattern.nodeType,
          subtype: pattern.subtype,
          tainted: pattern.tainted,
          chain,
        };
      }

      // Check specific dangerous constructors
      if (typeName === 'ObjectInputStream') {
        return { nodeType: 'INGRESS', subtype: 'deserialize', tainted: true, chain };
      }
      if (typeName === 'ProcessBuilder') {
        return { nodeType: 'EXTERNAL', subtype: 'system_exec', tainted: false, chain };
      }
      if (typeName === 'File' || typeName === 'FileInputStream' || typeName === 'FileOutputStream') {
        return { nodeType: 'INGRESS', subtype: 'file_read', tainted: false, chain };
      }
      if (typeName === 'URL' || typeName === 'URI') {
        return { nodeType: 'TRANSFORM', subtype: 'parse', tainted: false, chain };
      }
      if (typeName === 'Scanner') {
        return { nodeType: 'INGRESS', subtype: 'user_input', tainted: true, chain };
      }
    }
    return null;
  }

  return null;
}

// ---------------------------------------------------------------------------
// resolvePropertyAccess — resolve a Java `field_access` (non-call)
// ---------------------------------------------------------------------------

function resolvePropertyAccess(node: SyntaxNode): ResolvedPropertyResult | null {
  if (node.type !== 'field_access') return null;

  const chain = extractCalleeChain(node);
  if (chain.length < 2) return null;

  const fullPath = chain.join('.');

  // Check tainted paths
  if (TAINTED_PATHS.has(fullPath)) {
    return {
      nodeType: 'INGRESS',
      subtype: 'http_request',
      tainted: true,
    };
  }

  // Check phoneme dictionary for property access
  const pattern = _lookupJavaCallee(chain);
  if (pattern) {
    return {
      nodeType: pattern.nodeType,
      subtype: pattern.subtype,
      tainted: pattern.tainted,
    };
  }

  // System.out, System.err → EGRESS
  if (fullPath === 'System.out' || fullPath === 'System.err') {
    return { nodeType: 'EGRESS', subtype: 'display', tainted: false };
  }

  return null;
}

// ---------------------------------------------------------------------------
// extractPatternNames — Java has no destructuring but handles declarators
// ---------------------------------------------------------------------------

function extractPatternNames(pattern: SyntaxNode): string[] {
  const names: string[] = [];

  if (pattern.type === 'identifier') {
    names.push(pattern.text);
  }

  // variable_declarator: name = value
  if (pattern.type === 'variable_declarator') {
    const name = pattern.childForFieldName('name');
    if (name?.type === 'identifier') {
      names.push(name.text);
    }
  }

  return names;
}

// ---------------------------------------------------------------------------
// Helper: find INGRESS node inside a function (for cross-function taint)
// ---------------------------------------------------------------------------

function findIngressInFunction(funcNodeId: string, ctx: MapperContextLike): string | null {
  const contained = new Set<string>();
  const queue = [funcNodeId];

  while (queue.length > 0) {
    const id = queue.shift()!;
    const node = ctx.neuralMap.nodes.find((n: any) => n.id === id);
    if (!node) continue;

    for (const edge of node.edges) {
      if (edge.edge_type === 'CONTAINS' && !contained.has(edge.target)) {
        contained.add(edge.target);
        queue.push(edge.target);
      }
    }
  }

  const ingress = ctx.neuralMap.nodes.find(
    (n: any) => contained.has(n.id) && n.node_type === 'INGRESS'
  );
  return ingress?.id ?? null;
}

// ---------------------------------------------------------------------------
// Helper: check if a parameter has a Spring taint annotation
// ---------------------------------------------------------------------------

function paramHasTaintAnnotation(paramNode: SyntaxNode): boolean {
  // Walk siblings/children looking for annotations
  // In tree-sitter-java, formal_parameter has modifiers child containing annotations
  const modifiers = paramNode.childForFieldName('modifiers') ??
    paramNode.descendantsOfType('modifiers')[0];
  if (!modifiers) {
    // Check children directly for marker_annotation / annotation
    for (let i = 0; i < paramNode.childCount; i++) {
      const child = paramNode.child(i);
      if (!child) continue;
      if (child.type === 'marker_annotation' || child.type === 'annotation') {
        const annotName = child.childForFieldName('name')?.text ?? child.text.replace('@', '');
        if (SPRING_TAINT_ANNOTATIONS.has(annotName)) return true;
      }
    }
    return false;
  }

  for (let i = 0; i < modifiers.childCount; i++) {
    const mod = modifiers.child(i);
    if (!mod) continue;
    if (mod.type === 'marker_annotation' || mod.type === 'annotation') {
      const annotName = mod.childForFieldName('name')?.text ?? mod.text.replace('@', '');
      if (SPRING_TAINT_ANNOTATIONS.has(annotName)) return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Helper: check if a method has a Spring route annotation
// ---------------------------------------------------------------------------

function methodHasRouteAnnotation(methodNode: SyntaxNode): string | null {
  // Check preceding siblings or modifiers for route annotations
  const modifiers = methodNode.childForFieldName('modifiers') ??
    methodNode.descendantsOfType('modifiers')[0];
  if (!modifiers) return null;

  for (let i = 0; i < modifiers.childCount; i++) {
    const mod = modifiers.child(i);
    if (!mod) continue;
    if (mod.type === 'marker_annotation' || mod.type === 'annotation') {
      const annotName = mod.childForFieldName('name')?.text ?? mod.text.replace('@', '');
      if (SPRING_ROUTE_ANNOTATIONS.has(annotName)) {
        return annotName;
      }
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Helper: check if a method has Spring security annotations
// ---------------------------------------------------------------------------

function methodHasSecurityAnnotation(methodNode: SyntaxNode): boolean {
  const modifiers = methodNode.childForFieldName('modifiers') ??
    methodNode.descendantsOfType('modifiers')[0];
  if (!modifiers) return false;

  for (let i = 0; i < modifiers.childCount; i++) {
    const mod = modifiers.child(i);
    if (!mod) continue;
    if (mod.type === 'marker_annotation' || mod.type === 'annotation') {
      const annotName = mod.childForFieldName('name')?.text ?? mod.text.replace('@', '');
      if (SPRING_SECURITY_ANNOTATIONS.has(annotName)) return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Helper: extract annotation name from annotation node
// ---------------------------------------------------------------------------

function getAnnotationName(node: SyntaxNode): string {
  if (node.type === 'marker_annotation') {
    const name = node.childForFieldName('name');
    return name?.text ?? node.text.replace('@', '');
  }
  if (node.type === 'annotation') {
    const name = node.childForFieldName('name');
    return name?.text ?? node.text.replace(/@([^(]+).*/, '$1');
  }
  return node.text;
}

// ---------------------------------------------------------------------------
// extractTaintSources — the recursive expression X-ray
// ---------------------------------------------------------------------------

function extractTaintSources(expr: SyntaxNode, ctx: MapperContextLike): TaintSourceResult[] {
  if (!expr) return [];

  switch (expr.type) {
    // -- Leaf: identifier -- check if it's a tainted variable
    case 'identifier': {
      const varInfo = ctx.resolveVariable(expr.text);
      if (varInfo?.tainted && varInfo.producingNodeId) {
        return [{ nodeId: varInfo.producingNodeId, name: expr.text }];
      }
      return [];
    }

    // -- Leaf: field_access -- check for tainted paths (request.getParameter etc.)
    case 'field_access': {
      const resolution = resolvePropertyAccess(expr);
      if (resolution?.tainted) {
        const label = expr.text.length > 100 ? expr.text.slice(0, 97) + '...' : expr.text;
        const ingressNode = createNode({
          label,
          node_type: resolution.nodeType,
          node_subtype: resolution.subtype,
          language: 'java',
          file: ctx.neuralMap.source_file,
          line_start: expr.startPosition.row + 1,
          line_end: expr.endPosition.row + 1,
          code_snapshot: expr.text.slice(0, 200), analysis_snapshot: expr.text.slice(0, 2000),
          data_out: [{
            name: 'result',
            source: 'SELF',
            data_type: 'unknown',
            tainted: true,
            sensitivity: 'NONE',
          }],
          attack_surface: ['user_input'],
        });
        ingressNode.data_out[0].source = ingressNode.id;
        ctx.neuralMap.nodes.push(ingressNode);
        ctx.emitContainsIfNeeded(ingressNode.id);
        return [{ nodeId: ingressNode.id, name: expr.text }];
      }
      // Check if the object is a tainted variable
      const obj = expr.childForFieldName('object');
      if (obj?.type === 'identifier') {
        const varInfo = ctx.resolveVariable(obj.text);
        if (varInfo?.tainted && varInfo.producingNodeId) {
          return [{ nodeId: varInfo.producingNodeId, name: expr.text }];
        }
      }
      // Recurse into deeper chains
      if (obj?.type === 'field_access') {
        return extractTaintSources(obj, ctx);
      }
      return [];
    }

    // -- Binary expression: string concatenation ("SELECT " + userInput) --
    case 'binary_expression': {
      const left = expr.childForFieldName('left');
      const right = expr.childForFieldName('right');
      const sources: TaintSourceResult[] = [];
      if (left) sources.push(...extractTaintSources(left, ctx));
      if (right) sources.push(...extractTaintSources(right, ctx));
      return sources;
    }

    // -- Method invocation: check if sanitizer, then check args --
    case 'method_invocation': {
      const callResolution = resolveCallee(expr);
      // Sanitizer or encoder call stops taint
      if (callResolution &&
          callResolution.nodeType === 'TRANSFORM' &&
          (callResolution.subtype === 'sanitize' || callResolution.subtype === 'encode')) {
        return [];
      }
      // If the call itself is a tainted INGRESS source (e.g. socket.getInputStream(),
      // request.getParameter(), System.getenv()), propagate taint from the existing node
      // or create a synthetic source entry. This handles when INGRESS calls are used as
      // arguments inside other calls (e.g. new InputStreamReader(socket.getInputStream())).
      if (callResolution && callResolution.tainted) {
        const callLine = expr.startPosition.row + 1;
        const callSnap = expr.text.slice(0, 30);
        const existing = ctx.neuralMap.nodes.find((n: any) =>
          n.line_start === callLine && n.code_snapshot.startsWith(callSnap)
        );
        if (existing) {
          return [{ nodeId: existing.id, name: existing.label }];
        }
        // Node not yet created — create a new INGRESS node so that taint paths
        // are established even when classifyNode hasn't run yet for this expression.
        const label = expr.text.length > 100 ? expr.text.slice(0, 97) + '...' : expr.text;
        const newIngressNode = createNode({
          label,
          node_type: callResolution.nodeType,
          node_subtype: callResolution.subtype,
          language: 'java',
          file: ctx.neuralMap.source_file,
          line_start: callLine,
          line_end: expr.endPosition.row + 1,
          code_snapshot: expr.text.slice(0, 200),
          analysis_snapshot: expr.text.slice(0, 2000),
          data_out: [{
            name: 'result',
            source: 'SELF',
            data_type: 'unknown',
            tainted: true,
            sensitivity: 'NONE',
          }],
          attack_surface: ['user_input'],
        });
        newIngressNode.data_out[0].source = newIngressNode.id;
        ctx.neuralMap.nodes.push(newIngressNode);
        ctx.emitContainsIfNeeded(newIngressNode.id);
        return [{ nodeId: newIngressNode.id, name: newIngressNode.label }];
      }
      // For any other call, check arguments AND receiver for taint
      const sources: TaintSourceResult[] = [];
      const args = expr.childForFieldName('arguments');
      if (args) {
        for (let i = 0; i < args.namedChildCount; i++) {
          const arg = args.namedChild(i);
          if (arg) sources.push(...extractTaintSources(arg, ctx));
        }
      }
      // Check receiver (object)
      const obj = expr.childForFieldName('object');
      if (obj) sources.push(...extractTaintSources(obj, ctx));
      // Check: existing node with tainted data_out
      if (sources.length === 0) {
        const callLine = expr.startPosition.row + 1;
        const callSnap = expr.text.slice(0, 30);
        const existing = ctx.neuralMap.nodes.find((n: any) =>
          n.line_start === callLine && n.code_snapshot.startsWith(callSnap)
        );
        if (existing?.data_out.some((d: any) => d.tainted)) {
          sources.push({ nodeId: existing.id, name: existing.label });
        }
      }
      return sources;
    }

    // -- Object creation: new Foo(taintedArg) --
    case 'object_creation_expression': {
      const sources: TaintSourceResult[] = [];
      const args = expr.childForFieldName('arguments');
      if (args) {
        for (let i = 0; i < args.namedChildCount; i++) {
          const arg = args.namedChild(i);
          if (arg) sources.push(...extractTaintSources(arg, ctx));
        }
      }
      return sources;
    }

    // -- Parenthesized expression --
    case 'parenthesized_expression': {
      const inner = expr.namedChild(0);
      return inner ? extractTaintSources(inner, ctx) : [];
    }

    // -- Cast expression: (String) x --
    case 'cast_expression': {
      const value = expr.childForFieldName('value');
      return value ? extractTaintSources(value, ctx) : [];
    }

    // -- Ternary: condition ? a : b --
    case 'ternary_expression': {
      const sources: TaintSourceResult[] = [];
      const consequence = expr.childForFieldName('consequence');
      const alternative = expr.childForFieldName('alternative');
      if (consequence) sources.push(...extractTaintSources(consequence, ctx));
      if (alternative) sources.push(...extractTaintSources(alternative, ctx));
      return sources;
    }

    // -- Array access: arr[i] --
    case 'array_access': {
      const array = expr.childForFieldName('array');
      if (array) return extractTaintSources(array, ctx);
      return [];
    }

    // -- String concatenation via template: "..." + x + "..."  --
    // (already handled by binary_expression)

    // -- Assignment expression (within expressions) --
    case 'assignment_expression': {
      const right = expr.childForFieldName('right');
      return right ? extractTaintSources(right, ctx) : [];
    }

    default:
      return [];
  }
}

// ---------------------------------------------------------------------------
// processVariableDeclaration
// ---------------------------------------------------------------------------

function processVariableDeclaration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type === 'local_variable_declaration' || node.type === 'field_declaration') {
    // Walk variable_declarator children
    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (!child || child.type !== 'variable_declarator') continue;

      const nameNode = child.childForFieldName('name');
      const valueNode = child.childForFieldName('value');

      if (!nameNode || nameNode.type !== 'identifier') continue;
      const varName = nameNode.text;

      // Determine variable kind
      const kind: VariableInfo['kind'] = node.type === 'field_declaration' ? 'var' : 'let';

      let producingNodeId = ctx.lastCreatedNodeId;
      let tainted = false;

      // Check if lastCreatedNode is tainted
      if (producingNodeId) {
        const producer = ctx.neuralMap.nodes.find((n: any) => n.id === producingNodeId);
        if (producer && (
          producer.node_type === 'INGRESS' ||
          producer.data_out.some((d: any) => d.tainted)
        )) {
          tainted = true;
        }
      }

      // Multi-hop taint: if value is an identifier, inherit taint
      if (!tainted && valueNode) {
        if (valueNode.type === 'identifier') {
          const sourceVar = ctx.resolveVariable(valueNode.text);
          if (sourceVar) {
            tainted = sourceVar.tainted;
            if (sourceVar.producingNodeId) producingNodeId = sourceVar.producingNodeId;
          }
        }
      }

      // Direct taint extraction from the value expression
      if (!tainted && valueNode) {
        const directTaint = extractTaintSources(valueNode, ctx);
        if (directTaint.length > 0) {
          tainted = true;
          producingNodeId = directTaint[0].nodeId;
        }
      }

      // Cross-function taint: x = getInput(request)
      if (!producingNodeId && valueNode) {
        const checkCallTaint = (expr: SyntaxNode) => {
          if (expr.type === 'method_invocation') {
            const name = expr.childForFieldName('name');
            if (name?.type === 'identifier') {
              const funcNodeId = ctx.functionRegistry.get(name.text);
              if (funcNodeId) {
                const ingressInFunc = findIngressInFunction(funcNodeId, ctx);
                if (ingressInFunc) {
                  tainted = true;
                  producingNodeId = ingressInFunc;
                }
              }
            }
          }
        };
        checkCallTaint(valueNode);
      }

      // Alias chain detection: stmt = conn.createStatement() -> store chain
      let aliasChain: string[] | undefined;
      if (valueNode) {
        if (valueNode.type === 'method_invocation') {
          const obj = valueNode.childForFieldName('object');
          const name = valueNode.childForFieldName('name');
          if (obj && name) {
            const chain = extractCalleeChain(obj);
            chain.push(name.text);
            aliasChain = chain;
          }
        } else if (valueNode.type === 'field_access') {
          aliasChain = extractCalleeChain(valueNode);
        }
      }

      // Constant folding: String action = "quer" + "y" -> constantValue = "query"
      let constantValue: string | undefined;
      if (valueNode) {
        const folded = tryFoldConstant(valueNode);
        if (folded !== null) constantValue = folded;
      }

      ctx.declareVariable(varName, kind, null, tainted, producingNodeId);
      const v = ctx.resolveVariable(varName);
      if (v) {
        if (aliasChain) v.aliasChain = aliasChain;
        if (constantValue) v.constantValue = constantValue;
      }
    }
    return;
  }
}

// ---------------------------------------------------------------------------
// processFunctionParams — handle Java method parameters with annotations
// ---------------------------------------------------------------------------

function processFunctionParams(funcNode: SyntaxNode, ctx: MapperContextLike): void {
  const paramsNode = funcNode.childForFieldName('parameters');
  if (!paramsNode) return;

  // In Java, parameters are in `formal_parameters` containing `formal_parameter` nodes.
  for (let i = 0; i < paramsNode.namedChildCount; i++) {
    const param = paramsNode.namedChild(i);
    if (!param) continue;

    if (param.type === 'formal_parameter' || param.type === 'spread_parameter') {
      const nameNode = param.childForFieldName('name');
      const typeNode = param.childForFieldName('type');
      const paramName = nameNode?.text;
      const typeText = typeNode?.text ?? '';

      if (!paramName) continue;

      // Check 1: Spring taint annotations (@RequestBody, @PathVariable, etc.)
      const hasTaintAnnotation = paramHasTaintAnnotation(param);

      // Check 2: HttpServletRequest type
      const isRequestType = JAVA_HTTP_REQUEST_TYPES.has(typeText);

      // Check 3: Conventional request parameter names
      const isRequestName = JAVA_REQUEST_PARAM_NAMES.has(paramName);

      if (hasTaintAnnotation || isRequestType || isRequestName) {
        // Create an INGRESS node for tainted parameter
        const subtype = hasTaintAnnotation ? 'http_request' :
                        isRequestType ? 'http_request' : 'http_request';
        const ingressNode = createNode({
          label: paramName,
          node_type: 'INGRESS',
          node_subtype: subtype,
          language: 'java',
          file: ctx.neuralMap.source_file,
          line_start: param.startPosition.row + 1,
          line_end: param.endPosition.row + 1,
          code_snapshot: param.text.slice(0, 200), analysis_snapshot: param.text.slice(0, 2000),
        });
        ingressNode.data_out.push({
          name: 'result',
          source: ingressNode.id,
          data_type: typeText || 'unknown',
          tainted: true,
          sensitivity: 'NONE',
        });
        ingressNode.attack_surface.push('user_input');
        ctx.neuralMap.nodes.push(ingressNode);
        ctx.emitContainsIfNeeded(ingressNode.id);

        ctx.declareVariable(paramName, 'param', null, true, ingressNode.id);
      } else if (JAVA_RESPONSE_PARAM_NAMES.has(paramName)) {
        // Response — not tainted but declare it
        ctx.declareVariable(paramName, 'param', null, false, null);
      } else {
        // Regular parameter — check pendingCallbackTaint
        const producingId = ctx.pendingCallbackTaint.get(paramName) ?? null;
        const isTainted = producingId !== null;
        if (isTainted) ctx.pendingCallbackTaint.delete(paramName);
        ctx.declareVariable(paramName, 'param', null, isTainted, producingId);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// classifyNode — the heart of the switch statement
// ---------------------------------------------------------------------------

function classifyNode(node: SyntaxNode, ctx: MapperContextLike): void {
  switch (node.type) {
    // -- METHOD DECLARATIONS --
    case 'method_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'anonymous';
      const routeAnnotation = methodHasRouteAnnotation(node);
      const hasSecurityAnnotation = methodHasSecurityAnnotation(node);

      const methodNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: routeAnnotation ? 'route' : 'function',
        language: 'java',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        // STEP 4: Use 500 chars so the parameter list is never truncated for
        // inter-procedural taint propagation via functionParamPattern.
        code_snapshot: node.text.slice(0, 500),
      });

      if (routeAnnotation) {
        methodNode.tags.push('route', routeAnnotation);
      }
      if (hasSecurityAnnotation) {
        methodNode.tags.push('auth_gate');
      }

      ctx.neuralMap.nodes.push(methodNode);
      ctx.lastCreatedNodeId = methodNode.id;
      ctx.emitContainsIfNeeded(methodNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = methodNode.id;
      ctx.functionRegistry.set(name, methodNode.id);
      break;
    }

    // -- CONSTRUCTOR DECLARATIONS --
    case 'constructor_declaration': {
      const name = node.childForFieldName('name')?.text ?? '<init>';
      const ctorNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        language: 'java',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctorNode.tags.push('constructor');
      ctx.neuralMap.nodes.push(ctorNode);
      ctx.lastCreatedNodeId = ctorNode.id;
      ctx.emitContainsIfNeeded(ctorNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = ctorNode.id;
      ctx.functionRegistry.set(name, ctorNode.id);
      break;
    }

    // -- LAMBDA EXPRESSION --
    case 'lambda_expression': {
      let lambdaName = 'lambda';
      // Try to get name from parent variable declaration
      if (node.parent?.type === 'variable_declarator') {
        const parentName = node.parent.childForFieldName('name');
        if (parentName?.type === 'identifier') {
          lambdaName = parentName.text;
        }
      }
      const lambdaNode = createNode({
        label: lambdaName,
        node_type: 'STRUCTURAL',
        node_subtype: 'function',
        language: 'java',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      lambdaNode.tags.push('lambda');
      ctx.neuralMap.nodes.push(lambdaNode);
      ctx.lastCreatedNodeId = lambdaNode.id;
      ctx.emitContainsIfNeeded(lambdaNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = lambdaNode.id;
      if (lambdaName !== 'lambda') ctx.functionRegistry.set(lambdaName, lambdaNode.id);
      break;
    }

    // -- CLASS DECLARATIONS --
    case 'class_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'AnonymousClass';

      // Check for class-level annotations (Spring components)
      let subtype = 'class';
      const modifiers = node.childForFieldName('modifiers') ??
        node.descendantsOfType('modifiers')[0];
      if (modifiers) {
        for (let i = 0; i < modifiers.childCount; i++) {
          const mod = modifiers.child(i);
          if (mod && (mod.type === 'marker_annotation' || mod.type === 'annotation')) {
            const annotName = getAnnotationName(mod);
            if (annotName === 'RestController' || annotName === 'Controller') {
              subtype = 'controller';
            } else if (annotName === 'Service') {
              subtype = 'service';
            } else if (annotName === 'Repository') {
              subtype = 'repository';
            } else if (annotName === 'Component') {
              subtype = 'component';
            } else if (annotName === 'Entity') {
              subtype = 'entity';
            } else if (annotName === 'Configuration') {
              subtype = 'config';
            }
          }
        }
      }

      const classNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: subtype,
        language: 'java',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(classNode);
      ctx.lastCreatedNodeId = classNode.id;
      ctx.emitContainsIfNeeded(classNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = classNode.id;
      break;
    }

    // -- INTERFACE DECLARATION --
    case 'interface_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'AnonymousInterface';
      const ifaceNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'interface',
        language: 'java',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(ifaceNode);
      ctx.lastCreatedNodeId = ifaceNode.id;
      ctx.emitContainsIfNeeded(ifaceNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = ifaceNode.id;
      break;
    }

    // -- ENUM DECLARATION --
    case 'enum_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'AnonymousEnum';
      const enumNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'enum',
        language: 'java',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(enumNode);
      ctx.lastCreatedNodeId = enumNode.id;
      ctx.emitContainsIfNeeded(enumNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = enumNode.id;
      break;
    }

    // -- RECORD DECLARATION (Java 14+) --
    case 'record_declaration': {
      const name = node.childForFieldName('name')?.text ?? 'AnonymousRecord';
      const recordNode = createNode({
        label: name,
        node_type: 'STRUCTURAL',
        node_subtype: 'record',
        language: 'java',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(recordNode);
      ctx.lastCreatedNodeId = recordNode.id;
      ctx.emitContainsIfNeeded(recordNode.id);
      if (ctx.currentScope) ctx.currentScope.containerNodeId = recordNode.id;
      break;
    }

    // -- IMPORT DECLARATIONS --
    case 'import_declaration': {
      // import com.example.Foo; or import static com.example.Bar.*
      const scopedId = node.descendantsOfType('scoped_identifier')[0];
      const moduleName = scopedId?.text ?? node.text.replace(/^import\s+(static\s+)?/, '').replace(/;\s*$/, '').trim();
      const importNode = createNode({
        label: moduleName,
        node_type: 'STRUCTURAL',
        node_subtype: 'dependency',
        language: 'java',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(importNode);
      ctx.lastCreatedNodeId = importNode.id;
      ctx.emitContainsIfNeeded(importNode.id);
      break;
    }

    // -- PACKAGE DECLARATION --
    case 'package_declaration': {
      const pkgScopedId = node.descendantsOfType('scoped_identifier')[0];
      const pkgName = pkgScopedId?.text ?? node.text.replace(/^package\s+/, '').replace(/;\s*$/, '').trim();
      const pkgNode = createNode({
        label: `package ${pkgName}`,
        node_type: 'STRUCTURAL',
        node_subtype: 'module',
        language: 'java',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      ctx.neuralMap.nodes.push(pkgNode);
      ctx.lastCreatedNodeId = pkgNode.id;
      ctx.emitContainsIfNeeded(pkgNode.id);
      break;
    }

    // -- METHOD INVOCATION: classify by callee --
    case 'method_invocation': {
      const resolution = resolveCallee(node);
      if (resolution) {
        const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
        const n = createNode({
          label,
          node_type: resolution.nodeType,
          node_subtype: resolution.subtype,
          language: 'java',
          file: ctx.neuralMap.source_file,
          line_start: node.startPosition.row + 1,
          line_end: node.endPosition.row + 1,
          code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
        });
        if (resolution.tainted) {
          n.data_out.push({
            name: 'result',
            source: n.id,
            data_type: 'unknown',
            tainted: true,
            sensitivity: 'NONE',
          });
        }
        if (resolution.nodeType === 'INGRESS') {
          n.attack_surface.push('user_input');
        }
        if (resolution.nodeType === 'EXTERNAL' && resolution.subtype === 'system_exec') {
          n.attack_surface.push('command_injection');
        }
        // Anti-evasion: tag Class.forName and reflection calls, resolve variable constants
        if (resolution.nodeType === 'EXTERNAL' && resolution.subtype === 'reflection') {
          n.tags.push('anti_evasion', 'reflection');
          // Try to resolve the first argument from variable constantValue
          const reflArgs = node.childForFieldName('arguments');
          const reflFirstArg = reflArgs?.namedChild(0);
          if (reflFirstArg?.type === 'identifier') {
            const argVar = ctx.resolveVariable(reflFirstArg.text);
            if (argVar?.constantValue) {
              n.label = `Class.forName("${argVar.constantValue}")`;
              n.tags.push(`resolved:${argVar.constantValue}`);
              // Not tainted since we resolved it to a constant
              n.data_out = n.data_out.filter((d: any) => !d.tainted);
            }
          }
        }
        ctx.neuralMap.nodes.push(n);
        ctx.lastCreatedNodeId = n.id;
        ctx.emitContainsIfNeeded(n.id);

        // Data flow: resolve arguments via recursive taint extraction
        const argsNode = node.childForFieldName('arguments');
        let callHasTaintedArgs = false;
        if (argsNode) {
          for (let a = 0; a < argsNode.namedChildCount; a++) {
            const arg = argsNode.namedChild(a);
            if (!arg) continue;

            const taintSources = extractTaintSources(arg, ctx);
            if (taintSources.length > 0) callHasTaintedArgs = true;
            for (const source of taintSources) {
              ctx.addDataFlow(
                source.nodeId,
                n.id,
                source.name,
                'unknown',
                true,
              );
            }
          }
        }

        // Receiver taint: method calls on tainted objects
        const calleeObj = node.childForFieldName('object');
        if (calleeObj) {
          const receiverTaint = extractTaintSources(calleeObj, ctx);
          for (const source of receiverTaint) {
            if (!callHasTaintedArgs) callHasTaintedArgs = true;
            ctx.addDataFlow(source.nodeId, n.id, source.name, 'unknown', true);
          }
        }

        // Taint-through: if ANY tainted data flows in, mark output tainted
        if (callHasTaintedArgs && !n.data_out.some((d: any) => d.tainted)) {
          n.data_out.push({
            name: 'result',
            source: n.id,
            data_type: 'unknown',
            tainted: true,
            sensitivity: 'NONE',
          });
        }

        // Callback parameter taint (for lambdas passed as args)
        if (callHasTaintedArgs) {
          const callArgs = node.childForFieldName('arguments');
          if (callArgs) {
            for (let ai = 0; ai < callArgs.namedChildCount; ai++) {
              const arg = callArgs.namedChild(ai);
              if (arg?.type === 'lambda_expression') {
                const params = arg.childForFieldName('parameters');
                if (params) {
                  for (let pi = 0; pi < params.namedChildCount; pi++) {
                    const p = params.namedChild(pi);
                    if (p?.type === 'formal_parameter') {
                      const pName = p.childForFieldName('name');
                      if (pName?.type === 'identifier') {
                        ctx.pendingCallbackTaint.set(pName.text, n.id);
                      }
                    } else if (p?.type === 'identifier') {
                      // Inferred parameter: (x) -> x.foo() or just x -> x.foo()
                      ctx.pendingCallbackTaint.set(p.text, n.id);
                    }
                  }
                }
              }
            }
          }
        }
      } else {
        // -- Variable alias resolution --
        const aliasName = node.childForFieldName('name');
        const aliasObj = node.childForFieldName('object');
        if (aliasObj?.type === 'identifier') {
          const aliasVar = ctx.resolveVariable(aliasObj.text);
          if (aliasVar?.aliasChain && aliasName) {
            const fullChain = [...aliasVar.aliasChain, aliasName.text];
            const aliasPattern = _lookupJavaCallee(fullChain);
            if (aliasPattern) {
              const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
              const aliasN = createNode({
                label,
                node_type: aliasPattern.nodeType,
                node_subtype: aliasPattern.subtype,
                language: 'java',
                file: ctx.neuralMap.source_file,
                line_start: node.startPosition.row + 1,
                line_end: node.endPosition.row + 1,
                code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
              });
              if (aliasPattern.nodeType === 'EXTERNAL' && aliasPattern.subtype === 'system_exec') {
                aliasN.attack_surface.push('command_injection');
              }
              ctx.neuralMap.nodes.push(aliasN);
              ctx.lastCreatedNodeId = aliasN.id;
              ctx.emitContainsIfNeeded(aliasN.id);
              const aliasArgs = node.childForFieldName('arguments');
              if (aliasArgs) {
                for (let a = 0; a < aliasArgs.namedChildCount; a++) {
                  const arg = aliasArgs.namedChild(a);
                  if (!arg) continue;
                  const taintSources = extractTaintSources(arg, ctx);
                  for (const source of taintSources) {
                    ctx.addDataFlow(source.nodeId, aliasN.id, source.name, 'unknown', true);
                  }
                }
              }
              break;
            }
          }
        }

        // -- Anti-evasion: Class.forName(variable) with constant-folded variable --
        // Detects: String name = "ev" + "al"; Class.forName(name)
        if (aliasObj?.text === 'Class' && aliasName?.text === 'forName') {
          const argsNode = node.childForFieldName('arguments');
          const firstArg = argsNode?.namedChild(0);
          let resolved = false;
          if (firstArg) {
            // Try direct constant folding first
            let foldedClassName = tryFoldConstant(firstArg);
            // Fall back to variable constantValue lookup
            if (!foldedClassName && firstArg.type === 'identifier') {
              const argVar = ctx.resolveVariable(firstArg.text);
              if (argVar?.constantValue) foldedClassName = argVar.constantValue;
            }
            const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
            const reflectNode = createNode({
              label: foldedClassName ? `Class.forName("${foldedClassName}")` : label,
              node_type: 'EXTERNAL',
              node_subtype: 'reflection',
              language: 'java',
              file: ctx.neuralMap.source_file,
              line_start: node.startPosition.row + 1,
              line_end: node.endPosition.row + 1,
              code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
            });
            reflectNode.tags.push('anti_evasion', 'reflection');
            if (foldedClassName) {
              reflectNode.tags.push(`resolved:${foldedClassName}`);
            }
            // If we couldn't fold, the argument might be tainted
            if (!foldedClassName) {
              reflectNode.data_out.push({
                name: 'result', source: reflectNode.id,
                data_type: 'unknown', tainted: true, sensitivity: 'NONE',
              });
            }
            // Check for tainted args flowing in
            if (argsNode) {
              for (let a = 0; a < argsNode.namedChildCount; a++) {
                const arg = argsNode.namedChild(a);
                if (!arg) continue;
                const taintSources = extractTaintSources(arg, ctx);
                for (const source of taintSources) {
                  ctx.addDataFlow(source.nodeId, reflectNode.id, source.name, 'unknown', true);
                  reflectNode.data_out.push({
                    name: 'result', source: reflectNode.id,
                    data_type: 'unknown', tainted: true, sensitivity: 'NONE',
                  });
                }
              }
            }
            ctx.neuralMap.nodes.push(reflectNode);
            ctx.lastCreatedNodeId = reflectNode.id;
            ctx.emitContainsIfNeeded(reflectNode.id);
            resolved = true;
          }
          if (resolved) break;
        }

        // -- Unresolved call -- check if it's a locally-defined method --
        let calleeName: string | null = null;
        if (aliasName?.type === 'identifier') {
          calleeName = aliasName.text;
        }

        if (calleeName && ctx.functionRegistry.has(calleeName)) {
          const argsNode = node.childForFieldName('arguments');
          const taintSources: TaintSourceResult[] = [];
          if (argsNode) {
            for (let a = 0; a < argsNode.namedChildCount; a++) {
              const arg = argsNode.namedChild(a);
              if (arg) taintSources.push(...extractTaintSources(arg, ctx));
            }
          }

          const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
          const callNode = createNode({
            label,
            node_type: 'TRANSFORM',
            node_subtype: 'local_call',
            language: 'java',
            file: ctx.neuralMap.source_file,
            line_start: node.startPosition.row + 1,
            line_end: node.endPosition.row + 1,
            code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
          });
          const funcNodeId = ctx.functionRegistry.get(calleeName);
          const funcStructNode = funcNodeId ? ctx.neuralMap.nodes.find((n: any) => n.id === funcNodeId) : null;
          const funcReturnsTaint = funcStructNode?.data_out.some((d: any) => d.tainted) ?? false;

          if (taintSources.length > 0 || funcReturnsTaint) {
            callNode.data_out.push({
              name: 'result',
              source: callNode.id,
              data_type: 'unknown',
              tainted: true,
              sensitivity: 'NONE',
            });
          }
          ctx.neuralMap.nodes.push(callNode);
          ctx.lastCreatedNodeId = callNode.id;
          ctx.emitContainsIfNeeded(callNode.id);

          for (const source of taintSources) {
            ctx.addDataFlow(source.nodeId, callNode.id, source.name, 'unknown', true);
          }
        }
      }

      // CALLS edge: capture method name for pending calls
      const callName = node.childForFieldName('name');
      if (callName?.type === 'identifier') {
        const containerId = ctx.getCurrentContainerId();
        if (containerId) {
          ctx.pendingCalls.push({
            callerContainerId: containerId,
            calleeName: callName.text,
            isAsync: false,
          });
        }
      }
      break;
    }

    // -- OBJECT CREATION EXPRESSION: new ClassName(args) --
    case 'object_creation_expression': {
      const resolution = resolveCallee(node);
      if (resolution) {
        const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
        const n = createNode({
          label,
          node_type: resolution.nodeType,
          node_subtype: resolution.subtype,
          language: 'java',
          file: ctx.neuralMap.source_file,
          line_start: node.startPosition.row + 1,
          line_end: node.endPosition.row + 1,
          code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
        });
        if (resolution.tainted) {
          n.data_out.push({
            name: 'result',
            source: n.id,
            data_type: 'unknown',
            tainted: true,
            sensitivity: 'NONE',
          });
        }
        if (resolution.nodeType === 'INGRESS') {
          n.attack_surface.push('user_input');
        }
        if (resolution.nodeType === 'EXTERNAL' && resolution.subtype === 'system_exec') {
          n.attack_surface.push('command_injection');
        }
        ctx.neuralMap.nodes.push(n);
        ctx.lastCreatedNodeId = n.id;
        ctx.emitContainsIfNeeded(n.id);

        // Data flow from tainted arguments
        const argsNode = node.childForFieldName('arguments');
        if (argsNode) {
          for (let a = 0; a < argsNode.namedChildCount; a++) {
            const arg = argsNode.namedChild(a);
            if (!arg) continue;
            const taintSources = extractTaintSources(arg, ctx);
            for (const source of taintSources) {
              ctx.addDataFlow(source.nodeId, n.id, source.name, 'unknown', true);
            }
          }
        }
      }
      break;
    }

    // -- FIELD ACCESS: standalone property access --
    case 'field_access': {
      // Skip if this is part of a method_invocation's object
      const parentIsCall = node.parent?.type === 'method_invocation' &&
        node.parent.childForFieldName('object')?.startIndex === node.startIndex;
      if (!parentIsCall) {
        const lineNum = node.startPosition.row + 1;
        const codeText = node.text.slice(0, 200);
        const alreadyCreated = ctx.neuralMap.nodes.find(
          (n: any) => n.line_start === lineNum && n.code_snapshot === codeText
        );
        if (alreadyCreated) {
          ctx.lastCreatedNodeId = alreadyCreated.id;
          break;
        }

        const resolution = resolvePropertyAccess(node);
        if (resolution) {
          const label = node.text.length > 100 ? node.text.slice(0, 97) + '...' : node.text;
          const n = createNode({
            label,
            node_type: resolution.nodeType,
            node_subtype: resolution.subtype,
            language: 'java',
            file: ctx.neuralMap.source_file,
            line_start: lineNum,
            line_end: node.endPosition.row + 1,
            code_snapshot: codeText,
          });
          if (resolution.tainted) {
            n.data_out.push({
              name: 'result',
              source: n.id,
              data_type: 'unknown',
              tainted: true,
              sensitivity: 'NONE',
            });
            n.attack_surface.push('user_input');
          }
          ctx.neuralMap.nodes.push(n);
          ctx.lastCreatedNodeId = n.id;
          ctx.emitContainsIfNeeded(n.id);
        }
      }
      break;
    }

    // -- ANNOTATIONS (marker and normal) --
    case 'marker_annotation':
    case 'annotation': {
      const annotName = getAnnotationName(node);
      // Create META nodes for significant annotations
      if (SPRING_ROUTE_ANNOTATIONS.has(annotName) ||
          SPRING_SECURITY_ANNOTATIONS.has(annotName) ||
          VALIDATION_ANNOTATIONS.has(annotName) ||
          SPRING_TAINT_ANNOTATIONS.has(annotName) ||
          annotName === 'Transactional' ||
          annotName === 'Autowired' ||
          annotName === 'Override') {
        const annotNode = createNode({
          label: `@${annotName}`,
          node_type: 'META',
          node_subtype: SPRING_ROUTE_ANNOTATIONS.has(annotName) ? 'route_annotation' :
                        SPRING_SECURITY_ANNOTATIONS.has(annotName) ? 'security_annotation' :
                        VALIDATION_ANNOTATIONS.has(annotName) ? 'validation_annotation' :
                        'annotation',
          language: 'java',
          file: ctx.neuralMap.source_file,
          line_start: node.startPosition.row + 1,
          line_end: node.endPosition.row + 1,
          code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
        });
        if (VALIDATION_ANNOTATIONS.has(annotName)) {
          annotNode.tags.push('validation');
        }
        if (SPRING_SECURITY_ANNOTATIONS.has(annotName)) {
          annotNode.tags.push('auth_gate');
        }
        ctx.neuralMap.nodes.push(annotNode);
        ctx.lastCreatedNodeId = annotNode.id;
        ctx.emitContainsIfNeeded(annotNode.id);
      }
      break;
    }

    // -- CONTROL FLOW --
    case 'if_statement': {
      const ifN = createNode({ label: 'if', node_type: 'CONTROL', node_subtype: 'branch', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(ifN); ctx.lastCreatedNodeId = ifN.id; ctx.emitContainsIfNeeded(ifN.id);
      break;
    }
    case 'for_statement': {
      const forN = createNode({ label: 'for', node_type: 'CONTROL', node_subtype: 'loop', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(forN); ctx.lastCreatedNodeId = forN.id; ctx.emitContainsIfNeeded(forN.id);
      break;
    }
    case 'enhanced_for_statement': {
      const eforN = createNode({ label: 'for-each', node_type: 'CONTROL', node_subtype: 'loop', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(eforN); ctx.lastCreatedNodeId = eforN.id; ctx.emitContainsIfNeeded(eforN.id);
      break;
    }
    case 'while_statement': {
      const whileN = createNode({ label: 'while', node_type: 'CONTROL', node_subtype: 'loop', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(whileN); ctx.lastCreatedNodeId = whileN.id; ctx.emitContainsIfNeeded(whileN.id);
      break;
    }
    case 'do_statement': {
      const doN = createNode({ label: 'do-while', node_type: 'CONTROL', node_subtype: 'loop', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(doN); ctx.lastCreatedNodeId = doN.id; ctx.emitContainsIfNeeded(doN.id);
      break;
    }
    case 'switch_expression': {
      const switchN = createNode({ label: 'switch', node_type: 'CONTROL', node_subtype: 'branch', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(switchN); ctx.lastCreatedNodeId = switchN.id; ctx.emitContainsIfNeeded(switchN.id);
      break;
    }
    case 'return_statement': {
      const retN = createNode({ label: 'return', node_type: 'CONTROL', node_subtype: 'return', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(retN); ctx.lastCreatedNodeId = retN.id; ctx.emitContainsIfNeeded(retN.id);
      break;
    }
    case 'break_statement': {
      const breakN = createNode({ label: 'break', node_type: 'CONTROL', node_subtype: 'break', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(breakN); ctx.lastCreatedNodeId = breakN.id; ctx.emitContainsIfNeeded(breakN.id);
      break;
    }
    case 'continue_statement': {
      const contN = createNode({ label: 'continue', node_type: 'CONTROL', node_subtype: 'continue', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(contN); ctx.lastCreatedNodeId = contN.id; ctx.emitContainsIfNeeded(contN.id);
      break;
    }
    case 'throw_statement': {
      const throwN = createNode({ label: 'throw', node_type: 'CONTROL', node_subtype: 'throw', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      throwN.tags.push('error_handling');
      ctx.neuralMap.nodes.push(throwN); ctx.lastCreatedNodeId = throwN.id; ctx.emitContainsIfNeeded(throwN.id);
      break;
    }

    // -- JAVA-SPECIFIC: synchronized, try-with-resources, assert --
    case 'synchronized_statement': {
      const syncN = createNode({ label: 'synchronized', node_type: 'CONTROL', node_subtype: 'synchronized', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      syncN.tags.push('concurrency', 'synchronized');
      ctx.neuralMap.nodes.push(syncN); ctx.lastCreatedNodeId = syncN.id; ctx.emitContainsIfNeeded(syncN.id);
      break;
    }
    case 'try_statement':
    case 'try_with_resources_statement': {
      const tryN = createNode({
        label: node.type === 'try_with_resources_statement' ? 'try-with-resources' : 'try',
        node_type: 'CONTROL',
        node_subtype: 'error_handling',
        language: 'java',
        file: ctx.neuralMap.source_file,
        line_start: node.startPosition.row + 1,
        line_end: node.endPosition.row + 1,
        code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000),
      });
      if (node.type === 'try_with_resources_statement') {
        tryN.tags.push('resource_management', 'auto_closeable');
      }
      tryN.tags.push('error_handling');
      ctx.neuralMap.nodes.push(tryN); ctx.lastCreatedNodeId = tryN.id; ctx.emitContainsIfNeeded(tryN.id);
      break;
    }
    case 'catch_clause': {
      const catchN = createNode({ label: 'catch', node_type: 'CONTROL', node_subtype: 'error_handling', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      catchN.tags.push('error_handling');
      ctx.neuralMap.nodes.push(catchN); ctx.lastCreatedNodeId = catchN.id; ctx.emitContainsIfNeeded(catchN.id);
      break;
    }
    case 'finally_clause': {
      const finallyN = createNode({ label: 'finally', node_type: 'CONTROL', node_subtype: 'error_handling', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      finallyN.tags.push('cleanup', 'error_handling');
      ctx.neuralMap.nodes.push(finallyN); ctx.lastCreatedNodeId = finallyN.id; ctx.emitContainsIfNeeded(finallyN.id);
      break;
    }
    case 'assert_statement': {
      const assertN = createNode({ label: 'assert', node_type: 'CONTROL', node_subtype: 'guard', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      assertN.tags.push('validation');
      ctx.neuralMap.nodes.push(assertN); ctx.lastCreatedNodeId = assertN.id; ctx.emitContainsIfNeeded(assertN.id);
      break;
    }

    // -- ASSIGNMENT (non-declaration) --
    case 'assignment_expression': {
      const assignLeft = node.childForFieldName('left');
      const leftText = assignLeft?.text?.slice(0, 40) ?? '?';
      const assignN = createNode({ label: `${leftText} =`, node_type: 'TRANSFORM', node_subtype: 'assignment', language: 'java', file: ctx.neuralMap.source_file, line_start: node.startPosition.row + 1, line_end: node.endPosition.row + 1, code_snapshot: node.text.slice(0, 200), analysis_snapshot: node.text.slice(0, 2000) });
      ctx.neuralMap.nodes.push(assignN); ctx.lastCreatedNodeId = assignN.id; ctx.emitContainsIfNeeded(assignN.id);

      const assignRight = node.childForFieldName('right');
      if (assignRight) {
        const taintSources = extractTaintSources(assignRight, ctx);
        if (taintSources.length > 0) {
          for (const source of taintSources) {
            ctx.addDataFlow(source.nodeId, assignN.id, source.name, 'unknown', true);
          }
          // Propagate taint to the variable being assigned
          if (assignLeft?.type === 'identifier') {
            const varInfo = ctx.resolveVariable(assignLeft.text);
            if (varInfo) {
              varInfo.tainted = true;
              varInfo.producingNodeId = assignN.id;
            }
          }
          assignN.data_out.push({
            name: 'result',
            source: assignN.id,
            data_type: 'unknown',
            tainted: true,
            sensitivity: 'NONE',
          });
        }
      }
      break;
    }

    // -- STRING LITERAL (for hardcoded credential detection) --
    case 'string_literal': {
      // Don't create nodes for every string — handled by verifier patterns
      break;
    }

    // -- Silent pass-throughs --
    case 'expression_statement':
    case 'empty_statement':
    case 'parenthesized_expression':
    case 'comment':
    case 'line_comment':
    case 'block_comment':
      break;
  }
}

// ---------------------------------------------------------------------------
// postVisitFunction — check if return expression is tainted
// ---------------------------------------------------------------------------

function postVisitFunction(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'method_declaration' && node.type !== 'constructor_declaration' && node.type !== 'lambda_expression') {
    return;
  }

  const body = node.childForFieldName('body');
  if (!body) return;

  // Check for return statements with tainted expressions
  const returnStmts = body.descendantsOfType('return_statement');
  for (const stmt of returnStmts) {
    for (let j = 0; j < stmt.namedChildCount; j++) {
      const retExpr = stmt.namedChild(j);
      if (retExpr) {
        const taintSources = extractTaintSources(retExpr, ctx);
        if (taintSources.length > 0) {
          const funcNodeId = ctx.currentScope?.containerNodeId;
          if (funcNodeId) {
            const funcNode = ctx.neuralMap.nodes.find((n: any) => n.id === funcNodeId);
            if (funcNode && !funcNode.data_out.some((d: any) => d.tainted)) {
              funcNode.data_out.push({
                name: 'return', source: funcNode.id, data_type: 'unknown', tainted: true, sensitivity: 'NONE',
              });
            }
          }
          return; // one tainted return is enough
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// preVisitIteration — set up enhanced for loop variable taint
// ---------------------------------------------------------------------------

function preVisitIteration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'enhanced_for_statement') return;

  // Java enhanced for: for (Type item : collection) { ... }
  const name = node.childForFieldName('name');
  const value = node.childForFieldName('value');

  if (name && value) {
    const iterTaint = extractTaintSources(value, ctx);
    if (iterTaint.length > 0) {
      ctx.declareVariable(name.text, 'const', null, true, iterTaint[0].nodeId);
    }
  }
}

// ---------------------------------------------------------------------------
// postVisitIteration — re-mark enhanced for loop variable taint
// ---------------------------------------------------------------------------

function postVisitIteration(node: SyntaxNode, ctx: MapperContextLike): void {
  if (node.type !== 'enhanced_for_statement') return;

  const name = node.childForFieldName('name');
  const value = node.childForFieldName('value');

  if (name && value) {
    const iterTaint = extractTaintSources(value, ctx);
    if (iterTaint.length > 0) {
      const v = ctx.resolveVariable(name.text);
      if (v) {
        v.tainted = true;
        v.producingNodeId = iterTaint[0].nodeId;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// The Profile
// ---------------------------------------------------------------------------

export const javaProfile: LanguageProfile = {
  id: 'java',
  extensions: ['.java'],

  // Layer 1: AST Node Type Recognition
  functionScopeTypes: FUNCTION_SCOPE_TYPES,
  blockScopeTypes: BLOCK_SCOPE_TYPES,
  classScopeTypes: CLASS_SCOPE_TYPES,

  getScopeType(node: SyntaxNode): ScopeType | null {
    if (FUNCTION_SCOPE_TYPES.has(node.type)) return 'function';
    if (BLOCK_SCOPE_TYPES.has(node.type)) return 'block';
    if (CLASS_SCOPE_TYPES.has(node.type)) return 'class';
    return null;
  },

  variableDeclarationTypes: VARIABLE_DECLARATION_TYPES,
  functionDeclarationTypes: FUNCTION_DECLARATION_TYPES,

  // Layer 2: AST Child Access
  processVariableDeclaration,
  processFunctionParams,
  extractPatternNames,

  // Layer 3: Callee Resolution (Phoneme Dictionary)
  resolveCallee(node: SyntaxNode): ResolvedCalleeResult | null {
    return resolveCallee(node);
  },

  resolvePropertyAccess(node: SyntaxNode): ResolvedPropertyResult | null {
    return resolvePropertyAccess(node);
  },

  lookupCallee(chain: string[]): CalleePattern | null {
    return _lookupJavaCallee(chain);
  },

  analyzeStructure(_node: SyntaxNode): StructuralAnalysisResult | null {
    // Java Spring routing is annotation-driven, handled in classifyNode.
    return null;
  },

  // Layer 4: Taint Source Detection
  ingressPattern: /(?:request\.(?:getParameter|getHeader|getCookies|getInputStream|getReader|getQueryString|getPathInfo|getRequestURI|getRequestURL|getAttribute|getPart|getRemoteAddr|getMethod)|req\.(?:getParameter|getHeader|getCookies|getInputStream)|scanner\.(?:nextLine|next|nextInt)|@(?:RequestBody|PathVariable|RequestParam|RequestHeader|CookieValue|ModelAttribute)|BufferedReader\.readLine|Console\.readLine|System\.in|ObjectInputStream\.readObject)/,
  taintedPaths: TAINTED_PATHS,

  // Layer 5: Node Classification
  classifyNode,
  extractTaintSources,
  postVisitFunction,
  preVisitIteration,
  postVisitIteration,

  // Utility predicates
  isValueFirstDeclaration: (nodeType: string) =>
    nodeType === 'local_variable_declaration' || nodeType === 'field_declaration',
  isStatementContainer: (nodeType: string) =>
    nodeType === 'program' || nodeType === 'block' || nodeType === 'class_body',

  // Inter-procedural taint: Java method syntax
  // Matches: public void method(params) { | void method(params) { | method(params) {
  functionParamPattern: /(?:public|private|protected|static|final|\s)+\w+\s+\w+\s*\(([^)]*)\)/,
};

export default javaProfile;
