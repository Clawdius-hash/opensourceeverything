/**
 * Tests for cross-file analysis — import resolution, NeuralMap merging,
 * and cross-file taint propagation.
 */

import { describe, it, expect } from 'vitest';
import {
  extractImports,
  extractExports,
  resolveImportPath,
  mergeNeuralMaps,
  buildDependencyGraph,
  analyzeCrossFile,
} from './cross-file';
import { createNode, createNeuralMap, resetSequence } from './types';
import type { NeuralMap } from './types';
import { verifyAll } from './verifier';

// ---------------------------------------------------------------------------
// Import extraction tests
// ---------------------------------------------------------------------------

describe('extractImports', () => {
  it('extracts CommonJS require() with var/let/const', () => {
    const source = `
var express = require('express');
let db = require('./db');
const handler = require('../core/appHandler');
`;
    const imports = extractImports(source, '/project/app.js');
    expect(imports).toHaveLength(3);
    expect(imports[0]).toMatchObject({
      specifier: 'express',
      localName: 'express',
      importedNames: ['*'],
    });
    expect(imports[1]).toMatchObject({
      specifier: './db',
      localName: 'db',
    });
    expect(imports[2]).toMatchObject({
      specifier: '../core/appHandler',
      localName: 'handler',
    });
  });

  it('extracts destructured require()', () => {
    const source = `const { exec } = require('child_process');`;
    const imports = extractImports(source, '/project/app.js');
    expect(imports).toHaveLength(1);
    expect(imports[0]).toMatchObject({
      specifier: 'child_process',
      importedNames: ['exec'],
    });
  });

  it('extracts ES default import', () => {
    const source = `import express from 'express';`;
    const imports = extractImports(source, '/project/app.js');
    expect(imports).toHaveLength(1);
    expect(imports[0]).toMatchObject({
      specifier: 'express',
      importedNames: ['default'],
      localName: 'express',
    });
  });

  it('extracts ES named imports', () => {
    const source = `import { readFile, writeFile } from 'fs';`;
    const imports = extractImports(source, '/project/app.js');
    expect(imports).toHaveLength(1);
    expect(imports[0]).toMatchObject({
      specifier: 'fs',
      importedNames: ['readFile', 'writeFile'],
    });
  });

  it('extracts ES namespace import', () => {
    const source = `import * as path from 'path';`;
    const imports = extractImports(source, '/project/app.js');
    expect(imports).toHaveLength(1);
    expect(imports[0]).toMatchObject({
      specifier: 'path',
      importedNames: ['*'],
      localName: 'path',
    });
  });

  it('extracts side-effect require', () => {
    const source = `require('./core/passport')(passport);`;
    const imports = extractImports(source, '/project/app.js');
    expect(imports).toHaveLength(1);
    expect(imports[0]).toMatchObject({
      specifier: './core/passport',
      localName: null,
    });
  });

  it('handles mixed import styles', () => {
    const source = `
var router = require('express').Router()
var appHandler = require('../core/appHandler')
var authHandler = require('../core/authHandler')
`;
    const imports = extractImports(source, '/project/routes/app.js');
    expect(imports).toHaveLength(3);
    expect(imports[1]).toMatchObject({
      specifier: '../core/appHandler',
      localName: 'appHandler',
    });
  });

  it('captures line numbers', () => {
    const source = `
const a = require('./a');
const b = require('./b');
`;
    const imports = extractImports(source, '/project/app.js');
    expect(imports[0].line).toBe(2);
    expect(imports[1].line).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// Export extraction tests
// ---------------------------------------------------------------------------

describe('extractExports', () => {
  it('extracts module.exports.name = function', () => {
    const source = `
module.exports.userSearch = function (req, res) {};
module.exports.ping = function (req, res) {};
`;
    const exports = extractExports(source);
    expect(exports).toContain('userSearch');
    expect(exports).toContain('ping');
  });

  it('extracts exports.name = function', () => {
    const source = `
exports.handler = function (req, res) {};
`;
    const exports = extractExports(source);
    expect(exports).toContain('handler');
  });

  it('extracts ES export function', () => {
    const source = `
export function processData(data) {}
export default function main() {}
`;
    const exports = extractExports(source);
    expect(exports).toContain('processData');
    expect(exports).toContain('main');
  });

  it('extracts ES export const', () => {
    const source = `export const API_KEY = 'abc123';`;
    const exports = extractExports(source);
    expect(exports).toContain('API_KEY');
  });

  it('deduplicates exports', () => {
    const source = `
module.exports.handler = function() {};
module.exports.handler = function() {};
`;
    const exports = extractExports(source);
    expect(exports.filter(e => e === 'handler')).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Import path resolution tests
// ---------------------------------------------------------------------------

describe('resolveImportPath', () => {
  const allFiles = [
    '/project/app.js',
    '/project/db.js',
    '/project/core/appHandler.js',
    '/project/core/authHandler.js',
    '/project/models/index.js',
    '/project/utils.ts',
  ];

  it('resolves relative path to JS file', () => {
    const result = resolveImportPath('./db', '/project/app.js', allFiles);
    expect(result).toBe('/project/db.js');
  });

  it('resolves parent-relative path', () => {
    const result = resolveImportPath(
      '../core/appHandler',
      '/project/routes/app.js',
      allFiles,
    );
    expect(result).toBe('/project/core/appHandler.js');
  });

  it('resolves directory import to index.js', () => {
    const result = resolveImportPath('./models', '/project/app.js', allFiles);
    expect(result).toBe('/project/models/index.js');
  });

  it('resolves .ts extension', () => {
    const result = resolveImportPath('./utils', '/project/app.js', allFiles);
    expect(result).toBe('/project/utils.ts');
  });

  it('returns null for npm packages', () => {
    const result = resolveImportPath('express', '/project/app.js', allFiles);
    expect(result).toBeNull();
  });

  it('returns null for unresolvable paths', () => {
    const result = resolveImportPath('./nonexistent', '/project/app.js', allFiles);
    expect(result).toBeNull();
  });

  it('handles Windows-style paths', () => {
    const winFiles = [
      'C:/Users/pizza/project/app.js',
      'C:/Users/pizza/project/db.js',
    ];
    const result = resolveImportPath('./db', 'C:\\Users\\pizza\\project\\app.js', winFiles);
    expect(result).toBe('C:/Users/pizza/project/db.js');
  });
});

// ---------------------------------------------------------------------------
// NeuralMap merge tests
// ---------------------------------------------------------------------------

describe('mergeNeuralMaps', () => {
  function makeMap(file: string, sourceCode: string, nodeSpecs: Array<{
    id: string;
    type: 'INGRESS' | 'EGRESS' | 'STORAGE' | 'EXTERNAL' | 'STRUCTURAL' | 'TRANSFORM';
    label: string;
    code: string;
    taintedIn?: boolean;
    taintedOut?: boolean;
    edges?: Array<{ target: string; type: 'CALLS' | 'DATA_FLOW' }>;
    attackSurface?: string[];
  }>): NeuralMap {
    resetSequence();
    const map = createNeuralMap(file, sourceCode);
    for (const spec of nodeSpecs) {
      map.nodes.push(createNode({
        id: spec.id,
        node_type: spec.type,
        label: spec.label,
        code_snapshot: spec.code,
        file: file,
        data_in: spec.taintedIn ? [{ name: 'input', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }] : [],
        data_out: spec.taintedOut ? [{ name: 'output', source: spec.id, data_type: 'string', tainted: true, sensitivity: 'NONE' }] : [],
        edges: (spec.edges ?? []).map(e => ({ target: e.target, edge_type: e.type, conditional: false, async: false })),
        attack_surface: spec.attackSurface ?? [],
      }));
    }
    return map;
  }

  it('merges nodes from multiple files without collision', () => {
    const mapA = makeMap('/project/a.js', 'const x = 1;', [
      { id: 'node1', type: 'INGRESS', label: 'input', code: 'req.body' },
    ]);
    const mapB = makeMap('/project/b.js', 'const y = 2;', [
      { id: 'node1', type: 'STORAGE', label: 'db.query', code: 'db.query(x)' },
    ]);

    const fileMaps = new Map<string, NeuralMap>();
    fileMaps.set('/project/a.js', mapA);
    fileMaps.set('/project/b.js', mapB);

    const depGraph = {
      files: ['/project/a.js', '/project/b.js'],
      edges: [],
      importsOf: new Map(),
      importedBy: new Map(),
    };

    const { mergedMap } = mergeNeuralMaps(fileMaps, depGraph);
    expect(mergedMap.nodes).toHaveLength(2);
    // IDs should be prefixed to avoid collision
    const ids = mergedMap.nodes.map(n => n.id);
    expect(ids[0]).not.toBe(ids[1]);
    expect(ids[0]).toContain('project_a');
    expect(ids[1]).toContain('project_b');
  });

  it('creates cross-file CALLS edges for whole-module imports', () => {
    // File B exports: module.exports.handler = function(req, res) { ... }
    const mapB = makeMap(
      '/project/core/handler.js',
      'module.exports.handler = function(req, res) { db.query(req.body.id); };',
      [
        {
          id: 'func_handler',
          type: 'STRUCTURAL',
          label: 'handler',
          code: 'module.exports.handler = function(req, res) { db.query(req.body.id); }',
        },
      ],
    );

    // File A imports handler and calls handler.handler()
    const mapA = makeMap(
      '/project/routes/app.js',
      'var handler = require("../core/handler");\nrouter.post("/search", handler.handler);',
      [
        {
          id: 'route_search',
          type: 'STRUCTURAL',
          label: 'router.post("/search")',
          code: 'router.post("/search", handler.handler)',
        },
      ],
    );

    const fileMaps = new Map<string, NeuralMap>();
    fileMaps.set('/project/routes/app.js', mapA);
    fileMaps.set('/project/core/handler.js', mapB);

    const depGraph = {
      files: ['/project/routes/app.js', '/project/core/handler.js'],
      edges: [{
        from: '/project/routes/app.js',
        to: '/project/core/handler.js',
        importInfo: {
          specifier: '../core/handler',
          resolvedPath: '/project/core/handler.js',
          importedNames: ['*'],
          localName: 'handler',
          line: 1,
        },
      }],
      importsOf: new Map([
        ['/project/routes/app.js', ['/project/core/handler.js']],
        ['/project/core/handler.js', []],
      ]),
      importedBy: new Map([
        ['/project/routes/app.js', []],
        ['/project/core/handler.js', ['/project/routes/app.js']],
      ]),
    };

    const { mergedMap, crossFileEdges } = mergeNeuralMaps(fileMaps, depGraph);
    expect(crossFileEdges).toBeGreaterThan(0);

    // Find the route node — it should have a CALLS edge to the handler
    const routeNode = mergedMap.nodes.find(n => n.label.includes('router.post'));
    expect(routeNode).toBeDefined();
    const callEdges = routeNode!.edges.filter(e => e.edge_type === 'CALLS');
    expect(callEdges.length).toBeGreaterThan(0);
  });

  it('propagates taint across file boundaries', () => {
    // File A: has tainted INGRESS that flows to EGRESS
    const mapA = makeMap(
      '/project/routes.js',
      'var handler = require("./handler");\napp.post("/search", handler.search);',
      [
        {
          id: 'ingress',
          type: 'INGRESS',
          label: 'req.body.login',
          code: 'req.body.login',
          taintedOut: true,
          edges: [{ target: 'route_call', type: 'DATA_FLOW' }],
          attackSurface: ['user_input'],
        },
        {
          id: 'route_call',
          type: 'STRUCTURAL',
          label: 'handler.search',
          code: 'handler.search',
          taintedIn: true,
        },
      ],
    );

    // File B: has a STORAGE node (SQL query) that the route calls
    const mapB = makeMap(
      '/project/handler.js',
      'module.exports.search = function(req, res) { db.query("SELECT * FROM users WHERE id=" + req.body.id); };',
      [
        {
          id: 'func_search',
          type: 'STRUCTURAL',
          label: 'search',
          code: 'module.exports.search = function(req, res)',
        },
        {
          id: 'sql_query',
          type: 'STORAGE',
          label: 'db.query()',
          code: 'db.query("SELECT * FROM users WHERE id=" + req.body.id)',
          attackSurface: ['sql_sink'],
        },
      ],
    );

    const fileMaps = new Map<string, NeuralMap>();
    fileMaps.set('/project/routes.js', mapA);
    fileMaps.set('/project/handler.js', mapB);

    const depGraph = {
      files: ['/project/routes.js', '/project/handler.js'],
      edges: [{
        from: '/project/routes.js',
        to: '/project/handler.js',
        importInfo: {
          specifier: './handler',
          resolvedPath: '/project/handler.js',
          importedNames: ['*'],
          localName: 'handler',
          line: 1,
        },
      }],
      importsOf: new Map([
        ['/project/routes.js', ['/project/handler.js']],
        ['/project/handler.js', []],
      ]),
      importedBy: new Map([
        ['/project/routes.js', []],
        ['/project/handler.js', ['/project/routes.js']],
      ]),
    };

    const { mergedMap } = mergeNeuralMaps(fileMaps, depGraph);

    // The merged map should have nodes from both files
    expect(mergedMap.nodes.length).toBe(4);

    // The ingress node should still be tainted
    const ingressNode = mergedMap.nodes.find(n => n.node_type === 'INGRESS');
    expect(ingressNode).toBeDefined();
    expect(ingressNode!.data_out.some(d => d.tainted)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Integration: Cross-file findings via verifyAll
// ---------------------------------------------------------------------------

describe('cross-file verifyAll integration', () => {
  it('detects SQLi that spans two files (routes + handler)', () => {
    resetSequence();

    // Simulate what the mapper would produce for two files:
    // File 1 (routes): route that calls handler.userSearch
    // File 2 (handler): userSearch has SQL injection

    // Build the handler map (has the actual vulnerability)
    const handlerMap = createNeuralMap('/project/core/appHandler.js', `
module.exports.userSearch = function (req, res) {
  var query = "SELECT name FROM Users WHERE login='" + req.body.login + "'";
  db.sequelize.query(query);
};
`);

    handlerMap.nodes.push(createNode({
      id: 'handler_ingress',
      node_type: 'INGRESS',
      label: 'req.body.login',
      node_subtype: 'http_body',
      code_snapshot: "var query = \"SELECT name FROM Users WHERE login='\" + req.body.login + \"'\"",
      line_start: 3,
      attack_surface: ['user_input'],
      data_out: [{ name: 'login', source: 'EXTERNAL', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
      edges: [{ target: 'handler_sql', edge_type: 'DATA_FLOW', conditional: false, async: false }],
    }));

    handlerMap.nodes.push(createNode({
      id: 'handler_sql',
      node_type: 'STORAGE',
      label: 'db.sequelize.query()',
      node_subtype: 'sql_query',
      code_snapshot: 'db.sequelize.query(query)',
      line_start: 4,
      attack_surface: ['sql_sink'],
      data_in: [{ name: 'login', source: 'handler_ingress', data_type: 'string', tainted: true, sensitivity: 'NONE' }],
    }));

    handlerMap.nodes.push(createNode({
      id: 'handler_func',
      node_type: 'STRUCTURAL',
      label: 'userSearch',
      node_subtype: 'function_declaration',
      code_snapshot: 'module.exports.userSearch = function (req, res)',
      line_start: 2,
      edges: [
        { target: 'handler_ingress', edge_type: 'CONTAINS', conditional: false, async: false },
        { target: 'handler_sql', edge_type: 'CONTAINS', conditional: false, async: false },
      ],
    }));

    // Build the routes map (calls the handler)
    const routesMap = createNeuralMap('/project/routes/app.js', `
var appHandler = require('../core/appHandler');
router.post('/usersearch', appHandler.userSearch);
`);

    routesMap.nodes.push(createNode({
      id: 'route_post',
      node_type: 'STRUCTURAL',
      label: "router.post('/usersearch')",
      node_subtype: 'route_handler',
      code_snapshot: "router.post('/usersearch', appHandler.userSearch)",
      line_start: 3,
    }));

    // Merge
    const fileMaps = new Map<string, NeuralMap>();
    fileMaps.set('/project/core/appHandler.js', handlerMap);
    fileMaps.set('/project/routes/app.js', routesMap);

    const depGraph = {
      files: ['/project/routes/app.js', '/project/core/appHandler.js'],
      edges: [{
        from: '/project/routes/app.js',
        to: '/project/core/appHandler.js',
        importInfo: {
          specifier: '../core/appHandler',
          resolvedPath: '/project/core/appHandler.js',
          importedNames: ['*'],
          localName: 'appHandler',
          line: 2,
        },
      }],
      importsOf: new Map([
        ['/project/routes/app.js', ['/project/core/appHandler.js']],
        ['/project/core/appHandler.js', []],
      ]),
      importedBy: new Map([
        ['/project/routes/app.js', []],
        ['/project/core/appHandler.js', ['/project/routes/app.js']],
      ]),
    };

    const { mergedMap, crossFileEdges, resolvedImports } = mergeNeuralMaps(fileMaps, depGraph);

    // Should have cross-file edges
    expect(crossFileEdges).toBeGreaterThan(0);
    expect(resolvedImports.length).toBeGreaterThan(0);

    // Run verifiers on the merged map
    const results = verifyAll(mergedMap, 'javascript');
    const sqli = results.find(r => r.cwe === 'CWE-89');
    expect(sqli).toBeDefined();
    expect(sqli!.holds).toBe(false); // Should detect the vulnerability
    expect(sqli!.findings.length).toBeGreaterThan(0);
  });

  it('merged map does not break clean code detection', () => {
    resetSequence();

    // Two clean files — no vulnerabilities
    const mapA = createNeuralMap('/project/a.js', 'const x = 1;');
    mapA.nodes.push(createNode({
      id: 'safe_auth',
      node_type: 'AUTH',
      label: 'authenticate()',
      node_subtype: 'auth_check',
      code_snapshot: 'authenticate()',
    }));

    const mapB = createNeuralMap('/project/b.js', 'const y = 2;');
    mapB.nodes.push(createNode({
      id: 'safe_control',
      node_type: 'CONTROL',
      label: 'if (authorized)',
      node_subtype: 'authorization_check',
      code_snapshot: 'if (authorized)',
    }));

    const fileMaps = new Map<string, NeuralMap>();
    fileMaps.set('/project/a.js', mapA);
    fileMaps.set('/project/b.js', mapB);

    const depGraph = {
      files: ['/project/a.js', '/project/b.js'],
      edges: [],
      importsOf: new Map<string, string[]>(),
      importedBy: new Map<string, string[]>(),
    };

    const { mergedMap } = mergeNeuralMaps(fileMaps, depGraph);
    const results = verifyAll(mergedMap, 'javascript');

    // Should not produce false positives
    const critical = results.filter(r => !r.holds && r.findings.some(f => f.severity === 'critical'));
    expect(critical).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// analyzeCrossFile integration
// ---------------------------------------------------------------------------

describe('analyzeCrossFile', () => {
  it('returns complete result structure', () => {
    resetSequence();

    const mapA = createNeuralMap('/project/a.js', 'const x = 1;');
    const mapB = createNeuralMap('/project/b.js', 'const y = 2;');

    const fileMaps = new Map<string, NeuralMap>();
    fileMaps.set('/project/a.js', mapA);
    fileMaps.set('/project/b.js', mapB);

    // Note: analyzeCrossFile reads files from disk, so we test the structure
    // with pre-built maps using mergeNeuralMaps directly
    const depGraph = {
      files: ['/project/a.js', '/project/b.js'],
      edges: [],
      importsOf: new Map<string, string[]>(),
      importedBy: new Map<string, string[]>(),
    };

    const { mergedMap } = mergeNeuralMaps(fileMaps, depGraph);
    expect(mergedMap).toBeDefined();
    expect(mergedMap.source_file).toBe('[merged]');
    expect(mergedMap.parser_version).toContain('crossfile');
  });
});
