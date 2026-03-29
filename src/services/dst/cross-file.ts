/**
 * Cross-file analysis for DST — resolves imports between files and merges
 * NeuralMaps so taint flows across module boundaries.
 *
 * Phase 5 of the phoneme mapper: the biggest detection rate multiplier remaining.
 *
 * What this does:
 *   1. Import Resolver — parses require() and import statements to build a
 *      dependency graph between files in a scanned directory.
 *   2. NeuralMap Merger — takes per-file NeuralMaps and merges them into a
 *      single combined map with cross-file CALLS and DATA_FLOW edges.
 *   3. Cross-file taint propagation — when File A exports a function that
 *      takes user input, and File B imports and calls it, the taint propagates.
 *
 * The merged map is ADDITIONAL to per-file maps, not a replacement.
 */

import * as fs from 'fs';
import * as path from 'path';
import type { NeuralMap, NeuralMapNode, Edge } from './types.js';
import { createNode, createNeuralMap, nextGeneration } from './types.js';

// ---------------------------------------------------------------------------
// Import Resolver — find what each file requires/imports
// ---------------------------------------------------------------------------

export interface ImportInfo {
  /** The raw import specifier as written in code (e.g., '../core/appHandler') */
  specifier: string;
  /** Resolved absolute file path on disk (null if external/npm package) */
  resolvedPath: string | null;
  /** What names are imported (e.g., ['userSearch', 'ping'] or ['*'] for whole module) */
  importedNames: string[];
  /** The local binding name (e.g., 'appHandler' for `var appHandler = require(...)`) */
  localName: string | null;
  /** Line number where the import appears */
  line: number;
}

export interface FileImports {
  /** Absolute path of the importing file */
  filePath: string;
  /** All imports found in this file */
  imports: ImportInfo[];
}

export interface ExportInfo {
  /** Name of the exported symbol (e.g., 'userSearch', 'default') */
  name: string;
  /** Node IDs in the NeuralMap that correspond to this export */
  nodeIds: string[];
  /** Whether this is a module.exports assignment vs named export */
  isDefault: boolean;
}

export interface FileExports {
  /** Absolute path of the exporting file */
  filePath: string;
  /** All exports found in this file */
  exports: ExportInfo[];
}

export interface DependencyEdge {
  /** Importing file (absolute path) */
  from: string;
  /** Imported file (absolute path) */
  to: string;
  /** Import details */
  importInfo: ImportInfo;
}

export interface DependencyGraph {
  /** All files in the graph */
  files: string[];
  /** Edges: from imports to */
  edges: DependencyEdge[];
  /** Quick lookup: file -> files it imports */
  importsOf: Map<string, string[]>;
  /** Quick lookup: file -> files that import it */
  importedBy: Map<string, string[]>;
}

// ---------------------------------------------------------------------------
// Regex-based import extraction (works on raw source, no AST needed)
// ---------------------------------------------------------------------------

/**
 * Extract require() and import statements from JavaScript/TypeScript source.
 * Returns raw specifiers — resolution to file paths happens separately.
 */
export function extractImports(source: string, filePath: string): ImportInfo[] {
  const imports: ImportInfo[] = [];
  const lines = source.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // Destructured require MUST be checked before simple require
    // const { X, Y } = require('...')
    const destructuredRequire = line.match(
      /(?:var|let|const)\s*\{([^}]+)\}\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)/
    );
    if (destructuredRequire) {
      const names = destructuredRequire[1].split(',').map(n => n.trim()).filter(n => n.length > 0);
      imports.push({
        specifier: destructuredRequire[2],
        resolvedPath: null,
        importedNames: names,
        localName: null,
        line: lineNum,
      });
      continue;
    }

    // CommonJS: var/let/const X = require('...')
    // Also handles: var X = require('..').Y (e.g., require('express').Router())
    const cjsMatch = line.match(
      /(?:var|let|const)\s+(\w+)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)/
    );
    if (cjsMatch) {
      imports.push({
        specifier: cjsMatch[2],
        resolvedPath: null, // resolved later
        importedNames: ['*'],
        localName: cjsMatch[1],
        line: lineNum,
      });
      continue;
    }

    // CommonJS: require('..') without assignment (side-effect require)
    // e.g., require('./core/passport')(passport)
    const sideEffectRequire = line.match(
      /require\s*\(\s*['"]([^'"]+)['"]\s*\)/
    );
    if (sideEffectRequire && !cjsMatch) {
      imports.push({
        specifier: sideEffectRequire[1],
        resolvedPath: null,
        importedNames: ['*'],
        localName: null,
        line: lineNum,
      });
      continue;
    }

    // ES Module: import X from '...'
    const esDefaultMatch = line.match(
      /import\s+(\w+)\s+from\s+['"]([^'"]+)['"]/
    );
    if (esDefaultMatch) {
      imports.push({
        specifier: esDefaultMatch[2],
        resolvedPath: null,
        importedNames: ['default'],
        localName: esDefaultMatch[1],
        line: lineNum,
      });
      continue;
    }

    // ES Module: import { X, Y } from '...'
    const esNamedMatch = line.match(
      /import\s*\{([^}]+)\}\s*from\s+['"]([^'"]+)['"]/
    );
    if (esNamedMatch) {
      const names = esNamedMatch[1].split(',').map(n => {
        const parts = n.trim().split(/\s+as\s+/);
        return parts[0].trim();
      }).filter(n => n.length > 0);
      imports.push({
        specifier: esNamedMatch[2],
        resolvedPath: null,
        importedNames: names,
        localName: null,
        line: lineNum,
      });
      continue;
    }

    // ES Module: import * as X from '...'
    const esStarMatch = line.match(
      /import\s+\*\s+as\s+(\w+)\s+from\s+['"]([^'"]+)['"]/
    );
    if (esStarMatch) {
      imports.push({
        specifier: esStarMatch[2],
        resolvedPath: null,
        importedNames: ['*'],
        localName: esStarMatch[1],
        line: lineNum,
      });
      continue;
    }

    // (destructured require is handled at top of loop)
  }

  return imports;
}

/**
 * Extract module.exports and named exports from JavaScript source.
 * Returns export names that can be matched to NeuralMap nodes.
 */
export function extractExports(source: string): string[] {
  const exports: string[] = [];
  const lines = source.split('\n');

  for (const line of lines) {
    // module.exports.name = function
    const namedExport = line.match(/module\.exports\.(\w+)\s*=/);
    if (namedExport) {
      exports.push(namedExport[1]);
      continue;
    }

    // exports.name = function
    const shortExport = line.match(/(?<!\w)exports\.(\w+)\s*=/);
    if (shortExport) {
      exports.push(shortExport[1]);
      continue;
    }

    // ES Module: export function name
    const esFuncExport = line.match(/export\s+(?:default\s+)?function\s+(\w+)/);
    if (esFuncExport) {
      exports.push(esFuncExport[1]);
      continue;
    }

    // ES Module: export const/let/var name
    const esVarExport = line.match(/export\s+(?:const|let|var)\s+(\w+)/);
    if (esVarExport) {
      exports.push(esVarExport[1]);
      continue;
    }

    // module.exports = { ... } (object literal)
    const moduleExportsObj = line.match(/module\.exports\s*=\s*\{/);
    if (moduleExportsObj) {
      // Grab the whole object (may span lines, simplified: grab until closing brace)
      const restOfFile = lines.slice(lines.indexOf(line)).join('\n');
      const objMatch = restOfFile.match(/module\.exports\s*=\s*\{([^}]+)\}/);
      if (objMatch) {
        const props = objMatch[1].split(',').map(p => {
          const key = p.trim().split(/\s*[:=]/)[0].trim();
          return key;
        }).filter(k => k.length > 0 && /^\w+$/.test(k));
        exports.push(...props);
      }
      continue;
    }
  }

  return [...new Set(exports)];
}

// ---------------------------------------------------------------------------
// File path resolution — require('./db') -> /abs/path/to/db.js
// ---------------------------------------------------------------------------

const JS_EXTENSIONS = ['.js', '.mjs', '.cjs', '.ts', '.jsx', '.tsx'];

/**
 * Resolve a require/import specifier to an absolute file path.
 * Only resolves relative paths (starts with . or ..).
 * Returns null for npm packages.
 */
export function resolveImportPath(
  specifier: string,
  importingFile: string,
  allFiles: string[],
): string | null {
  // Skip npm packages
  if (!specifier.startsWith('.') && !specifier.startsWith('/')) {
    return null;
  }

  // Normalize everything to forward slashes for cross-platform consistency
  const normalizedImporting = importingFile.replace(/\\/g, '/');
  const dir = path.posix.dirname(normalizedImporting);

  // Use posix join to avoid Windows drive letter injection
  // path.posix.resolve needs an absolute path, so we use join + normalize
  const joined = path.posix.join(dir, specifier);
  // Normalize away any .. or . segments
  const normalizedResolved = path.posix.normalize(joined);

  // Build a set of normalized file paths for quick lookup
  const fileSet = new Set(allFiles.map(f => f.replace(/\\/g, '/')));

  // Try exact match first
  if (fileSet.has(normalizedResolved)) {
    return normalizedResolved;
  }

  // Try with extensions
  for (const ext of JS_EXTENSIONS) {
    const withExt = normalizedResolved + ext;
    if (fileSet.has(withExt)) {
      return withExt;
    }
  }

  // Try as directory with index file
  for (const ext of JS_EXTENSIONS) {
    const indexFile = normalizedResolved + '/index' + ext;
    if (fileSet.has(indexFile)) {
      return indexFile;
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// Dependency Graph Builder
// ---------------------------------------------------------------------------

/**
 * Build a dependency graph from a set of files.
 * Reads each file, extracts imports, resolves paths.
 */
export function buildDependencyGraph(files: string[]): DependencyGraph {
  const edges: DependencyEdge[] = [];
  const importsOf = new Map<string, string[]>();
  const importedBy = new Map<string, string[]>();
  const normalizedFiles = files.map(f => f.replace(/\\/g, '/'));

  for (const file of normalizedFiles) {
    importsOf.set(file, []);
    importedBy.set(file, []);
  }

  for (const file of normalizedFiles) {
    let source: string;
    try {
      source = fs.readFileSync(file, 'utf-8');
    } catch {
      continue;
    }

    const imports = extractImports(source, file);

    for (const imp of imports) {
      const resolvedPath = resolveImportPath(imp.specifier, file, normalizedFiles);
      imp.resolvedPath = resolvedPath;

      if (resolvedPath) {
        edges.push({ from: file, to: resolvedPath, importInfo: imp });
        importsOf.get(file)?.push(resolvedPath);
        importedBy.get(resolvedPath)?.push(file);
      }
    }
  }

  return {
    files: normalizedFiles,
    edges,
    importsOf,
    importedBy,
  };
}

// ---------------------------------------------------------------------------
// NeuralMap Merger — combine per-file maps into a cross-file map
// ---------------------------------------------------------------------------

export interface MergedMapResult {
  /** The merged NeuralMap containing all nodes + cross-file edges */
  mergedMap: NeuralMap;
  /** Number of cross-file edges added */
  crossFileEdges: number;
  /** Import relationships that were resolved */
  resolvedImports: Array<{ from: string; to: string; symbols: string[] }>;
}

/**
 * Merge multiple NeuralMaps into a single map with cross-file edges.
 *
 * Steps:
 *   1. Collect all nodes from all maps (prefix IDs to avoid collision)
 *   2. Build export registry: for each file, which nodes are exports
 *   3. Build import registry: for each file, what does it import
 *   4. Create CALLS edges between import sites and exported functions
 *   5. Propagate taint across file boundaries
 */
export function mergeNeuralMaps(
  fileMaps: Map<string, NeuralMap>,
  depGraph: DependencyGraph,
): MergedMapResult {
  nextGeneration();

  const allNodes: NeuralMapNode[] = [];
  const allEdges: Edge[] = [];
  const allSourceParts: string[] = [];
  let crossFileEdgeCount = 0;
  const resolvedImports: Array<{ from: string; to: string; symbols: string[] }> = [];

  // Track node ID mappings: original ID -> prefixed ID (per file)
  const idMap = new Map<string, string>();

  // Step 1: Collect all nodes, prefixing IDs to avoid collision
  for (const [filePath, map] of fileMaps) {
    const prefix = makeFilePrefix(filePath);
    allSourceParts.push(`// === ${filePath} ===\n${map.source_code}`);

    for (const node of map.nodes) {
      const newId = `${prefix}::${node.id}`;
      idMap.set(`${filePath}::${node.id}`, newId);

      const clonedNode: NeuralMapNode = {
        ...node,
        id: newId,
        file: filePath,
        // Remap edge targets
        edges: node.edges.map(e => ({
          ...e,
          target: `${prefix}::${e.target}`,
        })),
        // Remap data flow sources
        data_in: node.data_in.map(d => ({
          ...d,
          source: d.source === 'EXTERNAL' ? 'EXTERNAL' : `${prefix}::${d.source}`,
        })),
        data_out: node.data_out.map(d => ({
          ...d,
          source: d.source === 'EXTERNAL' ? 'EXTERNAL' : `${prefix}::${d.source}`,
          target: d.target ? `${prefix}::${d.target}` : undefined,
        })),
      };

      allNodes.push(clonedNode);
    }

    // Also remap top-level edges
    for (const edge of map.edges) {
      allEdges.push({
        ...edge,
        target: `${prefix}::${edge.target}`,
      });
    }
  }

  // Step 2: Build export registry
  // For each file, find which nodes are exported functions
  const exportRegistry = new Map<string, Map<string, string[]>>();

  for (const [filePath, map] of fileMaps) {
    const prefix = makeFilePrefix(filePath);
    const source = map.source_code;
    const exportNames = extractExports(source);
    const exportNodeMap = new Map<string, string[]>();

    for (const exportName of exportNames) {
      // Find nodes in this file's map whose label contains this export name
      const matchingNodeIds: string[] = [];

      for (const node of map.nodes) {
        // Match STRUCTURAL nodes (function declarations) by label
        if (node.node_type === 'STRUCTURAL' &&
            (node.label.includes(exportName) || node.code_snapshot.includes(exportName))) {
          matchingNodeIds.push(`${prefix}::${node.id}`);
        }
      }

      // If no structural match, look for any node referencing the export name
      if (matchingNodeIds.length === 0) {
        for (const node of map.nodes) {
          if (node.label.includes(exportName) || node.code_snapshot.includes(exportName)) {
            matchingNodeIds.push(`${prefix}::${node.id}`);
          }
        }
      }

      if (matchingNodeIds.length > 0) {
        exportNodeMap.set(exportName, matchingNodeIds);
      }
    }

    exportRegistry.set(filePath, exportNodeMap);
  }

  // Step 3: Create cross-file edges based on dependency graph
  for (const edge of depGraph.edges) {
    const fromPrefix = makeFilePrefix(edge.from);
    const toPrefix = makeFilePrefix(edge.to);
    const toExports = exportRegistry.get(edge.to);

    if (!toExports) continue;

    const importInfo = edge.importInfo;
    const symbols: string[] = [];

    if (importInfo.importedNames.includes('*') && importInfo.localName) {
      // Whole-module import (e.g., var appHandler = require('../core/appHandler'))
      // Look for usages of appHandler.X in the importing file's source
      const fromMap = fileMaps.get(edge.from);
      if (!fromMap) continue;

      for (const [exportName, exportNodeIds] of toExports) {
        // Check if the importing file references localName.exportName
        const usagePattern = `${importInfo.localName}.${exportName}`;

        // Find nodes in the importing file that reference this usage
        for (const fromNode of fromMap.nodes) {
          if (fromNode.code_snapshot.includes(usagePattern) ||
              fromNode.label.includes(usagePattern)) {
            // Create CALLS edge from the usage site to the exported function
            for (const exportNodeId of exportNodeIds) {
              const remappedFromId = `${fromPrefix}::${fromNode.id}`;
              const fromNodeInMerged = allNodes.find(n => n.id === remappedFromId);
              if (fromNodeInMerged) {
                fromNodeInMerged.edges.push({
                  target: exportNodeId,
                  edge_type: 'CALLS',
                  conditional: false,
                  async: false,
                });
                crossFileEdgeCount++;
              }
            }
            symbols.push(exportName);
          }
        }
      }
    } else {
      // Named imports — match imported names to exports
      for (const name of importInfo.importedNames) {
        const exportNodeIds = toExports.get(name);
        if (!exportNodeIds) continue;

        // Find where this name is used in the importing file
        const fromMap = fileMaps.get(edge.from);
        if (!fromMap) continue;

        for (const fromNode of fromMap.nodes) {
          if (fromNode.code_snapshot.includes(name) || fromNode.label.includes(name)) {
            for (const exportNodeId of exportNodeIds) {
              const remappedFromId = `${fromPrefix}::${fromNode.id}`;
              const fromNodeInMerged = allNodes.find(n => n.id === remappedFromId);
              if (fromNodeInMerged) {
                fromNodeInMerged.edges.push({
                  target: exportNodeId,
                  edge_type: 'CALLS',
                  conditional: false,
                  async: false,
                });
                crossFileEdgeCount++;
              }
            }
            symbols.push(name);
          }
        }
      }
    }

    if (symbols.length > 0) {
      resolvedImports.push({
        from: edge.from,
        to: edge.to,
        symbols: [...new Set(symbols)],
      });
    }
  }

  // Step 4: Propagate taint across file boundaries
  // When a function in file A has tainted data_in, and file B calls it,
  // propagate the taint to connected nodes
  propagateCrossFileTaint(allNodes);

  // Build the merged map
  const mergedMap: NeuralMap = {
    nodes: allNodes,
    edges: allEdges,
    source_file: '[merged]',
    source_code: allSourceParts.join('\n\n'),
    created_at: new Date().toISOString(),
    parser_version: '0.2.0-crossfile',
  };

  return { mergedMap, crossFileEdges: crossFileEdgeCount, resolvedImports };
}

// ---------------------------------------------------------------------------
// Cross-file taint propagation
// ---------------------------------------------------------------------------

/**
 * Propagate taint across CALLS edges in the merged graph.
 * If node A calls node B, and A has tainted data_out, then B's data_in
 * should be marked tainted too.
 */
function propagateCrossFileTaint(nodes: NeuralMapNode[]): void {
  const nodeById = new Map<string, NeuralMapNode>();
  for (const node of nodes) {
    nodeById.set(node.id, node);
  }

  // BFS taint propagation
  let changed = true;
  let iterations = 0;
  const MAX_ITERATIONS = 10; // prevent infinite loops

  while (changed && iterations < MAX_ITERATIONS) {
    changed = false;
    iterations++;

    for (const node of nodes) {
      // If this node has tainted data, propagate through its edges
      const hasTaintedInput = node.data_in.some(d => d.tainted);
      const hasTaintedOutput = node.data_out.some(d => d.tainted);
      const isIngress = node.node_type === 'INGRESS';

      if (!hasTaintedInput && !hasTaintedOutput && !isIngress) continue;

      for (const edge of node.edges) {
        if (edge.edge_type === 'CALLS' || edge.edge_type === 'DATA_FLOW') {
          const targetNode = nodeById.get(edge.target);
          if (!targetNode) continue;

          // Propagate taint to target's data_in
          const alreadyTainted = targetNode.data_in.some(d => d.tainted);
          if (!alreadyTainted) {
            if (targetNode.data_in.length > 0) {
              // Mark existing data_in as tainted
              for (const dataIn of targetNode.data_in) {
                if (!dataIn.tainted) {
                  dataIn.tainted = true;
                  changed = true;
                }
              }
            } else {
              // Add a tainted data_in entry
              targetNode.data_in.push({
                name: `cross_file_taint_from_${node.id}`,
                source: node.id,
                data_type: 'unknown',
                tainted: true,
                sensitivity: 'NONE',
              });
              changed = true;
            }

            // Also mark attack surface if target is a sink
            if (targetNode.node_type === 'STORAGE' || targetNode.node_type === 'EXTERNAL') {
              if (!targetNode.attack_surface.includes('cross_file_tainted_sink')) {
                targetNode.attack_surface.push('cross_file_tainted_sink');
              }
            }
          }
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Create a short prefix from a file path for namespacing node IDs.
 * e.g., /home/user/project/core/appHandler.js -> core_appHandler
 */
function makeFilePrefix(filePath: string): string {
  const normalized = filePath.replace(/\\/g, '/');
  const parts = normalized.split('/');
  const filename = parts[parts.length - 1].replace(/\.[^.]+$/, '');
  const parent = parts.length >= 2 ? parts[parts.length - 2] : '';
  const prefix = parent ? `${parent}_${filename}` : filename;
  // Sanitize: only alphanumeric and underscore
  return prefix.replace(/[^a-zA-Z0-9_]/g, '_');
}

// ---------------------------------------------------------------------------
// Public API for CLI integration
// ---------------------------------------------------------------------------

export interface CrossFileResult {
  /** The merged NeuralMap */
  mergedMap: NeuralMap;
  /** Dependency graph */
  depGraph: DependencyGraph;
  /** Number of cross-file edges */
  crossFileEdges: number;
  /** Resolved import relationships */
  resolvedImports: Array<{ from: string; to: string; symbols: string[] }>;
}

/**
 * Perform cross-file analysis on a set of file maps.
 * This is the main entry point called from dst-cli.ts.
 *
 * @param fileMaps Map of absolute file path -> NeuralMap (from per-file scanning)
 * @param files List of all files in the scan (for dependency resolution)
 */
export function analyzeCrossFile(
  fileMaps: Map<string, NeuralMap>,
  files: string[],
): CrossFileResult {
  // Build dependency graph
  const depGraph = buildDependencyGraph(files);

  // Merge maps
  const { mergedMap, crossFileEdges, resolvedImports } = mergeNeuralMaps(fileMaps, depGraph);

  return { mergedMap, depGraph, crossFileEdges, resolvedImports };
}
