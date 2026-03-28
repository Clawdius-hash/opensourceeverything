/**
 * DST Verification CLI — point at code, get a deterministic security report.
 *
 * This is the real pipeline: tree-sitter parse → Neural Map → 40 CWE verifiers.
 * No regex shortcuts. No confidence scores. Pass or fail.
 *
 * Usage:
 *   npx tsx src/services/dst/dst-cli.ts <file.js>        # scan a file
 *   npx tsx src/services/dst/dst-cli.ts --demo            # run against built-in vulnerable app
 *   npx tsx src/services/dst/dst-cli.ts --demo --json     # output as JSON
 *   npx tsx src/services/dst/dst-cli.ts <file.js> --json  # scan file, output JSON
 */

import { Parser, Language } from 'web-tree-sitter';
import { verifyAll, formatReport, registeredCWEs } from './verifier';
import { buildNeuralMap } from './mapper';
import { resetSequence } from './types';
import type { NeuralMap } from './types';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Node.js tree-sitter parser (loads WASM from filesystem, not HTTP)
// ---------------------------------------------------------------------------

let _parser: InstanceType<typeof Parser> | null = null;

async function getNodeParser(): Promise<InstanceType<typeof Parser>> {
  if (_parser) return _parser;

  await Parser.init();
  _parser = new Parser();

  // Load the JavaScript grammar WASM from node_modules
  const wasmPath = path.resolve(
    __dirname,
    '../../../node_modules/tree-sitter-javascript/tree-sitter-javascript.wasm'
  );

  if (!fs.existsSync(wasmPath)) {
    console.error(
      'tree-sitter-javascript WASM not found at:\n  ' + wasmPath + '\n\n' +
      'Run: npm install tree-sitter-javascript'
    );
    process.exit(1);
  }

  const wasmBuffer = fs.readFileSync(wasmPath);
  const JavaScript = await Language.load(wasmBuffer);
  _parser.setLanguage(JavaScript);

  return _parser;
}

/**
 * Parse JavaScript source and build a NeuralMap using the real mapper pipeline.
 *
 * tree-sitter CST → scope-aware walk → classified nodes → data flow edges → taint init
 */
async function analyzeWithRealMapper(source: string, filename: string): Promise<NeuralMap> {
  const parser = await getNodeParser();
  const tree = parser.parse(source);

  if (!tree) {
    console.error('tree-sitter failed to parse: ' + filename);
    process.exit(1);
  }

  resetSequence();
  const { map } = buildNeuralMap(tree, source, filename);

  tree.delete(); // free WASM memory

  return map;
}

// ---------------------------------------------------------------------------
// Report formatting
// ---------------------------------------------------------------------------

function printHeader(mode: string): void {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║          DST VERIFICATION ENGINE v0.2                   ║');
  console.log('║   Deterministic Security Testing — 40 CWE Properties   ║');
  console.log('║   tree-sitter Neural Map → Graph Query → Pass/Fail     ║');
  console.log('╠══════════════════════════════════════════════════════════╣');
  console.log(`║   Mode: ${mode.padEnd(47)}║`);
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log('');
}

function printMapStats(map: NeuralMap): void {
  const typeCounts: Record<string, number> = {};
  for (const node of map.nodes) {
    typeCounts[node.node_type] = (typeCounts[node.node_type] ?? 0) + 1;
  }

  const edgeTypeCounts: Record<string, number> = {};
  for (const edge of map.edges) {
    edgeTypeCounts[edge.edge_type] = (edgeTypeCounts[edge.edge_type] ?? 0) + 1;
  }

  const taintedFlows = map.nodes.reduce((count, n) => {
    return count + n.data_in.filter(d => d.tainted).length +
                   n.data_out.filter(d => d.tainted).length;
  }, 0);

  console.log(`Neural Map: ${map.nodes.length} nodes, ${map.edges.length} edges`);
  console.log(`  Nodes by type: ${Object.entries(typeCounts).map(([t, c]) => `${t}(${c})`).join(', ')}`);
  if (Object.keys(edgeTypeCounts).length > 0) {
    console.log(`  Edges by type: ${Object.entries(edgeTypeCounts).map(([t, c]) => `${t}(${c})`).join(', ')}`);
  }
  console.log(`  Tainted data flows: ${taintedFlows}`);
  console.log(`  CWE properties to check: ${registeredCWEs().length}`);
  console.log('');
}

// ---------------------------------------------------------------------------
// Demo vulnerable app (same one Atreus used for the E2E test)
// ---------------------------------------------------------------------------

const DEMO_CODE = `
const express = require('express');
const db = require('./db');
const fetch = require('node-fetch');
const { exec } = require('child_process');
const app = express();

// SQL Injection — string concatenation
app.post('/users/search', (req, res) => {
  var query = "SELECT name FROM Users WHERE login='" + req.body.login + "'";
  db.query(query, (err, results) => {
    res.render('search', { results: results });
  });
});

// XSS — reflected user input
app.get('/welcome', (req, res) => {
  res.send('<h1>Welcome, ' + req.query.name + '!</h1>');
});

// SSRF — user-controlled URL
app.get('/proxy', (req, res) => {
  fetch(req.query.url)
    .then(r => r.text())
    .then(body => res.send(body));
});

// Command injection
app.get('/convert', (req, res) => {
  exec("ffmpeg -i " + req.query.file + " output.mp4");
});

// Hardcoded credentials
const dbConfig = {
  host: "localhost",
  password: "SuperSecretPassword123",
  api_key: "sk_live_abc123def456"
};

// Missing auth on delete
app.delete('/users/:id', (req, res) => {
  db.query("DELETE FROM users WHERE id = " + req.params.id);
  res.json({ deleted: true });
});

app.listen(3000);
`;

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Directory scanning — find all JS files recursively
// ---------------------------------------------------------------------------

function collectJsFiles(dir: string): string[] {
  const files: string[] = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    // Skip common non-source directories
    if (entry.isDirectory()) {
      if (['node_modules', '.git', 'dist', 'build', 'coverage', '.next', '__pycache__'].includes(entry.name)) {
        continue;
      }
      files.push(...collectJsFiles(fullPath));
    } else if (entry.isFile() && /\.(js|mjs|cjs)$/.test(entry.name)) {
      // Skip test files, config files, and minified bundles
      if (entry.name.includes('.test.') || entry.name.includes('.spec.') ||
          entry.name.includes('.min.') || entry.name.includes('.bundle.')) {
        continue;
      }
      files.push(fullPath);
    }
  }

  return files;
}

// ---------------------------------------------------------------------------
// Report printing helpers
// ---------------------------------------------------------------------------

interface FileResult {
  filename: string;
  map: NeuralMap;
  results: ReturnType<typeof verifyAll>;
}

function printFileReport(fr: FileResult): void {
  const failed = fr.results.filter(r => !r.holds);
  if (failed.length === 0) return; // only print files with findings

  console.log(`\n${'━'.repeat(60)}`);
  console.log(`  ${fr.filename}`);
  console.log(`  ${fr.map.nodes.length} nodes, ${fr.map.edges.length} edges`);
  console.log(`${'━'.repeat(60)}`);

  for (const r of failed) {
    for (const f of r.findings) {
      const icon = f.severity === 'critical' ? '!!!' :
                   f.severity === 'high' ? ' !!' :
                   f.severity === 'medium' ? '  !' : '   ';
      console.log(`  ${icon} ${r.cwe}: ${r.name}`);
      console.log(`      ${f.description.slice(0, 120)}`);
      console.log(`      L${f.source.line}: ${f.source.code.slice(0, 80)}`);
      console.log('');
    }
  }
}

function printSummary(allResults: FileResult[], elapsed: number): void {
  const totalNodes = allResults.reduce((s, r) => s + r.map.nodes.length, 0);
  const totalEdges = allResults.reduce((s, r) => s + r.map.edges.length, 0);

  let totalFindings = 0;
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  const cweHits = new Map<string, number>();

  for (const fr of allResults) {
    for (const r of fr.results) {
      if (!r.holds) {
        for (const f of r.findings) {
          totalFindings++;
          if (f.severity === 'critical') criticalCount++;
          else if (f.severity === 'high') highCount++;
          else mediumCount++;
          cweHits.set(r.cwe, (cweHits.get(r.cwe) ?? 0) + 1);
        }
      }
    }
  }

  const cleanFiles = allResults.filter(fr => fr.results.every(r => r.holds)).length;

  console.log('');
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║                    SCAN COMPLETE                        ║');
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log('');
  console.log(`  Files scanned:  ${allResults.length}`);
  console.log(`  Clean files:    ${cleanFiles}`);
  console.log(`  Total nodes:    ${totalNodes}`);
  console.log(`  Total edges:    ${totalEdges}`);
  console.log(`  Time:           ${elapsed}ms`);
  console.log('');

  if (totalFindings === 0) {
    console.log('  No findings. All 40 CWE properties verified clean across all files.');
  } else {
    console.log(`  ${totalFindings} finding(s):`);
    if (criticalCount > 0) console.log(`    ${criticalCount} CRITICAL`);
    if (highCount > 0) console.log(`    ${highCount} HIGH`);
    if (mediumCount > 0) console.log(`    ${mediumCount} MEDIUM`);
    console.log('');

    // Top CWEs hit
    const sorted = [...cweHits.entries()].sort((a, b) => b[1] - a[1]);
    console.log('  Most common:');
    for (const [cwe, count] of sorted.slice(0, 5)) {
      console.log(`    ${cwe}: ${count} occurrence(s)`);
    }
  }

  console.log('');
  console.log('─'.repeat(50));
  console.log('  Deterministic: same code → same report. Always.');
  console.log('─'.repeat(50));
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const jsonOutput = args.includes('--json');
  const target = args.find(a => !a.startsWith('--'));
  const isDemo = args.includes('--demo') || !target;

  const startTime = Date.now();

  if (isDemo) {
    // Single file demo mode
    printHeader('DEMO — vulnerable Express app');
    console.log('Parsing with tree-sitter → building Neural Map...');
    console.log('');

    const map = await analyzeWithRealMapper(DEMO_CODE, 'demo-vulnerable-app.js');
    printMapStats(map);

    const results = verifyAll(map);

    if (jsonOutput) {
      console.log(JSON.stringify(results, null, 2));
    } else {
      console.log(formatReport(results));

      const failed = results.filter(r => !r.holds);
      const criticals = failed.filter(r => r.findings.some(f => f.severity === 'critical'));
      const highs = failed.filter(r => r.findings.some(f => f.severity === 'high'));
      const totalFindings = failed.reduce((sum, r) => sum + r.findings.length, 0);

      console.log('');
      console.log('─'.repeat(50));
      console.log(`  ${totalFindings} finding(s) across ${failed.length} failed properties`);
      if (criticals.length > 0) console.log(`  ${criticals.length} CRITICAL`);
      if (highs.length > 0) console.log(`  ${highs.length} HIGH`);
      console.log(`  ${results.length - failed.length}/${results.length} properties verified clean`);
      console.log('─'.repeat(50));
      console.log('');
      console.log('Deterministic: same code → same report. Always.');
    }
    return;
  }

  // Check if target is a file or directory
  const stat = fs.statSync(target!);

  if (stat.isFile()) {
    // Single file mode
    const source = fs.readFileSync(target!, 'utf-8');
    printHeader(target!);
    console.log('Parsing with tree-sitter → building Neural Map...');
    console.log('');

    const map = await analyzeWithRealMapper(source, target!);
    printMapStats(map);

    const results = verifyAll(map);

    if (jsonOutput) {
      console.log(JSON.stringify(results, null, 2));
    } else {
      console.log(formatReport(results));

      const failed = results.filter(r => !r.holds);
      const totalFindings = failed.reduce((sum, r) => sum + r.findings.length, 0);
      const criticals = failed.filter(r => r.findings.some(f => f.severity === 'critical'));
      const highs = failed.filter(r => r.findings.some(f => f.severity === 'high'));

      console.log('');
      console.log('─'.repeat(50));
      console.log(`  ${totalFindings} finding(s) across ${failed.length} failed properties`);
      if (criticals.length > 0) console.log(`  ${criticals.length} CRITICAL`);
      if (highs.length > 0) console.log(`  ${highs.length} HIGH`);
      console.log(`  ${results.length - failed.length}/${results.length} properties verified clean`);
      console.log('─'.repeat(50));
      console.log('');
      console.log('Deterministic: same code → same report. Always.');
    }
  } else if (stat.isDirectory()) {
    // Directory scan mode
    const files = collectJsFiles(target!);

    if (files.length === 0) {
      console.error(`No .js files found in: ${target}`);
      process.exit(1);
    }

    printHeader(`SCAN: ${target} (${files.length} files)`);
    console.log('Scanning with tree-sitter → building Neural Maps...');
    console.log('');

    const allResults: FileResult[] = [];
    let scanned = 0;

    for (const file of files) {
      scanned++;
      const shortName = path.relative(target!, file);
      process.stdout.write(`  [${scanned}/${files.length}] ${shortName}...`);

      try {
        const source = fs.readFileSync(file, 'utf-8');
        const map = await analyzeWithRealMapper(source, file);
        const results = verifyAll(map);
        const findings = results.filter(r => !r.holds).reduce((s, r) => s + r.findings.length, 0);

        allResults.push({ filename: shortName, map, results });

        if (findings > 0) {
          console.log(` ${findings} finding(s)`);
        } else {
          console.log(' clean');
        }
      } catch (err) {
        console.log(` ERROR: ${(err as Error).message?.slice(0, 60)}`);
      }
    }

    if (jsonOutput) {
      const jsonResults = allResults.map(fr => ({
        file: fr.filename,
        nodes: fr.map.nodes.length,
        results: fr.results,
      }));
      console.log(JSON.stringify(jsonResults, null, 2));
    } else {
      // Print per-file findings
      for (const fr of allResults) {
        printFileReport(fr);
      }

      // Print overall summary
      printSummary(allResults, Date.now() - startTime);
    }
  }
}

main().catch(err => {
  console.error('DST CLI error:', err);
  process.exit(1);
});
