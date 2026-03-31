/**
 * DST Verification CLI — point at code, get a deterministic security report.
 *
 * This is the real pipeline: tree-sitter parse → Neural Map → CWE verifiers.
 * No regex shortcuts. No confidence scores. Pass or fail.
 *
 * Usage:
 *   npx tsx src/services/dst/dst-cli.ts <file.js>             # scan a file (deduped)
 *   npx tsx src/services/dst/dst-cli.ts --demo                # run against built-in vulnerable app
 *   npx tsx src/services/dst/dst-cli.ts --demo --json         # output as JSON
 *   npx tsx src/services/dst/dst-cli.ts <file.js> --json      # scan file, output JSON
 *   npx tsx src/services/dst/dst-cli.ts <file.js> --no-dedup  # raw output, no CWE dedup
 *   npx tsx src/services/dst/dst-cli.ts <file.js> --pedantic  # include code-quality CWEs
 */

import { Parser, Language } from 'web-tree-sitter';
import { verifyAll, formatReport, registeredCWEs } from './verifier';
import { buildNeuralMap } from './mapper';
import { resetSequence } from './types';
import type { NeuralMap } from './types';
import type { LanguageProfile } from './languageProfile';
import { analyzeCrossFile } from './cross-file';
import type { CrossFileResult } from './cross-file';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Language detection + grammar/profile loading
// ---------------------------------------------------------------------------

interface LanguageConfig {
  grammarPackage: string;  // e.g. 'tree-sitter-python'
  profileImport: string;   // e.g. './profiles/python'
}

const LANGUAGE_MAP: Record<string, LanguageConfig> = {
  '.js':  { grammarPackage: 'tree-sitter-javascript', profileImport: 'javascript' },
  '.mjs': { grammarPackage: 'tree-sitter-javascript', profileImport: 'javascript' },
  '.cjs': { grammarPackage: 'tree-sitter-javascript', profileImport: 'javascript' },
  '.ts':  { grammarPackage: 'tree-sitter-javascript', profileImport: 'javascript' },
  '.py':  { grammarPackage: 'tree-sitter-python',     profileImport: 'python' },
  '.go':  { grammarPackage: 'tree-sitter-go',         profileImport: 'go' },
  '.rs':  { grammarPackage: 'tree-sitter-rust',       profileImport: 'rust' },
  '.java': { grammarPackage: 'tree-sitter-java',      profileImport: 'java' },
  '.php':  { grammarPackage: 'tree-sitter-php',       profileImport: 'php' },
  '.phtml': { grammarPackage: 'tree-sitter-php',      profileImport: 'php' },
  '.rb':   { grammarPackage: 'tree-sitter-ruby',      profileImport: 'ruby' },
  '.rake': { grammarPackage: 'tree-sitter-ruby',      profileImport: 'ruby' },
  '.cs':  { grammarPackage: 'tree-sitter-c-sharp',    profileImport: 'csharp' },
  '.kt':  { grammarPackage: '@tree-sitter-grammars/tree-sitter-kotlin', profileImport: 'kotlin' },
  '.kts': { grammarPackage: '@tree-sitter-grammars/tree-sitter-kotlin', profileImport: 'kotlin' },
  '.swift': { grammarPackage: 'tree-sitter-swift', profileImport: 'swift' },
};

const SCANNABLE_EXTENSIONS = new Set(Object.keys(LANGUAGE_MAP));

function detectLanguage(filename: string): LanguageConfig {
  const ext = path.extname(filename).toLowerCase();
  return LANGUAGE_MAP[ext] ?? LANGUAGE_MAP['.js']; // default to JS
}

// Cache parsers per grammar to avoid reloading WASM
const _parsers = new Map<string, InstanceType<typeof Parser>>();
const _profiles = new Map<string, LanguageProfile>();

async function getParser(grammarPackage: string): Promise<InstanceType<typeof Parser>> {
  if (_parsers.has(grammarPackage)) return _parsers.get(grammarPackage)!;

  await Parser.init();
  const parser = new Parser();

  let wasmPath = path.resolve(
    __dirname,
    `../../../node_modules/${grammarPackage}/${grammarPackage}.wasm`
  );

  // Some grammars use underscores in the WASM filename (e.g. tree-sitter-c_sharp.wasm)
  if (!fs.existsSync(wasmPath)) {
    const underscoreName = grammarPackage.replace(/-/g, '_');
    const altPath = path.resolve(
      __dirname,
      `../../../node_modules/${grammarPackage}/${underscoreName}.wasm`
    );
    if (fs.existsSync(altPath)) {
      wasmPath = altPath;
    }
  }

  // Scoped packages: @org/tree-sitter-foo -> tree-sitter-foo.wasm inside the scoped dir
  if (!fs.existsSync(wasmPath) && grammarPackage.startsWith('@')) {
    const baseName = grammarPackage.split('/').pop()!;
    const scopedPath = path.resolve(
      __dirname,
      `../../../node_modules/${grammarPackage}/${baseName}.wasm`
    );
    if (fs.existsSync(scopedPath)) {
      wasmPath = scopedPath;
    }
  }

  if (!fs.existsSync(wasmPath)) {
    console.error(
      `${grammarPackage} WASM not found at:\n  ${wasmPath}\n\n` +
      `Run: npm install ${grammarPackage}`
    );
    process.exit(1);
  }

  const wasmBuffer = fs.readFileSync(wasmPath);
  const lang = await Language.load(wasmBuffer);
  parser.setLanguage(lang);

  _parsers.set(grammarPackage, parser);
  return parser;
}

async function getProfile(profileName: string): Promise<LanguageProfile> {
  if (_profiles.has(profileName)) return _profiles.get(profileName)!;

  // Dynamic import of the profile
  const mod = await import(`./profiles/${profileName}.js`);
  const profile = mod.default ?? mod[`${profileName}Profile`] ?? mod.profile;
  if (!profile) {
    console.error(`Could not load profile '${profileName}' from ./profiles/${profileName}.js`);
    process.exit(1);
  }

  _profiles.set(profileName, profile);
  return profile;
}

/**
 * Strip TypeScript-specific syntax so tree-sitter-javascript can parse .ts files.
 * Preserves line numbers (replaces annotations with whitespace, not deletion).
 *
 * Handles:
 *   - Variable type annotations:  let x: Foo = ...  →  let x      = ...
 *   - Parameter type annotations: (x: Type, y: Type) → (x       , y       )
 *   - Return type annotations:    ): Type => {       → )          => {
 *   - Type assertions:            x as Type          → x
 *   - Interface/type declarations (whole lines)
 *   - Generic type parameters:    Array<string>      → Array
 *   - Import type:                import type { X }  → (blanked)
 *   - Non-null assertions:        x!.y               → x .y
 */
function stripTypeScriptAnnotations(source: string): string {
  let result = source;

  // Remove `import type` and `import { type X }` lines entirely (replace with blank lines)
  result = result.replace(/^import\s+type\s+.*$/gm, match => ' '.repeat(match.length));

  // Remove `import { type` qualifiers (keep the import, remove 'type' keyword)
  result = result.replace(/\bimport\s*\{[^}]*\}/g, match => {
    return match.replace(/\btype\s+/g, sub => ' '.repeat(sub.length));
  });

  // Remove interface/type alias declarations (whole statements)
  result = result.replace(/^(export\s+)?(interface|type)\s+\w+[\s\S]*?(?=\n(?:export|import|const|let|var|function|class|module|\/\/|\/\*|\n|$))/gm, match => {
    // Replace each char with space, preserve newlines
    return match.replace(/[^\n]/g, ' ');
  });

  // Remove non-null assertions: x! → x  (but not !== or !=)
  result = result.replace(/!(?=\.|\.?\[|\()/g, ' ');

  // Remove `as Type` assertions (but not `as` in destructuring)
  result = result.replace(/\bas\s+[A-Z]\w*(\s*\[?\]?)*/g, match => ' '.repeat(match.length));

  // Remove generic type parameters: Array<string>, Map<K, V>, etc.
  // Only match < > that follow an identifier (not comparison operators)
  result = result.replace(/(?<=\w)<[^<>]*(?:<[^<>]*>[^<>]*)*>/g, match => ' '.repeat(match.length));

  // Remove destructured parameter type annotations:  ({ body }: Type) → ({ body }      )
  // Match } or ] followed by : Type, stopping at , or ) or =
  result = result.replace(/([\]}])\s*:\s*([A-Z]\w*(?:\[\]|\s*\|\s*\w+)*)\s*(?=[,)=])/g, (match, bracket) => {
    return bracket + ' '.repeat(match.length - bracket.length);
  });

  // Remove parameter type annotations:  (x: Type) → (x      )
  // Match colon followed by type, stopping at , or ) or =
  result = result.replace(/(\w)\s*:\s*([A-Z]\w*(?:\[\]|\s*\|\s*\w+)*)\s*(?=[,)=])/g, (match, name) => {
    return name + ' '.repeat(match.length - name.length);
  });

  // Remove variable type annotations:  let x: Type = → let x       =
  // Match : Type after identifier in let/const/var declarations
  result = result.replace(/(let|const|var)\s+(\w+)\s*:\s*(\w+(?:\[\]|\s*\|\s*\w+)*)\s*(?==)/g, (match, keyword, varName) => {
    return keyword + ' ' + varName + ' '.repeat(match.length - keyword.length - 1 - varName.length);
  });

  // Remove return type annotations:  ): Type => or ): Type {
  result = result.replace(/\)\s*:\s*([A-Z]\w*(?:\[\]|\s*\|\s*\w+)*)\s*(?=[{=>])/g, (match) => {
    return ')' + ' '.repeat(match.length - 1);
  });

  return result;
}

/**
 * Parse source and build a NeuralMap using the language-appropriate profile.
 *
 * tree-sitter CST → scope-aware walk → classified nodes → data flow edges → taint init
 */
async function analyzeWithRealMapper(source: string, filename: string): Promise<NeuralMap> {
  const langConfig = detectLanguage(filename);
  const parser = await getParser(langConfig.grammarPackage);
  const profile = await getProfile(langConfig.profileImport);

  // For TypeScript files parsed with tree-sitter-javascript, strip TS annotations
  const ext = path.extname(filename).toLowerCase();
  const parseSource = (ext === '.ts' || ext === '.tsx')
    ? stripTypeScriptAnnotations(source)
    : source;

  const tree = parser.parse(parseSource);

  if (!tree) {
    console.error('tree-sitter failed to parse: ' + filename);
    process.exit(1);
  }

  resetSequence();
  const { map } = buildNeuralMap(tree, source, filename, profile);

  tree.delete(); // free WASM memory

  return map;
}

// ---------------------------------------------------------------------------
// Report formatting
// ---------------------------------------------------------------------------

function printHeader(mode: string): void {
  const cweCount = registeredCWEs().length;
  const countLabel = `Deterministic Security Testing — ${cweCount} CWE Properties`;
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║          DST VERIFICATION ENGINE v0.2                   ║');
  console.log(`║   ${countLabel.padEnd(53)}║`);
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

function collectSourceFiles(dir: string): string[] {
  const files: string[] = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    // Skip common non-source directories
    if (entry.isDirectory()) {
      if (['node_modules', '.git', 'dist', 'build', 'coverage', '.next', '__pycache__', 'venv', '.venv', 'env'].includes(entry.name)) {
        continue;
      }
      files.push(...collectSourceFiles(fullPath));
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (!SCANNABLE_EXTENSIONS.has(ext)) continue;
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
    console.log(`  No findings. All ${registeredCWEs().length} CWE properties verified clean across all files.`);
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
  const noDedup = args.includes('--no-dedup');
  const pedantic = args.includes('--pedantic');
  const target = args.find(a => !a.startsWith('--'));
  const isDemo = args.includes('--demo') || !target;
  const verifyOptions = (noDedup || pedantic)
    ? { ...(noDedup ? { noDedup: true } : {}), ...(pedantic ? { pedanticMode: true } : {}) }
    : undefined;

  const startTime = Date.now();

  if (isDemo) {
    // Single file demo mode
    printHeader('DEMO — vulnerable Express app');
    console.log('Parsing with tree-sitter → building Neural Map...');
    console.log('');

    const map = await analyzeWithRealMapper(DEMO_CODE, 'demo-vulnerable-app.js');
    printMapStats(map);

    const results = verifyAll(map, 'javascript', verifyOptions);

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
    const langConfig = detectLanguage(target!);
    printHeader(target!);
    console.log('Parsing with tree-sitter → building Neural Map...');
    console.log('');

    const map = await analyzeWithRealMapper(source, target!);
    printMapStats(map);

    const results = verifyAll(map, langConfig.profileImport, verifyOptions);

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
    const files = collectSourceFiles(target!);

    if (files.length === 0) {
      console.error(`No scannable files found in: ${target}`);
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
        const fileLangConfig = detectLanguage(file);
        const map = await analyzeWithRealMapper(source, file);
        const results = verifyAll(map, fileLangConfig.profileImport, verifyOptions);
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

    // ─── Cross-file analysis ──────────────────────────────────────────
    // Build a merged NeuralMap from all files and run verifiers on it.
    // This catches vulnerabilities that span module boundaries.
    // ──────────────────────────────────────────────────────────────────

    let crossFileResult: CrossFileResult | null = null;
    let crossFileFindings: FileResult | null = null;

    if (allResults.length >= 2) {
      console.log('');
      console.log('Cross-file analysis: merging Neural Maps...');

      try {
        // Build file-path -> NeuralMap mapping (using full paths)
        const fileMaps = new Map<string, NeuralMap>();
        for (const fr of allResults) {
          const fullPath = path.resolve(target!, fr.filename).replace(/\\/g, '/');
          fileMaps.set(fullPath, fr.map);
        }

        crossFileResult = analyzeCrossFile(fileMaps, files.map(f => f.replace(/\\/g, '/')));

        console.log(`  Dependency edges: ${crossFileResult.depGraph.edges.length}`);
        console.log(`  Cross-file edges: ${crossFileResult.crossFileEdges}`);
        console.log(`  Resolved imports: ${crossFileResult.resolvedImports.length}`);

        if (crossFileResult.resolvedImports.length > 0) {
          console.log('  Import chains:');
          for (const ri of crossFileResult.resolvedImports) {
            const fromShort = path.relative(target!, ri.from);
            const toShort = path.relative(target!, ri.to);
            console.log(`    ${fromShort} -> ${toShort} [${ri.symbols.join(', ')}]`);
          }
        }

        // Run verifiers on the merged map — use dominant language from scanned files
        const langCounts = new Map<string, number>();
        for (const fr of allResults) {
          const lang = detectLanguage(path.resolve(target!, fr.filename)).profileImport;
          langCounts.set(lang, (langCounts.get(lang) ?? 0) + 1);
        }
        const dominantLang = [...langCounts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? 'javascript';
        const mergedResults = verifyAll(crossFileResult.mergedMap, dominantLang, verifyOptions);
        const mergedFindings = mergedResults.filter(r => !r.holds).reduce((s, r) => s + r.findings.length, 0);

        crossFileFindings = {
          filename: '[cross-file merged]',
          map: crossFileResult.mergedMap,
          results: mergedResults,
        };

        console.log(`  Merged map: ${crossFileResult.mergedMap.nodes.length} nodes, ${crossFileResult.mergedMap.edges.length} edges`);
        console.log(`  Cross-file findings: ${mergedFindings}`);
      } catch (err) {
        console.log(`  Cross-file analysis error: ${(err as Error).message?.slice(0, 80)}`);
      }
    }

    if (jsonOutput) {
      const jsonResults = allResults.map(fr => ({
        file: fr.filename,
        nodes: fr.map.nodes.length,
        results: fr.results,
      }));
      if (crossFileFindings) {
        jsonResults.push({
          file: '[cross-file merged]',
          nodes: crossFileFindings.map.nodes.length,
          results: crossFileFindings.results,
        });
      }
      console.log(JSON.stringify(jsonResults, null, 2));
    } else {
      // Print per-file findings
      for (const fr of allResults) {
        printFileReport(fr);
      }

      // Print cross-file findings
      if (crossFileFindings) {
        const crossFailed = crossFileFindings.results.filter(r => !r.holds);
        if (crossFailed.length > 0) {
          console.log(`\n${'='.repeat(60)}`);
          console.log('  CROSS-FILE FINDINGS (merged Neural Map)');
          console.log(`${'='.repeat(60)}`);
          printFileReport(crossFileFindings);
        }
      }

      // Print overall summary (includes per-file only — cross-file shown separately)
      printSummary(allResults, Date.now() - startTime);

      if (crossFileFindings) {
        const crossFailed = crossFileFindings.results.filter(r => !r.holds);
        const crossTotal = crossFailed.reduce((s, r) => s + r.findings.length, 0);
        if (crossTotal > 0) {
          console.log(`  Cross-file analysis found ${crossTotal} additional finding(s) from ${crossFileResult!.crossFileEdges} cross-file edges.`);
          console.log('');
        }
      }
    }
  }
}

main().catch(err => {
  console.error('DST CLI error:', err);
  process.exit(1);
});
