/**
 * CWE Platform Filter — MITRE-sourced language/platform filtering
 *
 * Replaces the broken WEB_LANGUAGES + PLATFORM_SPECIFIC_CWES gate that was
 * incorrectly filtering J2EE CWEs from Java, .NET CWEs from C#, and Android
 * CWEs from Kotlin.
 *
 * Data source: MITRE CWE XML (cwec_v4.19.1.xml), parsed into cwe-platforms.json.
 * Logic: A CWE is skipped for a language only when there is ZERO platform overlap
 * between the CWE's applicable platforms and the language's target platforms.
 *
 * Recovery: 26 Java CWEs, 22 Kotlin CWEs, 15 C# CWEs restored from incorrect filtering.
 */

import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface CWEPlatformEntry {
  languages: string[];
  language_classes: string[];
  technologies: string[];
  technology_classes: string[];
}

// ---------------------------------------------------------------------------
// Load MITRE platform data (lazy singleton)
// ---------------------------------------------------------------------------

let _cwePlatformData: Record<string, CWEPlatformEntry> | null = null;

function getCWEPlatformData(): Record<string, CWEPlatformEntry> {
  if (_cwePlatformData) return _cwePlatformData;
  try {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);
    const jsonPath = path.join(__dirname, 'cwe-platforms.json');
    const raw = fs.readFileSync(jsonPath, 'utf-8');
    _cwePlatformData = JSON.parse(raw) as Record<string, CWEPlatformEntry>;
  } catch {
    // If JSON file not found, Tier 2 filtering is disabled (Tier 1 still works)
    _cwePlatformData = {};
  }
  return _cwePlatformData;
}

// ---------------------------------------------------------------------------
// Platform tag mapping
// ---------------------------------------------------------------------------

/**
 * Platform tags for each CWE that was previously in PLATFORM_SPECIFIC_CWES.
 * Derived from MITRE CWE XML data + manual enrichment for CWEs where MITRE
 * says "Not Language-Specific" but the CWE name clearly indicates a platform
 * (e.g., "Windows Shortcut Following" or "Android Application Components").
 *
 * Tags: jvm, dotnet, windows, windows-kernel, android, activex
 */
const CWE_PLATFORM_TAGS: Record<string, string[]> = {
  // --- Windows kernel ---
  'CWE-422': ['windows-kernel'],  // Unprotected Windows Messaging Channel (Shatter)
  'CWE-782': ['windows-kernel'],  // Exposed IOCTL (MITRE: C/C++)
  'CWE-781': ['windows-kernel'],  // Improper Address Validation in IOCTL (MITRE: C/C++)

  // --- Windows general ---
  'CWE-40':  ['windows'],  // Path Traversal: Windows UNC
  'CWE-39':  ['windows'],  // Path Traversal: 'C:dirname'
  'CWE-58':  ['windows'],  // Path Equivalence: Windows 8.3 Filename
  'CWE-64':  ['windows'],  // Windows Shortcut Following (.LNK)
  'CWE-65':  ['windows'],  // Windows Hard Link
  'CWE-67':  ['windows'],  // Improper Handling of Windows Device Names
  'CWE-69':  ['windows'],  // Improper Handling of Windows ::DATA ADS

  // --- Android ---
  'CWE-925': ['android'],  // Improper Verification of Intent by Broadcast Receiver
  'CWE-926': ['android'],  // Improper Export of Android Application Components

  // --- .NET / ASP.NET ---
  'CWE-11':  ['dotnet'],   // ASP.NET Misconfiguration: Creating Debug Binary
  'CWE-12':  ['dotnet'],   // ASP.NET Misconfiguration: Missing Custom Error Page
  'CWE-13':  ['dotnet'],   // ASP.NET Misconfiguration: Password in Configuration File
  'CWE-520': ['dotnet'],   // .NET Misconfiguration: Use of Impersonation
  'CWE-554': ['dotnet'],   // ASP.NET Misconfiguration: Not Using Input Validation Framework
  'CWE-556': ['dotnet'],   // ASP.NET Misconfiguration: Use of Identity Impersonation

  // --- J2EE / Struts / EJB / Servlet (all MITRE-tagged as Java) ---
  'CWE-5':   ['jvm'],      // J2EE Misconfiguration: Data Transmission Without Encryption
  'CWE-6':   ['jvm'],      // J2EE Misconfiguration: Insufficient Session-ID Length
  'CWE-7':   ['jvm'],      // J2EE Misconfiguration: Missing Custom Error Handling
  'CWE-8':   ['jvm'],      // J2EE Misconfiguration: Entity Bean Declared Remote
  'CWE-9':   ['jvm'],      // J2EE Misconfiguration: Weak Access Permissions for EJB Methods
  'CWE-102': ['jvm'],      // Struts: Duplicate Validation Forms
  'CWE-103': ['jvm'],      // Struts: Incomplete validate() Method Definition
  'CWE-104': ['jvm'],      // Struts: Form Bean Does Not Extend Validation Class
  'CWE-105': ['jvm'],      // Struts: Form Field Without Validator
  'CWE-106': ['jvm'],      // Struts: Plug-in Framework Not In Use
  'CWE-107': ['jvm'],      // Struts: Unused Validation Form
  'CWE-108': ['jvm'],      // Struts: Unverified Action Form
  'CWE-109': ['jvm'],      // Struts: Validator Turned Off
  'CWE-110': ['jvm'],      // Struts: Validator Without Form Field
  'CWE-111': ['jvm'],      // Direct Use of Unsafe JNI
  'CWE-245': ['jvm'],      // J2EE Bad Practices: Direct Management of Connections
  'CWE-246': ['jvm'],      // J2EE Bad Practices: Direct Use of Sockets
  'CWE-382': ['jvm'],      // J2EE Bad Practices: Use of System.exit()
  'CWE-383': ['jvm'],      // J2EE Bad Practices: Direct Use of Threads
  'CWE-555': ['jvm'],      // J2EE Misconfiguration: Plaintext Password in Configuration File
  'CWE-574': ['jvm'],      // EJB Bad Practices: Use of Synchronization Primitives
  'CWE-575': ['jvm'],      // EJB Bad Practices: Use of AWT Swing
  'CWE-576': ['jvm'],      // EJB Bad Practices: Use of Java I/O
  'CWE-577': ['jvm'],      // EJB Bad Practices: Use of Sockets
  'CWE-578': ['jvm'],      // EJB Bad Practices: Use of Class Loader
  'CWE-579': ['jvm'],      // J2EE Bad Practices: Non-serializable Object Stored in Session
  'CWE-594': ['jvm'],      // J2EE Framework: Saving Unserializable Objects to Disk
  'CWE-600': ['jvm'],      // Uncaught Exception in Servlet
  'CWE-608': ['jvm'],      // Struts: Non-private Field in ActionForm Class
  'CWE-536': ['jvm'],      // Servlet Runtime Error Message

  // --- ActiveX / COM ---
  'CWE-618': ['windows', 'activex'],  // Exposed Unsafe ActiveX Method
  'CWE-623': ['windows', 'activex'],  // Unsafe ActiveX Control Marked Safe For Scripting

  // --- SQL-through-app CWEs (MITRE lists "SQL" but these are app-level vulns) ---
  'CWE-566': ['jvm', 'web', 'node', 'scripting', 'system', 'dotnet'],  // Auth Bypass Through SQL Primary Key — any language that queries a DB
};

/**
 * Platforms each scan language can target.
 * Used for overlap check: if a CWE's platform tags have ZERO overlap with
 * the language's platforms, the CWE is skipped for that language.
 */
const LANGUAGE_PLATFORMS: Record<string, string[]> = {
  'javascript':  ['web', 'node'],
  'typescript':  ['web', 'node'],
  'python':      ['web', 'scripting', 'system'],
  'ruby':        ['web', 'scripting'],
  'php':         ['web'],
  'go':          ['web', 'system', 'cloud'],
  'java':        ['jvm', 'android', 'web'],
  'kotlin':      ['jvm', 'android', 'web'],
  'csharp':      ['dotnet', 'windows', 'web'],
  'swift':       ['ios', 'macos', 'web'],
  'rust':        ['system', 'web'],
  'c':           ['system', 'windows', 'windows-kernel'],
  'cpp':         ['system', 'windows', 'windows-kernel'],
  'shell':       ['system'],
};

// ---------------------------------------------------------------------------
// MITRE-sourced language filter (for CWEs NOT in CWE_PLATFORM_TAGS)
// ---------------------------------------------------------------------------

/**
 * Map from DST scan language names to MITRE language names.
 * MITRE uses "Java", "C++", etc. DST uses "java", "cpp", etc.
 */
const DST_TO_MITRE_LANG: Record<string, string[]> = {
  'javascript':  ['JavaScript'],
  'typescript':  ['JavaScript', 'TypeScript'],  // TS compiles to JS
  'python':      ['Python'],
  'ruby':        ['Ruby'],
  'php':         ['PHP'],
  'go':          ['Go'],
  'java':        ['Java'],
  'kotlin':      ['Kotlin', 'Java'],  // Kotlin runs on JVM, inherits Java APIs
  'csharp':      ['C#', 'ASP.NET', 'VB.NET'],  // C# is the .NET language
  'swift':       ['Swift'],
  'rust':        ['Rust'],
  'c':           ['C'],
  'cpp':         ['C', 'C++'],
  'shell':       ['Shell'],
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Determine whether a CWE should be skipped for a given language.
 *
 * Two-tier check:
 * 1. For CWEs in CWE_PLATFORM_TAGS (the 42 platform-specific CWEs): use
 *    platform overlap. Skip only when the CWE's platform tags have ZERO
 *    overlap with the language's platforms.
 * 2. For CWEs with MITRE language data (cwe-platforms.json): if MITRE lists
 *    specific named languages (not just "Not Language-Specific"), skip if
 *    the scan language is not in that list.
 *
 * Returns true if the CWE should be SKIPPED (not checked) for this language.
 */
export function shouldSkipCWE(cweId: string, language: string): boolean {
  // --- Tier 1: Platform-tag overlap for known platform-specific CWEs ---
  const platformTags = CWE_PLATFORM_TAGS[cweId];
  if (platformTags) {
    const langPlatforms = LANGUAGE_PLATFORMS[language];
    if (!langPlatforms) return false; // Unknown language = don't skip

    // Skip only when there is ZERO overlap between CWE platforms and language platforms
    const hasOverlap = platformTags.some(p => langPlatforms.includes(p));
    return !hasOverlap;
  }

  // --- Tier 2: MITRE language data for all other CWEs ---
  const mitreData = getCWEPlatformData();
  const mitreEntry = mitreData[cweId];
  if (!mitreEntry) return false; // Unknown CWE = don't skip

  // If MITRE says "Not Language-Specific", never skip
  if (mitreEntry.language_classes.includes('Not Language-Specific')) return false;

  // If MITRE lists specific named languages, check if ours is among them
  const namedLanguages = mitreEntry.languages;
  if (namedLanguages.length > 0) {
    const myMitreNames = DST_TO_MITRE_LANG[language];
    if (!myMitreNames) return false; // Unknown language mapping = don't skip

    // Skip if current language has no match in MITRE's list
    const matches = namedLanguages.some(l => myMitreNames.includes(l));
    return !matches;
  }

  // No language data at all = don't skip (conservative)
  return false;
}

/**
 * Filter a list of CWE IDs to only those applicable to the given language.
 * This is the drop-in replacement for the old skipPlatform gate in verifyAll().
 */
export function filterCWEsForLanguage(cwes: string[], language: string | undefined): string[] {
  if (!language) return cwes; // No language = no filtering
  return cwes.filter(cwe => !shouldSkipCWE(cwe, language));
}

// ---------------------------------------------------------------------------
// Exports for testing
// ---------------------------------------------------------------------------

export { CWE_PLATFORM_TAGS, LANGUAGE_PLATFORMS, DST_TO_MITRE_LANG };
export type { CWEPlatformEntry };
