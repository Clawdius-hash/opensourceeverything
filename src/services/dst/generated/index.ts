/**
 * DST Generated Verifiers — Index
 * Re-exports all generated verifier batches and provides a unified registry.
 */

export * from './_helpers';
export * from './batch_001';
export * from './batch_002';
export * from './batch_003';
export * from './batch_004';
export * from './batch_005';
export * from './batch_006';
export * from './batch_007';
export * from './batch_008';
export * from './batch_009';
export * from './batch_010';
export * from './batch_011';
export * from './batch_012';
export * from './batch_013';
export * from './batch_014';
export * from './batch_015';
export * from './batch_016';
export * from './batch_017';
export * from './batch_018';
export * from './batch_019';
export * from './batch_020';
export * from './batch_021';
import { BATCH_001_REGISTRY } from './batch_001';
import { BATCH_002_REGISTRY } from './batch_002';
import { BATCH_003_REGISTRY } from './batch_003';
import { BATCH_004_REGISTRY } from './batch_004';
import { BATCH_005_REGISTRY } from './batch_005';
import { BATCH_006_REGISTRY } from './batch_006';
import { BATCH_007_REGISTRY } from './batch_007';
import { BATCH_008_REGISTRY } from './batch_008';
import { BATCH_009_REGISTRY } from './batch_009';
import { BATCH_010_REGISTRY } from './batch_010';
import { BATCH_011_REGISTRY } from './batch_011';
import { BATCH_012_REGISTRY } from './batch_012';
import { BATCH_013_REGISTRY } from './batch_013';
import { BATCH_014_REGISTRY } from './batch_014';
import { BATCH_015_REGISTRY } from './batch_015';
import { BATCH_016_REGISTRY } from './batch_016';
import { BATCH_017_REGISTRY } from './batch_017';
import { BATCH_018_REGISTRY } from './batch_018';
import { BATCH_019_REGISTRY } from './batch_019';
import { BATCH_020_REGISTRY } from './batch_020';
import { BATCH_021_REGISTRY } from './batch_021';
import type { NeuralMap } from '../types';
import type { VerificationResult } from './_helpers';

/**
 * Combined registry of all generated verifiers.
 * Merge with the main CWE_REGISTRY in verifier.ts to extend coverage.
 */
export const GENERATED_REGISTRY: Record<string, (map: NeuralMap) => VerificationResult> = {
  ...BATCH_001_REGISTRY,
  ...BATCH_002_REGISTRY,
  ...BATCH_003_REGISTRY,
  ...BATCH_004_REGISTRY,
  ...BATCH_005_REGISTRY,
  ...BATCH_006_REGISTRY,
  ...BATCH_007_REGISTRY,
  ...BATCH_008_REGISTRY,
  ...BATCH_009_REGISTRY,
  ...BATCH_010_REGISTRY,
  ...BATCH_011_REGISTRY,
  ...BATCH_012_REGISTRY,
  ...BATCH_013_REGISTRY,
  ...BATCH_014_REGISTRY,
  ...BATCH_015_REGISTRY,
  ...BATCH_016_REGISTRY,
  ...BATCH_017_REGISTRY,
  ...BATCH_018_REGISTRY,
  ...BATCH_019_REGISTRY,
  ...BATCH_020_REGISTRY,
  ...BATCH_021_REGISTRY,
};

/**
 * Verify a specific CWE using generated verifiers only.
 */
export function verifyGenerated(map: NeuralMap, cwe: string): VerificationResult | null {
  const fn = GENERATED_REGISTRY[cwe];
  return fn ? fn(map) : null;
}

/**
 * List all CWEs covered by generated verifiers.
 */
export function generatedCWEs(): string[] {
  return Object.keys(GENERATED_REGISTRY);
}
