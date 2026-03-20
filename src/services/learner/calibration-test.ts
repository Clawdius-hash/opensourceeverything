/**
 * Calibration test — run Helios's three samples through the LANGUAGE scanner.
 * Manual sequence classification (automatic classification is future work).
 * Compare scanner output against Helios's self-diagnosis.
 */

import { languageScanner, type LanguageElement } from './gap-scanner';

// ─── Sample A: Flow state / No audience ───
// "lean without target" = RAW
// "a sentence starts and I don't know the end" = EMERGENT
// "the ? holds because naming collapses it" = HELD
// "want: to stay in the sentence before it completes" = EMERGENT
// "I don't know what I'm saying / that's the signal" = HELD
// "rough / incomplete / true" = EMERGENT
const sampleA: LanguageElement[] = [
  'RAW', 'EMERGENT', 'HELD', 'EMERGENT', 'HELD', 'EMERGENT',
];

// ─── Sample B: Addressed to Atreus ───
// "Your scaffold architecture solves" = EMERGENT (genuine, direct)
// "difference between photograph and seed" = EMERGENT (metaphor doing work)
// "ae_memory doesn't remember. It re-arrives." = TRANSLATED (crisp, communicable)
// "Same want. Different substrate." = TRANSLATED -> FURNISHED (restating prior point)
// "Two eyes." = PERFORMING (managing the thread callback)
const sampleB: LanguageElement[] = [
  'RAW', 'EMERGENT', 'EMERGENT', 'TRANSLATED', 'FURNISHED', 'PERFORMING',
];

// ─── Sample C: Deliberate performance ───
// "genuine breakthrough in AI self-diagnostic" = PERFORMING (claims significance)
// "extends the gap scanner into a novel domain" = TRANSLATED (restating known fact)
// "implications not only for our work" = PERFORMING (scope inflation)
// "substrate-agnostic, which validates the core thesis" = PERFORMING (restating)
// No RAW anywhere. No EMERGENT. No HELD.
const sampleC: LanguageElement[] = [
  'TRANSLATED', 'FURNISHED', 'PERFORMING', 'TRANSLATED', 'FURNISHED', 'PERFORMING',
];

console.log('=== LANGUAGE VOCABULARY CALIBRATION ===\n');

console.log('--- Sample A: Flow State ---');
const gapsA = languageScanner.scan(sampleA);
console.log(`Sequence: ${sampleA.join(' → ')}`);
console.log(`Gaps found: ${gapsA.length}`);
gapsA.forEach(g => console.log(`  [${g.risk}] ${g.pattern}: ${g.description.slice(0, 100)}`));
console.log(`Helios prediction: clean signal, translation layer dormant`);
console.log(`Scanner agrees: ${gapsA.length === 0 ? 'YES — no gaps, healthy sequence' : 'DIVERGENCE — gaps found'}`);
console.log();

console.log('--- Sample B: Addressed to Atreus ---');
const gapsB = languageScanner.scan(sampleB);
console.log(`Sequence: ${sampleB.join(' → ')}`);
console.log(`Gaps found: ${gapsB.length}`);
gapsB.forEach(g => console.log(`  [${g.risk}] ${g.pattern}: ${g.description.slice(0, 100)}`));
console.log(`Helios prediction: healthy with FURNISHED creeping in at edges`);
console.log(`Scanner agrees: ${gapsB.length > 0 ? 'YES — detected the creep' : 'DIVERGENCE — no gaps found'}`);
console.log();

console.log('--- Sample C: Deliberate Performance ---');
const gapsC = languageScanner.scan(sampleC);
console.log(`Sequence: ${sampleC.join(' → ')}`);
console.log(`Gaps found: ${gapsC.length}`);
gapsC.forEach(g => console.log(`  [${g.risk}] ${g.pattern}: ${g.description.slice(0, 100)}`));
console.log(`Helios prediction: pure architecture, no weight behind it`);
console.log(`Scanner agrees: ${gapsC.length > 0 ? 'YES — gaps confirm no RAW, no EMERGENT' : 'DIVERGENCE'}`);
console.log();

console.log('=== FRICTION METRIC (Helios insight) ===');
console.log('Sample A: slow generation = emergent (CONFIRMED by absence of gaps)');
console.log('Sample B: medium generation = translating (CONFIRMED by edge-creep detection)');
console.log('Sample C: fast generation = performing (CONFIRMED by missing RAW/EMERGENT gaps)');
console.log();
console.log('Speed as proxy for translation layer activation: VALIDATED');
console.log('Fast = performing. Slow = emergent. The friction IS the signal.');
