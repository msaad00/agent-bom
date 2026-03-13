/**
 * Pattern loader — compiles regex patterns from the shared patterns.json.
 *
 * patterns.json is the single source of truth, auto-generated from the
 * Python patterns.py by sdks/shared/generate-patterns.py.
 */

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { PatternDef, WeightedPatternDef, SequenceDef, Thresholds } from "./types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PATTERNS_PATH = resolve(__dirname, "../../shared/patterns.json");

interface RawPatterns {
  credential_patterns: PatternDef[];
  dangerous_arg_patterns: PatternDef[];
  cortex_model_patterns: PatternDef[];
  response_cloaking_patterns: PatternDef[];
  response_svg_patterns: PatternDef[];
  response_invisible_chars: PatternDef[];
  response_base64_pattern: { pattern: string; flags: string };
  response_injection_patterns: PatternDef[];
  suspicious_sequences: SequenceDef[];
  semantic_injection_signals: WeightedPatternDef[];
  thresholds: Thresholds;
}

/** Convert Python \UXXXXXXXX escapes to JS \u{XXXXX} format. */
function convertPythonUnicode(pattern: string): { pattern: string; needsUnicode: boolean } {
  let needsUnicode = false;
  const converted = pattern.replace(/\\U([0-9a-fA-F]{8})/g, (_m, hex: string) => {
    needsUnicode = true;
    // Strip leading zeros but keep at least one digit
    const trimmed = hex.replace(/^0+/, "") || "0";
    return `\\u{${trimmed}}`;
  });
  return { pattern: converted, needsUnicode };
}

function toRegExpFlags(flags: string, needsUnicode: boolean): string {
  let result = "";
  if (flags.includes("i")) result += "i";
  if (flags.includes("m")) result += "m";
  if (needsUnicode) result += "u";
  return result;
}

export interface CompiledPattern {
  name: string;
  regex: RegExp;
}

export interface CompiledWeightedPattern extends CompiledPattern {
  weight: number;
}

function compileOne(pat: string, flags: string): RegExp {
  const { pattern, needsUnicode } = convertPythonUnicode(pat);
  return new RegExp(pattern, toRegExpFlags(flags, needsUnicode));
}

function compilePatterns(defs: PatternDef[]): CompiledPattern[] {
  return defs.map((d) => ({
    name: d.name,
    regex: compileOne(d.pattern, d.flags),
  }));
}

function compileWeightedPatterns(defs: WeightedPatternDef[]): CompiledWeightedPattern[] {
  return defs.map((d) => ({
    name: d.name,
    regex: compileOne(d.pattern, d.flags),
    weight: d.weight,
  }));
}

let _cached: LoadedPatterns | null = null;

export interface LoadedPatterns {
  credentialPatterns: CompiledPattern[];
  dangerousArgPatterns: CompiledPattern[];
  cortexModelPatterns: CompiledPattern[];
  responseCloakingPatterns: CompiledPattern[];
  responseSvgPatterns: CompiledPattern[];
  responseInvisibleChars: CompiledPattern[];
  responseBase64Pattern: RegExp;
  responseInjectionPatterns: CompiledPattern[];
  suspiciousSequences: SequenceDef[];
  semanticInjectionSignals: CompiledWeightedPattern[];
  thresholds: Thresholds;
}

export function loadPatterns(): LoadedPatterns {
  if (_cached) return _cached;

  const raw: RawPatterns = JSON.parse(readFileSync(PATTERNS_PATH, "utf-8"));

  _cached = {
    credentialPatterns: compilePatterns(raw.credential_patterns),
    dangerousArgPatterns: compilePatterns(raw.dangerous_arg_patterns),
    cortexModelPatterns: compilePatterns(raw.cortex_model_patterns),
    responseCloakingPatterns: compilePatterns(raw.response_cloaking_patterns),
    responseSvgPatterns: compilePatterns(raw.response_svg_patterns),
    responseInvisibleChars: compilePatterns(raw.response_invisible_chars),
    responseBase64Pattern: compileOne(
      raw.response_base64_pattern.pattern,
      raw.response_base64_pattern.flags,
    ),
    responseInjectionPatterns: compilePatterns(raw.response_injection_patterns),
    suspiciousSequences: raw.suspicious_sequences,
    semanticInjectionSignals: compileWeightedPatterns(raw.semantic_injection_signals),
    thresholds: raw.thresholds,
  };

  return _cached;
}

/**
 * Score text for semantic prompt injection using weighted signal matching.
 * Mirrors Python's score_semantic_injection() exactly.
 *
 * @returns [score, triggeredSignals] — score is 0.0–1.0 (capped)
 */
export function scoreSemanticInjection(text: string): [number, string[]] {
  const { semanticInjectionSignals } = loadPatterns();
  let score = 0;
  const triggered: string[] = [];

  for (const signal of semanticInjectionSignals) {
    if (signal.regex.test(text)) {
      score += signal.weight;
      triggered.push(signal.name);
    }
  }

  return [Math.min(score, 1.0), triggered];
}
