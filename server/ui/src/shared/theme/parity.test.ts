import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, it, expect } from "vitest";
import { ACCENT, ACCENT_BRIGHT, SIGNAL_OK, SEVERITY } from "./tokens";

// The design system keeps its blessed hex sources in lockstep. slop-check bans
// hex anywhere ELSE but cannot detect when these sources drift apart, so this
// parity test closes that gap: it derives each overlapping color from its
// sources and asserts equality. It intentionally hardcodes NO hex literal — it
// imports the token value and reads the other source's TEXT from disk — so the
// test itself stays within slop-check rule #1. (Files are read from disk
// because vitest mocks CSS/asset imports to empty strings.)
//
// There are two duplicated surfaces to guard:
//   1. tokens.ts  <-> globals.css  (the signature accents).
//   2. tokens.ts  <-> tailwind.config.ts (the severity palette). Tailwind
//      needs literal hex to generate `bg-severity-*` classes (e.g.
//      `bg-severity-medium` on finding severity chips), and tailwind.config.ts lives
//      OUTSIDE src/ so slop-check never scans it — hence this guard.

// vitest runs from the UI package root (server/ui), so resolve from cwd.
const css = readFileSync(
  resolve(process.cwd(), "src/shared/styles/globals.css"),
  "utf8",
);
const tailwind = readFileSync(
  resolve(process.cwd(), "tailwind.config.ts"),
  "utf8",
);

function hexToRgb(hex: string): [number, number, number] {
  const body = hex.replace("#", "");
  return [
    parseInt(body.slice(0, 2), 16),
    parseInt(body.slice(2, 4), 16),
    parseInt(body.slice(4, 6), 16),
  ];
}

function cssVarRgb(name: string): [number, number, number] {
  const match = css.match(new RegExp(`--${name}:\\s*(\\d+)\\s+(\\d+)\\s+(\\d+)`));
  if (!match) {
    throw new Error(`CSS variable --${name} not found in globals.css`);
  }
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

function tailwindSeverityHex(level: string): string {
  const body = tailwind.match(/severity:\s*\{([^}]*)\}/)?.[1];
  if (!body) {
    throw new Error("severity palette not found in tailwind.config.ts");
  }
  const hex = body.match(new RegExp(`${level}:\\s*"(#[0-9a-fA-F]{6})"`))?.[1];
  if (!hex) {
    throw new Error(`severity.${level} not found in tailwind.config.ts`);
  }
  return hex;
}

// tokens.ts (hex export) <-> globals.css CSS variable. The signature accents
// (amber phosphor + signal green) appear in both files and must agree.
const CSS_VAR_PAIRS: ReadonlyArray<readonly [string, string, string]> = [
  ["ACCENT", ACCENT, "phosphor-raw"],
  ["ACCENT_BRIGHT", ACCENT_BRIGHT, "phosphor-bright-raw"],
  ["SIGNAL_OK", SIGNAL_OK, "signal-raw"],
];

// tokens.ts SEVERITY[*].solid <-> tailwind.config.ts severity.* literal.
const SEVERITY_LEVELS = ["critical", "high", "medium"] as const;

describe("theme token <-> CSS var parity", () => {
  for (const [name, hex, varName] of CSS_VAR_PAIRS) {
    it(`${name} equals --${varName}`, () => {
      expect(hexToRgb(hex)).toEqual(cssVarRgb(varName));
    });
  }
});

describe("tailwind severity palette <-> tokens.SEVERITY parity", () => {
  for (const level of SEVERITY_LEVELS) {
    it(`tailwind severity.${level} equals SEVERITY.${level}.solid`, () => {
      expect(hexToRgb(tailwindSeverityHex(level))).toEqual(
        hexToRgb(SEVERITY[level].solid),
      );
    });
  }
});
