// Flat ESLint config for the AgentHound UI.
//
// Its single job is to enforce the layered import-direction rule from
// ARCHITECTURE.md via eslint-plugin-boundaries. We deliberately do not enable a
// broad TypeScript/React ruleset here; tsc (`npm run build`) covers
// type/unused-symbol checking. Code-quality rulesets can be layered on later.
//
// The four architectural layers (only these are "elements"):
//   app      -> may import features, entities, shared
//   features -> may import entities, shared, and ONLY their own feature
//   entities -> may import shared and sibling entities (shared wire types)
//   shared   -> may import shared only (no upward imports)
//
// Files outside the four layer roots (for example src/main.tsx, tests, and
// static assets) are not domain elements and are skipped by
// boundaries/dependencies.
//
// NOTE: eslint-plugin-boundaries v6 renamed `element-types` -> `dependencies`
// and uses structured selectors ({ from, allow: { to } }) with Handlebars
// capture templates ({{ from.captured.feature }}).
import tseslint from "typescript-eslint";
import boundaries from "eslint-plugin-boundaries";

export default tseslint.config(
  {
    ignores: ["dist/**", "node_modules/**"],
  },
  // Parser only — no rule sets — so every TS/TSX file parses cleanly.
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        ecmaVersion: "latest",
        sourceType: "module",
      },
    },
  },
  // Architecture boundaries, scoped to src. The rule acts on files that
  // resolve to a declared layer element.
  {
    files: ["src/**/*.{ts,tsx}"],
    plugins: { boundaries },
    settings: {
      "boundaries/elements": [
        { type: "app", pattern: "src/app", mode: "folder" },
        { type: "shared", pattern: "src/shared", mode: "folder" },
        {
          type: "feature",
          pattern: "src/features/*",
          mode: "folder",
          capture: ["feature"],
        },
        {
          type: "entity",
          pattern: "src/entities/*",
          mode: "folder",
          capture: ["entity"],
        },
      ],
      // Resolve `@/`, `@app/`, `@shared/`, `@entities/`, `@features/` and
      // relative imports.
      "import/resolver": {
        typescript: { project: "tsconfig.json" },
        node: true,
      },
    },
    rules: {
      "boundaries/dependencies": [
        "error",
        {
          default: "disallow",
          rules: [
            // app -> anything below it
            {
              from: { type: "app" },
              allow: { to: { type: ["app", "feature", "entity", "shared"] } },
            },
            // features -> shared, any entity, and ONLY their own feature
            {
              from: { type: "feature" },
              allow: [
                { to: { type: ["shared", "entity"] } },
                {
                  to: {
                    type: "feature",
                    captured: { feature: "{{ from.captured.feature }}" },
                  },
                },
              ],
            },
            // entities -> shared and sibling entities (shared wire types)
            {
              from: { type: "entity" },
              allow: { to: { type: ["shared", "entity"] } },
            },
            // shared -> shared only (no upward imports)
            {
              from: { type: "shared" },
              allow: { to: { type: "shared" } },
            },
          ],
        },
      ],
    },
  },
);
