import type { Config } from "tailwindcss";
import defaultTheme from "tailwindcss/defaultTheme";

const config: Config = {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", ...defaultTheme.fontFamily.sans],
        mono: ["JetBrains Mono", "Fira Code", ...defaultTheme.fontFamily.mono],
      },
      fontSize: {
        display: ["2.25rem", { lineHeight: "1.1", fontWeight: "700", letterSpacing: "-0.02em" }],
        "title-lg": ["1.5rem", { lineHeight: "1.2", fontWeight: "600", letterSpacing: "-0.015em" }],
        "title-sm": ["1rem", { lineHeight: "1.3", fontWeight: "600" }],
        label: ["0.6875rem", { lineHeight: "1.3", fontWeight: "600", letterSpacing: "0.06em" }],
        overline: ["0.625rem", { lineHeight: "1.3", fontWeight: "600", letterSpacing: "0.12em" }],
        // Mono instrument readouts — tactical SOC numerics.
        metric: ["2.75rem", { lineHeight: "1", fontWeight: "700", letterSpacing: "-0.02em" }],
        "metric-lg": ["3.75rem", { lineHeight: "0.95", fontWeight: "700", letterSpacing: "-0.03em" }],
        "metric-sm": ["1.75rem", { lineHeight: "1", fontWeight: "600", letterSpacing: "-0.01em" }],
        // Console section labels: [ THREAT SEVERITY ]
        console: ["0.6875rem", { lineHeight: "1.2", fontWeight: "600", letterSpacing: "0.18em" }],
        tick: ["0.625rem", { lineHeight: "1.2", fontWeight: "500", letterSpacing: "0.08em" }],
      },
      colors: {
        // Semantic tokens — resolve to Radix-mauve / cyan / tomato steps
        // via globals.css. Stored as space-separated RGB triplets so the
        // Tailwind opacity modifier (`bg-primary/80`) keeps working.
        border: "rgb(var(--border) / <alpha-value>)",
        input: "rgb(var(--input) / <alpha-value>)",
        ring: "rgb(var(--ring) / <alpha-value>)",
        background: "rgb(var(--background) / <alpha-value>)",
        foreground: "rgb(var(--foreground) / <alpha-value>)",
        primary: {
          DEFAULT: "rgb(var(--primary) / <alpha-value>)",
          foreground: "rgb(var(--primary-foreground) / <alpha-value>)",
        },
        secondary: {
          DEFAULT: "rgb(var(--secondary) / <alpha-value>)",
          foreground: "rgb(var(--secondary-foreground) / <alpha-value>)",
        },
        destructive: {
          DEFAULT: "rgb(var(--destructive) / <alpha-value>)",
          foreground: "rgb(var(--destructive-foreground) / <alpha-value>)",
        },
        muted: {
          DEFAULT: "rgb(var(--muted) / <alpha-value>)",
          foreground: "rgb(var(--muted-foreground) / <alpha-value>)",
        },
        accent: {
          DEFAULT: "rgb(var(--accent) / <alpha-value>)",
          foreground: "rgb(var(--accent-foreground) / <alpha-value>)",
        },
        popover: {
          DEFAULT: "rgb(var(--popover) / <alpha-value>)",
          foreground: "rgb(var(--popover-foreground) / <alpha-value>)",
        },
        card: {
          DEFAULT: "rgb(var(--card) / <alpha-value>)",
          foreground: "rgb(var(--card-foreground) / <alpha-value>)",
        },
        // Direct Radix step access — use sparingly, prefer semantic tokens.
        // Useful when a component genuinely needs "step 8 border" rather
        // than the abstracted `border` token.
        mauve: {
          1: "rgb(var(--mauve-1-raw) / <alpha-value>)",
          2: "rgb(var(--mauve-2-raw) / <alpha-value>)",
          3: "rgb(var(--mauve-3-raw) / <alpha-value>)",
          4: "rgb(var(--mauve-4-raw) / <alpha-value>)",
          5: "rgb(var(--mauve-5-raw) / <alpha-value>)",
          6: "rgb(var(--mauve-6-raw) / <alpha-value>)",
          7: "rgb(var(--mauve-7-raw) / <alpha-value>)",
          8: "rgb(var(--mauve-8-raw) / <alpha-value>)",
          9: "rgb(var(--mauve-9-raw) / <alpha-value>)",
          10: "rgb(var(--mauve-10-raw) / <alpha-value>)",
          11: "rgb(var(--mauve-11-raw) / <alpha-value>)",
          12: "rgb(var(--mauve-12-raw) / <alpha-value>)",
        },
        cyan: {
          8: "rgb(var(--cyan-8-raw) / <alpha-value>)",
          9: "rgb(var(--cyan-9-raw) / <alpha-value>)",
          10: "rgb(var(--cyan-10-raw) / <alpha-value>)",
          11: "rgb(var(--cyan-11-raw) / <alpha-value>)",
        },
        tomato: {
          3: "rgb(var(--tomato-3-raw) / <alpha-value>)",
          9: "rgb(var(--tomato-9-raw) / <alpha-value>)",
          11: "rgb(var(--tomato-11-raw) / <alpha-value>)",
        },
        // Domain palettes — node-kind hues (graph identity) and severity
        // (information signal). These remain literal hex because they
        // have to be perceptually distinct ACROSS hues, not within one
        // ramp; a Radix scale per kind would defeat the purpose.
        node: {
          agent: "#06B6D4",
          server: "#10B981",
          tool: "#F59E0B",
          resource: "#EF4444",
          a2a: "#A855F7",
          skill: "#C084FC",
          identity: "#94A3B8",
          credential: "#EC4899",
          config: "#D97706",
          host: "#475569",
        },
        severity: {
          critical: "#EF4444",
          high: "#F97316",
          medium: "#EAB308",
          low: "#94A3B8",
          info: "#64748B",
        },
        explorer: { canvas: "rgb(var(--explorer-canvas) / <alpha-value>)" },
        // OBSIDIAN TERMINAL signature accents. Amber "phosphor" is the single
        // dominant accent; "signal" green is reserved for operational/OK.
        // Both literal — they are brand identity, not a neutral ramp.
        phosphor: {
          DEFAULT: "#F5A623",
          bright: "#FFB020",
          dim: "#7A5A1E",
          glow: "rgb(245 166 35 / 0.14)",
        },
        signal: {
          DEFAULT: "#3FB950",
          dim: "#1E6E2E",
        },
        // Carbon canvas steps — pure near-black instrument surfaces.
        carbon: {
          950: "#0A0A0B",
          900: "#0C0D0F",
          850: "#121316",
          800: "#16171B",
          700: "#1C1E22",
          600: "#26292F",
        },
      },
      boxShadow: {
        "glow-cyan":
          "0 0 0 1px rgb(var(--cyan-9-raw) / 0.20), 0 0 20px -4px rgb(var(--cyan-9-raw) / 0.15)",
        // glow-orange retains its literal RGB — orange is a deliberate
        // "active/selected" identity distinct from cyan hover.
        "glow-orange": "0 0 0 1px rgb(249 115 22 / 0.40), 0 0 24px -4px rgb(249 115 22 / 0.25)",
        "glow-critical":
          "0 0 0 1px rgb(var(--tomato-9-raw) / 0.40), 0 0 20px -4px rgb(var(--tomato-9-raw) / 0.30)",
        // Tactical instrument panel: crisp 1px frame + a faint inner top
        // keyline (single light source) — no puffy blur.
        panel: "0 1px 0 0 rgb(255 255 255 / 0.03) inset, 0 1px 2px 0 rgb(0 0 0 / 0.5)",
        "phosphor-edge":
          "0 0 0 1px rgb(245 166 35 / 0.35), 0 0 16px -6px rgb(245 166 35 / 0.5)",
      },
      keyframes: {
        "slide-in-from-bottom-4": {
          "0%": { transform: "translateY(16px)", opacity: "0" },
          "100%": { transform: "translateY(0)", opacity: "1" },
        },
        "fade-in": {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        "fade-up": {
          "0%": { transform: "translateY(6px)", opacity: "0" },
          "100%": { transform: "translateY(0)", opacity: "1" },
        },
        shimmer: {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
        // Console caret blink — mechanical, hard steps.
        blink: {
          "0%, 49%": { opacity: "1" },
          "50%, 100%": { opacity: "0" },
        },
        // Live status LED — a slow operational breathe (no scale bounce).
        "led-pulse": {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.35" },
        },
        // Scanning sweep — a faint amber line traversing the strip.
        "scan-sweep": {
          "0%": { transform: "translateX(-100%)" },
          "100%": { transform: "translateX(100%)" },
        },
      },
      animation: {
        "slide-in-from-bottom-4": "slide-in-from-bottom-4 200ms ease-out",
        "fade-in": "fade-in 150ms ease-out",
        "fade-up": "fade-up 300ms cubic-bezier(0.33,0,0.2,1) both",
        shimmer: "shimmer 2s linear infinite",
        blink: "blink 1.1s steps(1) infinite",
        "led-pulse": "led-pulse 2.4s ease-in-out infinite",
        "scan-sweep": "scan-sweep 3.2s linear infinite",
      },
      borderRadius: {
        xl: "calc(var(--radius) + 4px)",
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
    },
  },
  plugins: [],
};

export default config;
