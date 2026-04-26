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
      },
      colors: {
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
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
        explorer: { canvas: "hsl(var(--explorer-canvas))" },
      },
      boxShadow: {
        "glow-cyan": "0 0 0 1px rgba(6,182,212,0.20), 0 0 20px -4px rgba(6,182,212,0.15)",
        "glow-orange": "0 0 0 1px rgba(249,115,22,0.40), 0 0 24px -4px rgba(249,115,22,0.25)",
        "glow-critical": "0 0 0 1px rgba(239,68,68,0.40), 0 0 20px -4px rgba(239,68,68,0.30)",
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
        shimmer: {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
      },
      animation: {
        "slide-in-from-bottom-4": "slide-in-from-bottom-4 200ms ease-out",
        "fade-in": "fade-in 150ms ease-out",
        shimmer: "shimmer 2s linear infinite",
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
