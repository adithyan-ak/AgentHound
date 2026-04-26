# AgentHound Dark Dashboard Theme System

**Version:** 1.0.0
**Stack:** React 18 + TypeScript + Tailwind CSS 3.x + shadcn/ui + Recharts 2.x + Sigma.js 3
**WCAG Target:** AA (minimum), AAA where achievable without compromising readability
**Reference:** ByteArmor security dashboard aesthetic

---

## Table of Contents

1. [Design Principles](#1-design-principles)
2. [Token Architecture](#2-token-architecture)
3. [Color System](#3-color-system)
4. [Typography](#4-typography)
5. [Spacing & Layout](#5-spacing--layout)
6. [Responsive System](#6-responsive-system)
7. [Elevation & Depth](#7-elevation--depth)
8. [State System](#8-state-system)
9. [Motion & Animation](#9-motion--animation)
10. [Accessibility](#10-accessibility)
11. [Component Patterns](#11-component-patterns)
12. [Data Visualization](#12-data-visualization)
13. [Graph Explorer Theme](#13-graph-explorer-theme)
14. [Empty, Error & Loading States](#14-empty-error--loading-states)
15. [Notification & Toast System](#15-notification--toast-system)
16. [Form System](#16-form-system)
17. [Table & Data Grid](#17-table--data-grid)
18. [Icon System](#18-icon-system)
19. [Scrollbar Styling](#19-scrollbar-styling)
20. [Selection & Drag States](#20-selection--drag-states)
21. [Z-Index System](#21-z-index-system)
22. [Opacity Scale](#22-opacity-scale)
23. [Content Density](#23-content-density)
24. [Print Styles](#24-print-styles)
25. [CSS Architecture](#25-css-architecture)
26. [Extensibility Guide](#26-extensibility-guide)
27. [Migration from Current Theme](#27-migration-from-current-theme)

---

## 1. Design Principles

These principles resolve ambiguity when no specific rule exists. Apply them in priority order.

1. **Darkness as depth, not absence.** The dark palette is not "no light" -- it is layered surfaces with a cool-blue undertone. Every surface step communicates z-depth. Pure black (`#000`) is never used for backgrounds; it is reserved for true shadows and overlay backdrops.

2. **Color encodes meaning, not decoration.** Every color in the UI has a semantic purpose: severity, node kind, interactive state, or data category. If a color does not map to a meaning, it should not be there. Decoration comes from surface layering and subtle border glow, not from gratuitous color.

3. **Glow over shadow.** Traditional drop shadows are invisible on dark backgrounds. Depth is communicated through border-glow (colored `box-shadow` at low spread) and surface stepping. Hover states illuminate rather than depress.

4. **Redundant encoding.** No information is conveyed through color alone. Severity uses color + icon + label. Node types use color + shape + text tag. Interactive states use color + border + cursor change. This makes the system usable for color-blind users without any special mode.

5. **Cybersecurity visual language.** The aesthetic communicates precision, threat awareness, and technical authority. Monospace for data values. Uppercase tracking for category labels. Hex shapes for graph nodes. Cyan/orange accent duality (scan/alert). No rounded-friendly pastel softness.

6. **Stillness by default.** Animation serves to orient attention, not to entertain. The resting state of the UI is static. Motion occurs only during state transitions, data loading, and user-initiated interactions. Background decorative animation (starfield particles) is extremely subtle and respects `prefers-reduced-motion`.

---

## 2. Token Architecture

Tokens are organized in three layers. Developers should always use semantic tokens; primitive tokens exist only as building blocks for semantic tokens. Component tokens exist only where a component needs to override a semantic default.

### Layer 1: Primitive Tokens

Raw values with no semantic meaning. Never reference these directly in component code.

```css
:root {
  /* --- Primitive: Gray Scale (Slate-Blue undertone) --- */
  --gray-0:   #000000;
  --gray-50:  #050910;
  --gray-100: #0A1120;
  --gray-150: #0D1526;
  --gray-200: #111B2E;
  --gray-250: #151F35;
  --gray-300: #1A2540;
  --gray-350: #1E2B48;
  --gray-400: #263351;
  --gray-500: #334766;
  --gray-600: #475B7A;
  --gray-700: #64788F;
  --gray-800: #8899A8;
  --gray-900: #B0BEC5;
  --gray-950: #D7DEE3;
  --gray-1000: #EDF0F3;

  /* --- Primitive: Brand Accents --- */
  --cyan-400:    #22D3EE;
  --cyan-500:    #06B6D4;
  --cyan-600:    #0891B2;
  --cyan-700:    #0E7490;
  --orange-400:  #FB923C;
  --orange-500:  #F97316;
  --orange-600:  #EA580C;

  /* --- Primitive: Severity --- */
  --red-400:     #F87171;
  --red-500:     #EF4444;
  --red-600:     #DC2626;
  --red-700:     #B91C1C;
  --red-900:     #7F1D1D;
  --amber-400:   #FBBF24;
  --amber-500:   #F59E0B;
  --amber-600:   #D97706;
  --amber-900:   #78350F;
  --yellow-400:  #FACC15;
  --yellow-500:  #EAB308;
  --yellow-600:  #CA8A04;
  --yellow-900:  #713F12;
  --green-400:   #4ADE80;
  --green-500:   #22C55E;
  --green-600:   #16A34A;
  --blue-400:    #60A5FA;
  --blue-500:    #3B82F6;
  --blue-600:    #2563EB;
  --purple-400:  #C084FC;
  --purple-500:  #A855F7;
  --purple-600:  #9333EA;
  --pink-400:    #F472B6;
  --pink-500:    #EC4899;

  /* --- Primitive: Radius --- */
  --radius-xs:   4px;
  --radius-sm:   6px;
  --radius-md:   8px;
  --radius-lg:   12px;
  --radius-xl:   16px;
  --radius-2xl:  20px;
  --radius-full: 9999px;
}
```

### Layer 2: Semantic Tokens

Map primitive values to UI roles. These are the primary interface for developers.

```css
:root {
  /* === SURFACES ===
     Surfaces step from darkest (base) to lightest (raised-2).
     Each step is ~2-4 lightness points in HSL.
     This matches the ByteArmor layering model.
  */
  --surface-base:      var(--gray-50);   /* #050910 -- page background */
  --surface-sunken:    var(--gray-100);  /* #0A1120 -- inset areas, wells */
  --surface-default:   var(--gray-150);  /* #0D1526 -- cards, panels */
  --surface-raised:    var(--gray-200);  /* #111B2E -- popovers, dropdowns */
  --surface-raised-2:  var(--gray-250);  /* #151F35 -- nested raised, hover bg */
  --surface-overlay:   rgba(0, 0, 0, 0.75); /* modal backdrop */

  /* === BORDERS ===
     Borders use rgba white for consistency across surface levels.
  */
  --border-subtle:     rgba(255, 255, 255, 0.06);
  --border-default:    rgba(255, 255, 255, 0.10);
  --border-emphasis:   rgba(255, 255, 255, 0.16);
  --border-strong:     rgba(255, 255, 255, 0.24);

  /* === TEXT ===
     Luminance contrast targets (against --surface-default #0D1526):
       --text-primary:   ~15.2:1  (AAA)
       --text-secondary: ~8.1:1   (AAA)
       --text-tertiary:  ~4.7:1   (AA)
       --text-disabled:  ~2.8:1   (decorative only, not standalone)
  */
  --text-primary:      var(--gray-1000); /* #EDF0F3 */
  --text-secondary:    var(--gray-900);  /* #B0BEC5 */
  --text-tertiary:     var(--gray-700);  /* #64788F */
  --text-disabled:     var(--gray-600);  /* #475B7A */
  --text-inverse:      var(--gray-100);  /* #0A1120 -- text on light bg */
  --text-link:         var(--cyan-400);  /* #22D3EE */
  --text-link-hover:   var(--cyan-500);  /* #06B6D4 */

  /* === ACCENTS ===
     Two-accent system: Cyan for navigation/interactive, Orange for action/emphasis.
  */
  --accent-primary:      var(--cyan-500);    /* Interactive accent */
  --accent-primary-fg:   var(--gray-100);    /* Text on accent bg */
  --accent-primary-muted: rgba(6, 182, 212, 0.15);  /* Subtle accent bg */
  --accent-primary-glow:  rgba(6, 182, 212, 0.35);  /* Focus/hover glow */

  --accent-emphasis:       var(--orange-500);  /* Action accent */
  --accent-emphasis-fg:    var(--gray-100);
  --accent-emphasis-muted: rgba(249, 115, 22, 0.15);
  --accent-emphasis-glow:  rgba(249, 115, 22, 0.35);

  /* === SEVERITY ===
     Each severity has: solid, muted background, muted text, and border.
     Muted backgrounds are used for badges/pills; solid for filled indicators.
  */
  --severity-critical:        var(--red-500);
  --severity-critical-bg:     rgba(239, 68, 68, 0.12);
  --severity-critical-text:   var(--red-400);
  --severity-critical-border: rgba(239, 68, 68, 0.30);

  --severity-high:            var(--orange-500);
  --severity-high-bg:         rgba(249, 115, 22, 0.12);
  --severity-high-text:       var(--orange-400);
  --severity-high-border:     rgba(249, 115, 22, 0.30);

  --severity-medium:          var(--yellow-500);
  --severity-medium-bg:       rgba(234, 179, 8, 0.12);
  --severity-medium-text:     var(--yellow-400);
  --severity-medium-border:   rgba(234, 179, 8, 0.30);

  --severity-low:             var(--gray-700);
  --severity-low-bg:          rgba(100, 120, 143, 0.12);
  --severity-low-text:        var(--gray-800);
  --severity-low-border:      rgba(100, 120, 143, 0.20);

  --severity-info:            var(--blue-500);
  --severity-info-bg:         rgba(59, 130, 246, 0.12);
  --severity-info-text:       var(--blue-400);
  --severity-info-border:     rgba(59, 130, 246, 0.30);

  /* === FEEDBACK ===
     Success, warning, error, info for form validation and system messages.
  */
  --feedback-success:         var(--green-500);
  --feedback-success-bg:      rgba(34, 197, 94, 0.12);
  --feedback-success-text:    var(--green-400);
  --feedback-success-border:  rgba(34, 197, 94, 0.30);

  --feedback-warning:         var(--amber-500);
  --feedback-warning-bg:      rgba(245, 158, 11, 0.12);
  --feedback-warning-text:    var(--amber-400);
  --feedback-warning-border:  rgba(245, 158, 11, 0.30);

  --feedback-error:           var(--red-500);
  --feedback-error-bg:        rgba(239, 68, 68, 0.12);
  --feedback-error-text:      var(--red-400);
  --feedback-error-border:    rgba(239, 68, 68, 0.30);

  --feedback-info:            var(--blue-500);
  --feedback-info-bg:         rgba(59, 130, 246, 0.12);
  --feedback-info-text:       var(--blue-400);
  --feedback-info-border:     rgba(59, 130, 246, 0.30);
}
```

### Layer 3: Component Tokens

Override semantic defaults for specific components. Only create these when a component needs to deviate from semantic norms. These are set as CSS custom properties scoped to the component, or as Tailwind class overrides.

```css
/* Example: Card component tokens */
.card {
  --card-bg: var(--surface-default);
  --card-border: var(--border-subtle);
  --card-border-hover: var(--border-emphasis);
  --card-radius: var(--radius-xl);
}

/* Example: Explorer canvas tokens */
.explorer-canvas {
  --canvas-bg: #050B18;
  --canvas-grid: rgba(255, 255, 255, 0.02);
  --canvas-node-fill: #0B1220;
}
```

### Token Decision Tree

When styling a new element, follow this decision tree:

```
Does a semantic token exist for this purpose?
  YES --> Use the semantic token.
  NO  --> Does this need apply to more than one component?
    YES --> Create a new semantic token.
    NO  --> Use a component token or inline Tailwind utility.
         (Never create a semantic token for a single-use case.)
```

---

## 3. Color System

### 3.1 Surface Palette

The surface system uses a 5-step background ramp with a consistent blue-slate undertone. All values share the same hue range (~215-220 HSL) to maintain visual cohesion.

| Token | Hex | HSL (approx.) | Use Case |
|-------|-----|---------------|----------|
| `surface-base` | `#050910` | 218 50% 3% | Page background |
| `surface-sunken` | `#0A1120` | 218 53% 8% | Inset wells, code blocks |
| `surface-default` | `#0D1526` | 218 50% 10% | Cards, panels, sidebar |
| `surface-raised` | `#111B2E` | 218 47% 12% | Popovers, dropdowns, tooltips |
| `surface-raised-2` | `#151F35` | 218 42% 15% | Nested modals, hover states |
| `surface-overlay` | `rgba(0,0,0,0.75)` | -- | Modal/dialog backdrop |

**Glass effect** (for floating toolbars like LensBar and Legend):
```css
.glass-surface {
  background: rgba(5, 11, 24, 0.90);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border: 1px solid rgba(255, 255, 255, 0.08);
}
```

**Noise texture** (optional, for card depth):
```css
.noise-texture::after {
  content: '';
  position: absolute;
  inset: 0;
  background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='256' height='256' filter='url(%23n)' opacity='0.015'/%3E%3C/svg%3E");
  background-repeat: repeat;
  pointer-events: none;
  border-radius: inherit;
  z-index: 0;
}
```

### 3.2 Node Kind Colors

These are the canonical colors for graph node types. They are used in the graph explorer, badges, legends, and any place a node type is referenced visually.

| Node Kind | Hex | Tailwind Class | Contrast on surface-default | Purpose |
|-----------|-----|----------------|-----------------------------|---------|
| `AgentInstance` | `#06B6D4` | `text-cyan-500` | 5.1:1 AA | Entry point, orchestrator |
| `A2AAgent` | `#A855F7` | `text-purple-500` | 4.6:1 AA | Cross-protocol agent |
| `MCPServer` | `#10B981` | `text-emerald-500` | 5.2:1 AA | Server/service |
| `MCPTool` | `#F59E0B` | `text-amber-500` | 7.1:1 AAA | Capability |
| `MCPResource` | `#EF4444` | `text-red-500` | 4.8:1 AA | Sensitive target |
| `MCPPrompt` | `#FB923C` | `text-orange-400` | 6.2:1 AAA | Prompt template |
| `A2ASkill` | `#C084FC` | `text-purple-400` | 5.5:1 AA | Agent capability |
| `Host` | `#475569` | `text-slate-600` | 2.5:1 (always paired with label) | Infrastructure |
| `Identity` | `#94A3B8` | `text-slate-400` | 5.3:1 AA | Auth identity |
| `Credential` | `#EC4899` | `text-pink-500` | 5.0:1 AA | Sensitive secret |
| `ConfigFile` | `#D97706` | `text-amber-600` | 5.4:1 AA | Configuration |
| `InstructionFile` | `#EAB308` | `text-yellow-500` | 7.8:1 AAA | Instruction file |
| `ResourceGroup` | `#64748B` | `text-slate-500` | 3.2:1 (decorative, always labeled) | Synthetic group |
| `TrustZone` | `#22D3EE` | `text-cyan-400` | 6.8:1 AAA | Synthetic zone |

**Accessibility note:** `Host` and `ResourceGroup` have contrast ratios below 4.5:1. These are always paired with a text label and never used as standalone color indicators. In any context where they appear in isolation (e.g., a legend), they must be accompanied by their text name.

### 3.3 Edge Category Colors

| Category | Hex | Use |
|----------|-----|-----|
| Attack | `#FF2D2D` | CAN_REACH, CAN_EXFILTRATE, SHADOWS, POISONED |
| Trust | `#4A90D9` | TRUSTS_SERVER, AUTHENTICATES_WITH, DELEGATES_TO |
| Structure | `#666666` | PROVIDES_TOOL, RUNS_ON, CONFIGURED_IN |

### 3.4 Severity Colors

| Level | Solid | Badge BG | Badge Text | Left Border | Icon |
|-------|-------|----------|------------|-------------|------|
| Critical | `#EF4444` | `rgba(239,68,68,0.12)` | `#F87171` | `#EF4444` | `AlertOctagon` |
| High | `#F97316` | `rgba(249,115,22,0.12)` | `#FB923C` | `#F97316` | `AlertTriangle` |
| Medium | `#EAB308` | `rgba(234,179,8,0.12)` | `#FACC15` | `#EAB308` | `AlertCircle` |
| Low | `#64788F` | `rgba(100,120,143,0.12)` | `#8899A8` | `#64788F` | `Info` |
| Info | `#3B82F6` | `rgba(59,130,246,0.12)` | `#60A5FA` | `#3B82F6` | `Info` |

**Color-blind safe encoding:** Severity is always communicated through:
1. Color (hue)
2. Icon shape (different icon per level -- octagon, triangle, circle, info)
3. Text label (CRITICAL, HIGH, MEDIUM, LOW, INFO)
4. Optional left border (colored stripe on list items)

This triple redundancy ensures usability across protanopia, deuteranopia, and tritanopia.

### 3.5 Data Visualization Palette

For charts where multiple series need distinct colors (not severity-mapped):

```
Series 1: #06B6D4 (cyan-500)
Series 2: #A855F7 (purple-500)
Series 3: #10B981 (emerald-500)
Series 4: #F59E0B (amber-500)
Series 5: #EC4899 (pink-500)
Series 6: #3B82F6 (blue-500)
Series 7: #EF4444 (red-500)
Series 8: #22D3EE (cyan-400)
```

This palette is derived from the node-kind colors to maintain visual consistency. Maximum 8 series; beyond 8, aggregate into "Other".

---

## 4. Typography

### 4.1 Font Stack

```css
:root {
  --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  --font-mono: 'JetBrains Mono', 'Fira Code', 'SF Mono', Menlo, monospace;
}
```

Inter is the primary typeface for its geometric precision and excellent readability at small sizes on screen. JetBrains Mono for data values, code, and technical identifiers because of its coding ligatures and distinct character shapes (1/l/I, 0/O).

### 4.2 Type Scale

| Token | Size | Line Height | Weight | Letter Spacing | Use |
|-------|------|-------------|--------|----------------|-----|
| `text-display` | 36px / 2.25rem | 1.1 | 700 | -0.02em | Hero stats (exposure score) |
| `text-title-lg` | 24px / 1.5rem | 1.2 | 600 | -0.015em | Page titles |
| `text-title` | 20px / 1.25rem | 1.25 | 600 | -0.01em | Card titles, section headers |
| `text-title-sm` | 16px / 1rem | 1.3 | 600 | 0 | Subsection headers |
| `text-body` | 14px / 0.875rem | 1.5 | 400 | 0 | Body text, descriptions |
| `text-body-sm` | 13px / 0.8125rem | 1.45 | 400 | 0 | Secondary body text |
| `text-caption` | 12px / 0.75rem | 1.4 | 500 | 0 | Captions, helper text |
| `text-label` | 11px / 0.6875rem | 1.3 | 600 | 0.06em | Uppercase labels, badges |
| `text-overline` | 10px / 0.625rem | 1.3 | 600 | 0.12em | Category tags, metadata overlines |
| `text-micro` | 9px / 0.5625rem | 1.3 | 600 | 0.1em | Hex node kind tags |
| `text-data` | 14px / 0.875rem | 1.3 | 500 | 0 | Monospace data values |
| `text-data-lg` | 28px / 1.75rem | 1.1 | 700 | -0.01em | Monospace stat numbers |

### 4.3 Typography Rules

- **Labels and overlines** are always uppercase with tracked letter-spacing. Use `text-label` or `text-overline` tokens, never manually set `uppercase` without the matching spacing.
- **Data values** (counts, scores, percentages, IDs, hashes) always use `font-mono`. This signals "this is machine data" to the user.
- **Never go below 11px** for interactive text. The `text-overline` (10px) and `text-micro` (9px) sizes are reserved for decorative/supplementary labels that are always accompanied by a larger interactive element.
- **Minimum font weight on dark backgrounds:** 400. Light fonts (300, 200) have poor contrast rendering on dark backgrounds in many OS/browser combinations.

### 4.4 Tailwind Config for Typography

```typescript
// In tailwind.config.ts theme.extend
fontFamily: {
  sans: ['Inter', ...defaultTheme.fontFamily.sans],
  mono: ['JetBrains Mono', 'Fira Code', ...defaultTheme.fontFamily.mono],
},
fontSize: {
  'display': ['2.25rem', { lineHeight: '1.1', fontWeight: '700', letterSpacing: '-0.02em' }],
  'title-lg': ['1.5rem', { lineHeight: '1.2', fontWeight: '600', letterSpacing: '-0.015em' }],
  'title': ['1.25rem', { lineHeight: '1.25', fontWeight: '600', letterSpacing: '-0.01em' }],
  'title-sm': ['1rem', { lineHeight: '1.3', fontWeight: '600' }],
  'body': ['0.875rem', { lineHeight: '1.5', fontWeight: '400' }],
  'body-sm': ['0.8125rem', { lineHeight: '1.45', fontWeight: '400' }],
  'caption': ['0.75rem', { lineHeight: '1.4', fontWeight: '500' }],
  'label': ['0.6875rem', { lineHeight: '1.3', fontWeight: '600', letterSpacing: '0.06em' }],
  'overline': ['0.625rem', { lineHeight: '1.3', fontWeight: '600', letterSpacing: '0.12em' }],
},
```

---

## 5. Spacing & Layout

### 5.1 Spacing Scale

The spacing scale uses a 4px base unit. All spacing values are multiples of 4px to maintain vertical and horizontal rhythm.

| Token | Value | Tailwind | Use |
|-------|-------|----------|-----|
| `space-0` | 0 | `0` | Reset |
| `space-px` | 1px | `px` | Hairline separator |
| `space-0.5` | 2px | `0.5` | Micro gap (icon adjustment) |
| `space-1` | 4px | `1` | Tight inline spacing |
| `space-1.5` | 6px | `1.5` | Badge padding, compact gaps |
| `space-2` | 8px | `2` | Default inline gap, small padding |
| `space-3` | 12px | `3` | Default card content padding |
| `space-4` | 16px | `4` | Section spacing, card padding |
| `space-5` | 20px | `5` | Card header padding |
| `space-6` | 24px | `6` | Page padding, section gaps |
| `space-8` | 32px | `8` | Large section gaps |
| `space-10` | 40px | `10` | Page-level vertical rhythm |
| `space-12` | 48px | `12` | Major section separator |
| `space-16` | 64px | `16` | Empty state vertical centering |

### 5.2 Layout Grid

```
+-------+---------------------------------------------+
| NavBar (h-12, full width, sticky top)               |
+-------+---------------------------------------------+
| Sidebar|         Main Content Area                  |
| (w-64) |  Padding: 24px (p-6)                       |
| or     |  Max content: 1400px                        |
| hidden |  Grid: 12-column implicit                   |
|        |                                             |
+--------+---------------------------------------------+
```

**Sidebar:**
- Collapsed (explorer): hidden
- Default: `w-[380px]` right-side inspector panel
- NavBar: horizontal top bar `h-12` with icon+label links

**Main content:**
- Padding: `p-6` (24px all sides)
- Maximum width: `max-w-[1400px] mx-auto` for detail pages
- Grid gaps: `gap-4` (16px) for tight grids, `gap-6` (24px) for section grids

**Card grid patterns:**
```
Stat cards:     grid grid-cols-2 sm:grid-cols-5 gap-4
Dashboard 2-up: grid gap-6 lg:grid-cols-2
Detail 5-col:   grid grid-cols-1 lg:grid-cols-5 gap-6
```

---

## 6. Responsive System

### 6.1 Breakpoints

Aligned with Tailwind defaults. No custom breakpoints -- the standard set covers all use cases.

| Breakpoint | Min Width | Layout Change |
|------------|-----------|---------------|
| `sm` | 640px | Stat cards go from 2-col to 5-col. Search inputs expand. |
| `md` | 768px | Inspector sidebar appears. Dashboard grids go 2-col. |
| `lg` | 1024px | Full dashboard layout. Finding detail 5-col grid. |
| `xl` | 1280px | Explorer canvas gets more breathing room. |
| `2xl` | 1536px | Max content width reached. Side margins grow. |

### 6.2 Responsive Behaviors

**NavBar:**
- `>= md`: Full icon+label nav links
- `< md`: Hamburger menu with slide-out nav panel. Health indicator moves into hamburger panel.

**Inspector Sidebar:**
- `>= md`: Right-side panel at `w-[380px]`
- `< md`: Full-screen bottom sheet (slides up from bottom, 80vh max height)

**Stat Cards:**
- `>= sm`: 5 columns
- `< sm`: 2 columns, 3rd row wraps

**Dashboard Grid:**
- `>= lg`: 2-column side-by-side
- `< lg`: Single column stacked

**Explorer:**
- Fills available viewport at all sizes
- LensBar: horizontal scroll with fade indicators on small screens
- Legend: collapsed to icon-only toggle on `< md`

**Finding Detail:**
- `>= lg`: 3-col + 2-col side-by-side
- `< lg`: Full-width stacked

**Touch Targets:**
- All interactive elements: minimum 44x44px touch target (achieved via padding, not element size)
- Buttons: `min-h-[44px]` on mobile
- Nav links: `py-3` on mobile to meet 44px

### 6.3 Container Queries (future-safe)

For components that may be rendered in different contexts (sidebar vs. main content), use Tailwind's `@container` queries when available. Until then, use the responsive breakpoint system.

---

## 7. Elevation & Depth

### 7.1 Elevation Model

No traditional box-shadow drop shadows. Depth is communicated through surface stepping and border glow.

| Elevation | Surface | Border | Glow | Use |
|-----------|---------|--------|------|-----|
| `e-0` (base) | `surface-base` | none | none | Page background |
| `e-1` (sunken) | `surface-sunken` | `border-subtle` | none | Code blocks, wells |
| `e-2` (default) | `surface-default` | `border-subtle` | none | Cards, nav, sidebar |
| `e-3` (raised) | `surface-raised` | `border-default` | none | Dropdowns, popovers |
| `e-4` (overlay) | `surface-raised-2` | `border-emphasis` | Subtle colored glow | Modals, command palette |
| `e-5` (urgent) | `surface-raised-2` | colored border | Strong colored glow | Active alerts, selected items |

### 7.2 Glow Specifications

Glow replaces shadow as the primary depth indicator for interactive states.

```css
/* Hover glow -- applied to cards and interactive surfaces */
.glow-hover {
  box-shadow: 0 0 0 1px rgba(6, 182, 212, 0.20),
              0 0 20px -4px rgba(6, 182, 212, 0.15);
}

/* Active/selected glow -- stronger, warmer */
.glow-active {
  box-shadow: 0 0 0 1px rgba(249, 115, 22, 0.40),
              0 0 24px -4px rgba(249, 115, 22, 0.25);
}

/* Focus glow -- high-visibility for keyboard nav */
.glow-focus {
  box-shadow: 0 0 0 2px var(--surface-default),
              0 0 0 4px rgba(6, 182, 212, 0.60);
}

/* Severity glow -- applied to hex nodes and alert items */
.glow-critical {
  box-shadow: 0 0 0 1px rgba(239, 68, 68, 0.40),
              0 0 20px -4px rgba(239, 68, 68, 0.30);
}

.glow-high {
  box-shadow: 0 0 0 1px rgba(249, 115, 22, 0.40),
              0 0 18px -4px rgba(249, 115, 22, 0.25);
}

.glow-medium {
  box-shadow: 0 0 0 1px rgba(234, 179, 8, 0.35),
              0 0 16px -4px rgba(234, 179, 8, 0.20);
}
```

---

## 8. State System

Every interactive element implements the following state machine. Not all states apply to all elements (e.g., buttons do not have an "empty" state), but the visual treatment is consistent.

### 8.1 Core States

| State | Visual Treatment | CSS |
|-------|-----------------|-----|
| **Default** | Surface + subtle border. No glow. | `bg-[surface-default] border border-[border-subtle]` |
| **Hover** | Surface lightens one step. Border brightens. Cyan glow appears. | `hover:bg-[surface-raised-2] hover:border-[border-emphasis]` + `glow-hover` |
| **Active / Pressed** | Surface darkens slightly from hover. Border color shifts to orange. Glow shifts to orange. | `active:bg-[surface-raised]` + `glow-active` |
| **Focus-visible** | 2px offset ring in cyan. No visual change to surface. Always visible for keyboard navigation, hidden for mouse. | `focus-visible:ring-2 focus-visible:ring-cyan-500 focus-visible:ring-offset-2 focus-visible:ring-offset-[surface-default]` |
| **Selected** | Orange accent border. Muted orange background. Persistent glow. | `border-orange-500/40 bg-orange-500/8` + `glow-active` |
| **Disabled** | 40% opacity. No pointer events. No hover/focus states. | `opacity-40 pointer-events-none cursor-not-allowed` |
| **Loading** | Skeleton shimmer or spinner replaces content. Surface maintained. | See section 14.3 |
| **Error** | Red border. Red glow. Error message below. | `border-red-500/40` + `glow-critical` |
| **Success** | Green border. Brief green glow (fades after 2s). | `border-green-500/40` + transient green glow |

### 8.2 State Specifics by Component

**Buttons (primary):**
```
Default:       bg-cyan-600 text-[#0A1120] font-medium
Hover:         bg-cyan-500 shadow-[0_0_20px_-4px_rgba(6,182,212,0.4)]
Active:        bg-cyan-700
Focus-visible: ring-2 ring-cyan-400 ring-offset-2 ring-offset-[#050910]
Disabled:      bg-cyan-600/40 text-[#0A1120]/40 cursor-not-allowed
Loading:       bg-cyan-600/70 with spinner replacing text
```
Note: Dark text on cyan bg (7.8:1 AAA). White on cyan fails WCAG (2.4:1).

**Ghost Buttons:**
```
Default:       bg-transparent text-secondary
Hover:         bg-white/5 text-primary
Active:        bg-white/8
Focus-visible: ring-2 ring-cyan-400/60
```

**Cards:**
```
Default:       bg-surface-default border-subtle rounded-xl
Hover:         border-emphasis + glow-hover (only if card is clickable)
Selected:      border-orange-500/40 bg-orange-500/5 + glow-active
```

**Nav Links:**
```
Default:       text-secondary bg-transparent
Hover:         text-primary bg-white/5
Active:        text-cyan-400 bg-cyan-500/10 font-medium
```

**Table Rows:**
```
Default:       bg-transparent
Hover:         bg-white/3
Selected:      bg-cyan-500/8 border-l-2 border-l-cyan-500
Striped (alt): bg-white/[0.015]
```

**Form Inputs:**
```
Default:       bg-surface-sunken border-subtle
Hover:         border-emphasis
Focus:         border-cyan-500/50 ring-1 ring-cyan-500/20
Error:         border-red-500/50 ring-1 ring-red-500/20
Disabled:      bg-surface-sunken/50 opacity-50
```

---

## 9. Motion & Animation

### 9.1 Duration Scale

| Token | Duration | Use |
|-------|----------|-----|
| `duration-instant` | 50ms | Color changes (hover bg) |
| `duration-fast` | 100ms | Border transitions, opacity |
| `duration-normal` | 150ms | Most transitions (default) |
| `duration-moderate` | 200ms | Panel slides, card transforms |
| `duration-slow` | 300ms | Modal enter, page transitions |
| `duration-slower` | 500ms | Complex choreography |
| `duration-loading` | 1500ms | Skeleton shimmer cycle |

### 9.2 Easing Functions

```css
:root {
  --ease-out:     cubic-bezier(0.16, 1, 0.3, 1);    /* Decelerate: panels entering */
  --ease-in:      cubic-bezier(0.7, 0, 0.84, 0);    /* Accelerate: panels exiting */
  --ease-in-out:  cubic-bezier(0.65, 0, 0.35, 1);   /* Symmetric: position changes */
  --ease-bounce:  cubic-bezier(0.34, 1.56, 0.64, 1); /* Overshoot: attention elements */
  --ease-spring:  cubic-bezier(0.22, 1, 0.36, 1);   /* Spring-like: interactive feedback */
}
```

### 9.3 Transition Defaults

```css
/* Applied via Tailwind `transition` classes */
.transition-default {
  transition-property: background-color, border-color, color, box-shadow, opacity;
  transition-duration: 150ms;
  transition-timing-function: cubic-bezier(0.16, 1, 0.3, 1);
}

.transition-transform {
  transition-property: transform, opacity;
  transition-duration: 200ms;
  transition-timing-function: cubic-bezier(0.16, 1, 0.3, 1);
}
```

### 9.4 Enter/Exit Animations

**Modal / Dialog:**
```
Enter:  opacity 0->1 (200ms ease-out) + scale 0.95->1 (200ms ease-out)
Exit:   opacity 1->0 (150ms ease-in) + scale 1->0.95 (150ms ease-in)
Overlay: opacity 0->1 (200ms ease-out) / 1->0 (150ms ease-in)
```

**Toast / Notification:**
```
Enter:  translateY(16px)->0 + opacity 0->1 (200ms ease-out)
Exit:   translateX(100%)->0 + opacity 1->0 (150ms ease-in)
Stack:  existing toasts translateY up by toast height (200ms ease-out)
```

**Sidebar Panel:**
```
Enter:  translateX(100%)->0 (300ms ease-out) from right
Exit:   translateX(0)->100% (200ms ease-in) to right
```

**Bottom Sheet (mobile):**
```
Enter:  translateY(100%)->0 (300ms ease-out)
Exit:   translateY(0)->100% (200ms ease-in)
Drag:   follows finger position, snaps to open/closed on release
```

**Dropdown / Popover:**
```
Enter:  opacity 0->1 + scale 0.95->1 + translateY(-4px)->0 (150ms ease-out)
Exit:   opacity 1->0 + scale 1->0.95 (100ms ease-in)
```

**Staggered List Items:**
```
Each item: opacity 0->1 + translateY(8px)->0
Stagger delay: 30ms per item, max 10 items animated (items 11+ appear instantly)
Duration: 200ms per item, ease-out
```

### 9.5 Skeleton Loading Shimmer

```css
@keyframes shimmer {
  0% {
    background-position: -200% 0;
  }
  100% {
    background-position: 200% 0;
  }
}

.skeleton {
  background: linear-gradient(
    90deg,
    var(--surface-sunken) 25%,
    var(--surface-raised) 50%,
    var(--surface-sunken) 75%
  );
  background-size: 200% 100%;
  animation: shimmer 1.5s ease-in-out infinite;
  border-radius: var(--radius-md);
}
```

### 9.6 Reduced Motion

```css
@media (prefers-reduced-motion: reduce) {
  *,
  *::before,
  *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }

  .skeleton {
    animation: none;
    background: var(--surface-sunken);
  }
}
```

When `prefers-reduced-motion: reduce` is active:
- All transitions become instant (effectively disabled)
- Skeleton shimmer becomes a static muted background
- Staggered list items appear all at once
- Modal/toast animations are instant appear/disappear
- Graph layout animation is skipped (nodes placed in final position)
- Background particle effects are disabled entirely

---

## 10. Accessibility

### 10.1 Contrast Ratios

All text/background combinations verified against WCAG 2.1 AA requirements.

| Combination | Ratio | Grade |
|-------------|-------|-------|
| `text-primary` (#EDF0F3) on `surface-default` (#0D1526) | 15.9:1 | AAA |
| `text-secondary` (#B0BEC5) on `surface-default` (#0D1526) | 9.6:1 | AAA |
| `text-tertiary` (#64788F) on `surface-default` (#0D1526) | 4.0:1 | AA-Large only |
| `text-link` (#22D3EE) on `surface-default` (#0D1526) | 10.1:1 | AAA |
| `accent-primary` (#06B6D4) on `surface-default` (#0D1526) | 7.5:1 | AAA |
| `severity-critical-text` (#F87171) on `surface-default` (#0D1526) | 6.6:1 | AA |
| `severity-high-text` (#FB923C) on `surface-default` (#0D1526) | 8.1:1 | AAA |
| `severity-medium-text` (#FACC15) on `surface-default` (#0D1526) | 11.9:1 | AAA |
| White (#FFF) on `accent-primary` (#06B6D4) | 2.4:1 | FAILS -- use dark fg |
| `accent-primary-fg` (#0A1120) on `accent-primary` (#06B6D4) | 7.8:1 | AAA |

**Rule:** `text-tertiary` (#64788F) must only be used for supplementary text that is paired with primary or secondary text. It must never be the sole carrier of information.

**Rule:** White text on cyan buttons fails WCAG AA. Always use dark text (`--accent-primary-fg: #0A1120`) on cyan backgrounds. This applies to all `bg-cyan-*` buttons.

### 10.2 Focus Management

```css
/* Focus ring -- visible only on keyboard navigation (focus-visible) */
:focus-visible {
  outline: none;
  box-shadow:
    0 0 0 2px var(--surface-default),
    0 0 0 4px rgba(6, 182, 212, 0.60);
}

/* Reset for mouse users */
:focus:not(:focus-visible) {
  outline: none;
  box-shadow: none;
}
```

**Focus order:** All interactive elements must be reachable in a logical document order. Modals trap focus. Popovers return focus to trigger on close. The sidebar inspector panel does not trap focus but is included in the tab order.

**Skip links:**
```html
<a href="#main-content" class="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-[100] focus:bg-cyan-600 focus:text-white focus:px-4 focus:py-2 focus:rounded-md">
  Skip to main content
</a>
```

### 10.3 Screen Reader Considerations

- All icon-only buttons have `aria-label`
- Severity badges include the severity level in text (not just color)
- Graph nodes have `aria-label` describing kind and name
- Data visualizations (charts) have `aria-label` summarizing the data
- Decorative SVGs use `aria-hidden="true"`
- Loading states announce via `aria-live="polite"`
- Error states announce via `aria-live="assertive"`
- Toast notifications use `role="alert"` for severity >= high, `role="status"` for info

### 10.4 Color Blind Safe Patterns

Beyond the severity icon/label redundancy:
- Graph nodes use both color AND unique icon per kind (Server, Wrench, Key, etc.)
- Edge types use color AND line style (solid, dashed, dotted)
- Chart bars/slices include value labels, not just color
- The severity filter buttons include text labels, not just colored dots

### 10.5 High Contrast Mode

When `prefers-contrast: more` is detected:

```css
@media (prefers-contrast: more) {
  :root {
    --border-subtle: rgba(255, 255, 255, 0.20);
    --border-default: rgba(255, 255, 255, 0.30);
    --border-emphasis: rgba(255, 255, 255, 0.50);
    --text-tertiary: var(--gray-800); /* bumped from 700 */
    --text-disabled: var(--gray-700); /* bumped from 600 */
  }
}
```

---

## 11. Component Patterns

### 11.1 Card

The primary content container. Matches the ByteArmor card aesthetic: near-black background, subtle border, large radius, optional glow on hover.

```css
.ah-card {
  background: var(--surface-default);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-xl);     /* 16px */
  padding: 0;                          /* padding applied to header/content/footer */
  transition: border-color 150ms ease-out, box-shadow 150ms ease-out;
}

.ah-card:hover {                       /* only when card is interactive */
  border-color: var(--border-emphasis);
  box-shadow: 0 0 0 1px rgba(6, 182, 212, 0.15),
              0 0 20px -4px rgba(6, 182, 212, 0.10);
}

.ah-card--selected {
  border-color: rgba(249, 115, 22, 0.40);
  box-shadow: 0 0 0 1px rgba(249, 115, 22, 0.30),
              0 0 24px -4px rgba(249, 115, 22, 0.20);
}

/* Card sections */
.ah-card-header {
  padding: 20px 24px 12px;
}
.ah-card-content {
  padding: 0 24px 24px;
}
.ah-card-footer {
  padding: 16px 24px;
  border-top: 1px solid var(--border-subtle);
}
```

**Tailwind pattern:**
```tsx
<div className="rounded-xl border border-white/[0.06] bg-[#0D1526] transition-all hover:border-white/[0.16] hover:shadow-[0_0_20px_-4px_rgba(6,182,212,0.15)]">
  {/* ... */}
</div>
```

### 11.2 Stat Card

Large bold number, small muted label above, colored icon badge.

```tsx
<Card className="rounded-xl border-white/[0.06]">
  <CardContent className="pt-4">
    <div className="flex items-center gap-3">
      <div className="rounded-lg bg-cyan-600/15 p-2.5">
        <Icon className="h-5 w-5 text-cyan-400" />
      </div>
      <div>
        <p className="text-overline uppercase text-[--text-tertiary]">Label</p>
        <p className="font-mono text-2xl font-bold text-[--text-primary]">42</p>
      </div>
    </div>
  </CardContent>
</Card>
```

### 11.3 Severity Badge

```tsx
// Critical
<span className="inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-label uppercase
  bg-red-500/12 text-red-400 border-red-500/30">
  <AlertOctagon className="h-3 w-3" />
  Critical
</span>

// High
<span className="... bg-orange-500/12 text-orange-400 border-orange-500/30">
  <AlertTriangle className="h-3 w-3" />
  High
</span>

// Medium
<span className="... bg-yellow-500/12 text-yellow-400 border-yellow-500/30">
  <AlertCircle className="h-3 w-3" />
  Medium
</span>

// Low
<span className="... bg-slate-500/12 text-slate-400 border-slate-500/20">
  <Info className="h-3 w-3" />
  Low
</span>
```

### 11.4 Finding List Item

```tsx
<div className="flex items-start gap-4 rounded-lg border border-white/[0.06] bg-[--surface-default] p-4
  transition-all hover:border-white/[0.12] hover:bg-[--surface-raised-2] cursor-pointer"
  style={{ borderLeft: `3px solid var(--severity-${severity})` }}
>
  <SeverityBadge level={severity} />
  <div className="flex-1 min-w-0">
    <p className="text-body font-medium text-[--text-primary] truncate">{title}</p>
    <p className="text-body-sm text-[--text-secondary] truncate mt-0.5">{description}</p>
  </div>
  <span className="text-caption font-mono text-[--text-tertiary]">{confidence}%</span>
</div>
```

### 11.5 Glass Floating Bar (LensBar, Legend)

```tsx
<div className="rounded-full border border-white/[0.08] bg-[#050B18]/90 px-3 py-2
  shadow-2xl backdrop-blur-xl">
  {/* ... */}
</div>
```

### 11.6 Section Header

```tsx
<div className="flex items-center justify-between">
  <div className="flex items-center gap-2">
    <Icon className="h-5 w-5 text-[--text-tertiary]" />
    <h2 className="text-title-sm text-[--text-primary]">Section Title</h2>
    <span className="text-caption text-[--text-tertiary]">(42)</span>
  </div>
  <Button variant="ghost" size="sm">Action</Button>
</div>
```

---

## 12. Data Visualization

### 12.1 Recharts Theme Object

All Recharts components inherit from this configuration object. Apply it via wrapper components or a shared config.

```typescript
export const CHART_THEME = {
  // Grid
  grid: {
    stroke: 'rgba(255, 255, 255, 0.04)',
    strokeDasharray: '3 3',
  },

  // Axes
  axis: {
    tick: {
      fill: '#64788F',       // text-tertiary
      fontSize: 11,
      fontFamily: 'Inter, sans-serif',
    },
    axisLine: {
      stroke: 'rgba(255, 255, 255, 0.08)',
    },
  },

  // Tooltip
  tooltip: {
    contentStyle: {
      backgroundColor: '#111B2E',          // surface-raised
      border: '1px solid rgba(255,255,255,0.12)',
      borderRadius: 8,
      padding: '8px 12px',
      boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
    },
    labelStyle: {
      color: '#B0BEC5',                    // text-secondary
      fontSize: 11,
      fontWeight: 500,
      marginBottom: 4,
    },
    itemStyle: {
      color: '#EDF0F3',                    // text-primary
      fontSize: 12,
      fontFamily: "'JetBrains Mono', monospace",
      padding: '2px 0',
    },
    cursor: {
      stroke: 'rgba(6, 182, 212, 0.3)',
      strokeWidth: 1,
    },
  },

  // Legend
  legend: {
    wrapperStyle: {
      paddingTop: 8,
    },
    formatter: {
      color: '#8899A8',                    // between text-secondary and tertiary
      fontSize: 11,
    },
  },

  // Area/Line fills
  areaGradient: {
    /* Usage: <defs><linearGradient id="cyan-gradient">
       <stop offset="0%" stopColor="#06B6D4" stopOpacity={0.3}/>
       <stop offset="100%" stopColor="#06B6D4" stopOpacity={0}/>
       </linearGradient></defs> */
  },

  // Colors (matches data viz palette)
  colors: [
    '#06B6D4', '#A855F7', '#10B981', '#F59E0B',
    '#EC4899', '#3B82F6', '#EF4444', '#22D3EE',
  ],
} as const;
```

### 12.2 Pie / Donut Chart

```tsx
<PieChart>
  <Pie
    data={data}
    dataKey="value"
    cx="50%"
    cy="50%"
    innerRadius={50}      // donut
    outerRadius={80}
    paddingAngle={2}      // gap between slices
    strokeWidth={0}       // no stroke between slices
  >
    {data.map((entry, i) => (
      <Cell key={entry.name} fill={CHART_THEME.colors[i % 8]} />
    ))}
  </Pie>
  <Tooltip
    contentStyle={CHART_THEME.tooltip.contentStyle}
    labelStyle={CHART_THEME.tooltip.labelStyle}
    itemStyle={CHART_THEME.tooltip.itemStyle}
  />
</PieChart>
```

### 12.3 Bar Chart

```tsx
<BarChart data={data}>
  <CartesianGrid {...CHART_THEME.grid} />
  <XAxis
    dataKey="name"
    tick={CHART_THEME.axis.tick}
    axisLine={CHART_THEME.axis.axisLine}
    tickLine={false}
  />
  <YAxis
    tick={CHART_THEME.axis.tick}
    axisLine={false}
    tickLine={false}
  />
  <Tooltip
    contentStyle={CHART_THEME.tooltip.contentStyle}
    labelStyle={CHART_THEME.tooltip.labelStyle}
    itemStyle={CHART_THEME.tooltip.itemStyle}
    cursor={{ fill: 'rgba(255,255,255,0.03)' }}
  />
  <Bar dataKey="value" radius={[4, 4, 0, 0]}>
    {data.map((entry, i) => (
      <Cell key={i} fill={getBarColor(entry)} />
    ))}
  </Bar>
</BarChart>
```

### 12.4 Treemap (Risk Chart)

The existing custom treemap implementation uses severity-mapped gradient fills:

```typescript
const TREEMAP_FILLS: Record<string, string> = {
  critical: 'linear-gradient(135deg, #dc2626 0%, #b91c1c 100%)',
  high:     'linear-gradient(135deg, #d97706 0%, #b45309 100%)',
  medium:   'linear-gradient(135deg, #a16207 0%, #854d0e 100%)',
  low:      'linear-gradient(135deg, #475569 0%, #334155 100%)',
};
```

Text inside treemap cells: white with 80% opacity for labels, white at 100% for values. Labels use `text-[11px] font-medium`, values use `font-mono font-bold` with dynamic sizing.

### 12.5 Exposure Score Gauge

The exposure score uses conditional coloring:

| Score Range | Color | Background Class |
|-------------|-------|-----------------|
| 0-39 | `#22C55E` (green) | `bg-green-500/5 border-green-500/20` |
| 40-74 | `#F59E0B` (amber) | `bg-amber-500/5 border-amber-500/20` |
| 75-100 | `#EF4444` (red) | `bg-red-500/5 border-red-500/20` |

Number rendered in `font-mono text-3xl font-bold` with the conditional color.

---

## 13. Graph Explorer Theme

The explorer canvas has its own isolated dark theme, darker than the rest of the app.

### 13.1 Canvas

```css
.explorer-canvas {
  background: #050B18;
}

/* Grid pattern (if using React Flow minimap or bg) */
.react-flow__background pattern line {
  stroke: rgba(255, 255, 255, 0.02);
}
```

### 13.2 Hex Nodes

All hex nodes share:
- Fill: `#0B1220` (darkest, nearly black)
- Stroke: kind-specific color (see 3.2)
- Stroke width: 2.5px
- Vertex dots: kind color at 85% opacity, radius 2.5px
- Label: `text-[11px] font-semibold text-white` with text shadow `0 1px 4px rgba(0,0,0,0.9)`
- Kind tag: `text-[8px] tracking-[0.12em] text-slate-400 font-medium`

### 13.3 Severity Halos

Nodes with findings get a CSS `filter: drop-shadow()` halo:

| Severity | Halo |
|----------|------|
| Critical | `drop-shadow(0 0 10px rgba(239,68,68,0.85)) drop-shadow(0 0 18px rgba(239,68,68,0.45))` |
| High | `drop-shadow(0 0 8px rgba(249,115,22,0.75)) drop-shadow(0 0 16px rgba(249,115,22,0.35))` |
| Medium | `drop-shadow(0 0 6px rgba(234,179,8,0.65)) drop-shadow(0 0 12px rgba(234,179,8,0.3))` |
| Low | `drop-shadow(0 0 4px rgba(148,163,184,0.5))` |

### 13.4 Edges

| Category | Color | Width | Style | Animated |
|----------|-------|-------|-------|----------|
| Attack | `#FF2D2D` | 2.5 + weight*2 | Solid (default), Dashed (CAN_REACH), Dotted (SHADOWS) | Dash animation on hover |
| Trust | `#4A90D9` | 1.5 | Solid | No |
| Structure | `#666666` | 0.8 | Solid | No |

### 13.5 Selection

- Selected node: `ring-2 ring-white ring-offset-2 ring-offset-[#050B18]`
- Hovered node: Scale 1.05x with 200ms ease-out transition
- Dimmed nodes (not in active lens scope): `opacity: 0.08`
- Emphasized nodes: Scale 1.35x

### 13.6 Explorer Overlay Panels

LensBar, Legend, InfoCard, StatusStrip, and NodeDetailDrawer all use the glass surface:
```css
background: rgba(5, 11, 24, 0.90);
backdrop-filter: blur(12px);
border: 1px solid rgba(255, 255, 255, 0.08);
border-radius: var(--radius-lg) to var(--radius-full) depending on component;
box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
```

---

## 14. Empty, Error & Loading States

### 14.1 Empty States

Empty states communicate "no data yet" with clear next actions.

```tsx
// Standard empty state pattern
<div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-white/[0.10] bg-[--surface-sunken] py-16 text-center">
  <Icon className="h-10 w-10 text-[--text-disabled]" />
  <div>
    <p className="text-body font-medium text-[--text-secondary]">
      No findings detected
    </p>
    <p className="text-body-sm text-[--text-tertiary] mt-1 max-w-sm">
      Run a scan to discover attack paths in your MCP and A2A infrastructure.
    </p>
  </div>
  <Button variant="default" size="sm" className="mt-2">
    Run First Scan
  </Button>
</div>
```

**Visual rules for empty states:**
- Dashed border (not solid) -- signals "awaiting content"
- Sunken background (not default surface) -- signals "inert"
- Large icon (h-10 w-10) in `text-disabled` color
- Primary message in `text-secondary`, description in `text-tertiary`
- Single clear CTA button

### 14.2 Error States

```tsx
// Inline error
<div className="flex items-start gap-3 rounded-lg border border-red-500/30 bg-red-500/8 px-4 py-3">
  <AlertOctagon className="h-5 w-5 text-red-400 shrink-0 mt-0.5" />
  <div>
    <p className="text-body font-medium text-red-400">Failed to load graph data</p>
    <p className="text-body-sm text-[--text-tertiary] mt-1">
      Neo4j connection refused. Check that the database is running.
    </p>
    <Button variant="ghost" size="sm" className="mt-2 text-red-400 hover:text-red-300">
      Retry
    </Button>
  </div>
</div>

// Full-page error
<div className="flex flex-col items-center justify-center h-full gap-4 p-6">
  <div className="rounded-xl bg-red-500/10 p-4">
    <AlertOctagon className="h-8 w-8 text-red-400" />
  </div>
  <p className="text-title-sm text-[--text-primary]">Something went wrong</p>
  <p className="text-body text-[--text-tertiary] text-center max-w-md">
    {error.message}
  </p>
  <div className="flex gap-2 mt-2">
    <Button variant="outline" size="sm" onClick={retry}>Retry</Button>
    <Button variant="ghost" size="sm" onClick={() => navigate('/')}>Go to Dashboard</Button>
  </div>
</div>
```

### 14.3 Loading / Skeleton States

Skeletons match the shape and approximate size of the content they replace.

```css
.skeleton {
  background: linear-gradient(
    90deg,
    rgba(255, 255, 255, 0.03) 25%,
    rgba(255, 255, 255, 0.06) 50%,
    rgba(255, 255, 255, 0.03) 75%
  );
  background-size: 200% 100%;
  animation: shimmer 1.5s ease-in-out infinite;
  border-radius: var(--radius-md);
}
```

**Skeleton sizing rules:**
- Stat cards: Match exact card dimensions (`h-[76px]`)
- Charts: Match chart container height (`h-52`)
- Table rows: Match row height (`h-14`), 8 rows
- Text blocks: Width varies (60-90%), height matches line height
- Always wrap skeletons in the same container structure as real content

**Spinner** (for inline loading, e.g., buttons):
```tsx
<svg className="animate-spin h-4 w-4 text-current" viewBox="0 0 24 24">
  <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3"
    fill="none" strokeLinecap="round" strokeDasharray="60 200" />
</svg>
```

### 14.4 First-Run Experience

When the user opens AgentHound for the first time (no scans, no data):

The dashboard shows:
- Stat cards at 0
- Empty states in all chart slots with "No data yet" + CTA to run first scan
- ExposureScore shows 0 in green
- A prominent banner at the top:

```tsx
<div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-6">
  <div className="flex items-start gap-4">
    <div className="rounded-lg bg-cyan-500/15 p-3">
      <Shield className="h-6 w-6 text-cyan-400" />
    </div>
    <div>
      <h3 className="text-title-sm text-[--text-primary]">Welcome to AgentHound</h3>
      <p className="text-body text-[--text-secondary] mt-1 max-w-2xl">
        Start by running a scan to discover MCP servers, A2A agents, and attack paths
        in your AI agent infrastructure.
      </p>
      <div className="flex gap-2 mt-4">
        <Button onClick={() => navigate('/scans')}>Run First Scan</Button>
        <Button variant="ghost">View Documentation</Button>
      </div>
    </div>
  </div>
</div>
```

---

## 15. Notification & Toast System

### 15.1 Position and Stacking

Toasts appear in the **bottom-right** corner, stacked vertically with 8px gap.

```
Position: fixed, bottom: 24px, right: 24px
Width: 380px (fixed)
Max visible: 5 (excess queued, shown on dismiss)
Stack direction: bottom-up (newest at bottom)
Z-index: var(--z-toast) = 90
```

### 15.2 Toast Variants

```tsx
// Info toast
<div className="flex items-start gap-3 rounded-xl border border-blue-500/20 bg-[--surface-raised] p-4 shadow-[0_8px_32px_rgba(0,0,0,0.5)]">
  <Info className="h-5 w-5 text-blue-400 shrink-0 mt-0.5" />
  <div className="flex-1">
    <p className="text-body font-medium text-[--text-primary]">Scan queued</p>
    <p className="text-body-sm text-[--text-tertiary] mt-0.5">Config collector started.</p>
  </div>
  <button className="text-[--text-tertiary] hover:text-[--text-primary]">
    <X className="h-4 w-4" />
  </button>
</div>

// Success toast
<div className="... border-green-500/20">
  <CheckCircle className="h-5 w-5 text-green-400 ..." />
  ...
</div>

// Warning toast
<div className="... border-amber-500/20">
  <AlertTriangle className="h-5 w-5 text-amber-400 ..." />
  ...
</div>

// Error toast
<div className="... border-red-500/20">
  <AlertOctagon className="h-5 w-5 text-red-400 ..." />
  ...
</div>
```

### 15.3 Auto-Dismiss Timing

| Severity | Duration | Rationale |
|----------|----------|-----------|
| Info | 4000ms | Low urgency, quick acknowledgment |
| Success | 3000ms | Confirmation, user expects it |
| Warning | 6000ms | Needs reading time |
| Error | No auto-dismiss | User must acknowledge, may need to copy text |

### 15.4 Animation

```
Enter:   translateY(16px) -> 0, opacity 0 -> 1, 200ms ease-out
Exit:    translateX(0) -> 100%, opacity 1 -> 0, 150ms ease-in
Stack:   existing toasts translateY(-toast-height - 8px), 200ms ease-out
```

---

## 16. Form System

### 16.1 Input

```tsx
<div className="space-y-1.5">
  <label className="text-caption font-medium text-[--text-secondary]" htmlFor="input-id">
    Label
  </label>
  <input
    id="input-id"
    className="h-10 w-full rounded-lg border border-white/[0.10] bg-[--surface-sunken] px-3 text-body text-[--text-primary]
      placeholder:text-[--text-disabled]
      transition-all duration-150
      hover:border-white/[0.16]
      focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 focus:outline-none
      disabled:opacity-50 disabled:cursor-not-allowed"
    placeholder="Placeholder text"
  />
  <p className="text-caption text-[--text-tertiary]">Helper text goes here.</p>
</div>
```

### 16.2 Validation States

**Error:**
```tsx
<input className="... border-red-500/50 focus:ring-red-500/20" aria-invalid="true" aria-describedby="error-id" />
<p id="error-id" className="text-caption text-red-400 flex items-center gap-1">
  <AlertCircle className="h-3 w-3" /> This field is required
</p>
```

**Warning:**
```tsx
<input className="... border-amber-500/40 focus:ring-amber-500/20" />
<p className="text-caption text-amber-400 flex items-center gap-1">
  <AlertTriangle className="h-3 w-3" /> This value looks unusual
</p>
```

**Success:**
```tsx
<input className="... border-green-500/40" />
<p className="text-caption text-green-400 flex items-center gap-1">
  <CheckCircle className="h-3 w-3" /> Endpoint verified
</p>
```

### 16.3 Select

```tsx
<select className="h-10 w-full rounded-lg border border-white/[0.10] bg-[--surface-sunken] px-3 text-body text-[--text-primary]
  appearance-none bg-[url('data:image/svg+xml,...chevron...')] bg-[right_12px_center] bg-no-repeat
  hover:border-white/[0.16]
  focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 focus:outline-none">
  <option>Option 1</option>
</select>
```

### 16.4 Checkbox and Radio

```tsx
// Checkbox
<label className="flex items-center gap-2 cursor-pointer">
  <div className="flex h-4 w-4 items-center justify-center rounded border border-white/[0.16] bg-[--surface-sunken]
    data-[state=checked]:bg-cyan-600 data-[state=checked]:border-cyan-500
    transition-colors">
    {checked && <Check className="h-3 w-3 text-white" strokeWidth={3} />}
  </div>
  <span className="text-body text-[--text-secondary]">Label</span>
</label>

// Radio
<label className="flex items-center gap-2 cursor-pointer">
  <div className="flex h-4 w-4 items-center justify-center rounded-full border border-white/[0.16] bg-[--surface-sunken]
    data-[state=checked]:border-cyan-500
    transition-colors">
    {checked && <div className="h-2 w-2 rounded-full bg-cyan-500" />}
  </div>
  <span className="text-body text-[--text-secondary]">Label</span>
</label>
```

### 16.5 Toggle Switch

```tsx
<button
  role="switch"
  aria-checked={enabled}
  className={cn(
    "relative h-6 w-11 rounded-full transition-colors duration-200",
    enabled ? "bg-cyan-600" : "bg-[--surface-raised-2] border border-white/[0.10]"
  )}
>
  <span className={cn(
    "block h-5 w-5 rounded-full bg-white shadow-sm transition-transform duration-200",
    enabled ? "translate-x-5" : "translate-x-0.5"
  )} />
</button>
```

### 16.6 Slider

```css
input[type="range"] {
  -webkit-appearance: none;
  appearance: none;
  width: 100%;
  height: 6px;
  background: var(--surface-raised-2);
  border-radius: 9999px;
  outline: none;
}

input[type="range"]::-webkit-slider-thumb {
  -webkit-appearance: none;
  appearance: none;
  width: 18px;
  height: 18px;
  border-radius: 50%;
  background: #06B6D4;
  border: 2px solid #0A1120;
  box-shadow: 0 0 0 1px rgba(6, 182, 212, 0.3);
  cursor: pointer;
  transition: box-shadow 150ms;
}

input[type="range"]::-webkit-slider-thumb:hover {
  box-shadow: 0 0 0 1px rgba(6, 182, 212, 0.5),
              0 0 12px rgba(6, 182, 212, 0.25);
}

input[type="range"]:focus-visible::-webkit-slider-thumb {
  box-shadow: 0 0 0 2px var(--surface-default),
              0 0 0 4px rgba(6, 182, 212, 0.6);
}
```

---

## 17. Table & Data Grid

### 17.1 Table Styling

```tsx
<div className="rounded-xl border border-white/[0.06] bg-[--surface-default] overflow-hidden">
  <table className="w-full text-body">
    <thead>
      <tr className="border-b border-white/[0.06] bg-white/[0.02]">
        <th className="px-4 py-3 text-left text-caption font-medium text-[--text-tertiary] uppercase tracking-wider">
          Column
          {sorted && <ChevronDown className="inline h-3 w-3 ml-1" />}
        </th>
      </tr>
    </thead>
    <tbody>
      <tr className="border-b border-white/[0.04] transition-colors hover:bg-white/[0.03] cursor-pointer">
        <td className="px-4 py-3 text-[--text-primary]">Value</td>
      </tr>
      {/* Striped alternate */}
      <tr className="border-b border-white/[0.04] bg-white/[0.015] transition-colors hover:bg-white/[0.03]">
        <td className="px-4 py-3 text-[--text-primary]">Value</td>
      </tr>
    </tbody>
  </table>
</div>
```

### 17.2 Sort Indicators

- Unsorted: No indicator
- Ascending: `ChevronUp` icon, `text-[--text-tertiary]` color
- Descending: `ChevronDown` icon, `text-[--text-tertiary]` color
- Sorted column header text becomes `text-[--text-primary]`

### 17.3 Sticky Headers

```css
thead th {
  position: sticky;
  top: 0;
  z-index: 10;
  background: var(--surface-default);
  /* Fade edge so content scrolls under cleanly */
  box-shadow: 0 1px 0 0 rgba(255, 255, 255, 0.06);
}
```

### 17.4 Row Selection

```tsx
<tr className={cn(
  "border-b border-white/[0.04] transition-colors cursor-pointer",
  selected
    ? "bg-cyan-500/8 border-l-2 border-l-cyan-500"
    : "hover:bg-white/[0.03]"
)}>
```

### 17.5 Cell Alignment

- Text: left-aligned
- Numbers: right-aligned, `font-mono`
- Status/badge: center-aligned
- Actions: right-aligned

---

## 18. Icon System

### 18.1 Icon Library

Lucide React is the canonical icon library (configured in `components.json`).

### 18.2 Size Scale

| Token | Size | Stroke Width | Use |
|-------|------|-------------|-----|
| `icon-xs` | 12px (h-3 w-3) | 2.5 | Badge inline, micro |
| `icon-sm` | 14px (h-3.5 w-3.5) | 2.25 | Compact buttons, pills |
| `icon-md` | 16px (h-4 w-4) | 2 | Default inline, nav items, button icons |
| `icon-lg` | 20px (h-5 w-5) | 1.75 | Stat cards, section headers |
| `icon-xl` | 24px (h-6 w-6) | 1.75 | Hex node interior, feature icons |
| `icon-2xl` | 32px (h-8 w-8) | 1.5 | Empty state decorative |
| `icon-3xl` | 40px (h-10 w-10) | 1.5 | Large empty state, onboarding |

### 18.3 Icon + Text Pairing

- Icon and text share the same color
- Gap between icon and text: `gap-1.5` (6px) for compact, `gap-2` (8px) for default
- Icon is vertically centered with text baseline using `items-center`
- Icon-only buttons must have `aria-label`

### 18.4 Icon Buttons

```tsx
// Default icon button
<button className="flex h-8 w-8 items-center justify-center rounded-md text-[--text-tertiary]
  transition-colors hover:bg-white/[0.05] hover:text-[--text-primary]
  focus-visible:ring-2 focus-visible:ring-cyan-500/60"
  aria-label="Description">
  <Icon className="h-4 w-4" />
</button>

// Compact icon button (nav)
<button className="flex h-7 w-7 items-center justify-center rounded-md ..." aria-label="...">
  <Icon className="h-4 w-4" />
</button>
```

---

## 19. Scrollbar Styling

Custom scrollbars that match the dark theme. Applied globally.

```css
/* Webkit (Chrome, Safari, Edge) */
::-webkit-scrollbar {
  width: 8px;
  height: 8px;
}

::-webkit-scrollbar-track {
  background: transparent;
}

::-webkit-scrollbar-thumb {
  background: rgba(255, 255, 255, 0.10);
  border-radius: 9999px;
  border: 2px solid transparent;
  background-clip: padding-box;
}

::-webkit-scrollbar-thumb:hover {
  background: rgba(255, 255, 255, 0.18);
  border: 2px solid transparent;
  background-clip: padding-box;
}

::-webkit-scrollbar-corner {
  background: transparent;
}

/* Firefox */
* {
  scrollbar-width: thin;
  scrollbar-color: rgba(255, 255, 255, 0.10) transparent;
}

/* Thin variant for compact panels */
.scrollbar-thin::-webkit-scrollbar {
  width: 4px;
}
```

---

## 20. Selection & Drag States

### 20.1 Text Selection

```css
::selection {
  background: rgba(6, 182, 212, 0.30);
  color: inherit;
}

::-moz-selection {
  background: rgba(6, 182, 212, 0.30);
  color: inherit;
}
```

### 20.2 Drag and Drop (if applicable)

```css
/* Dragging element */
.dragging {
  opacity: 0.7;
  transform: scale(1.02) rotate(1deg);
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
  cursor: grabbing;
}

/* Drop target */
.drop-target {
  border: 2px dashed rgba(6, 182, 212, 0.40);
  background: rgba(6, 182, 212, 0.05);
  border-radius: var(--radius-lg);
}

.drop-target-active {
  border-color: rgba(6, 182, 212, 0.60);
  background: rgba(6, 182, 212, 0.10);
}
```

---

## 21. Z-Index System

Organized in bands of 10 to leave room for intermediate layers.

| Token | Value | Use |
|-------|-------|-----|
| `--z-base` | 0 | Default content |
| `--z-sticky` | 10 | Sticky headers, table headers |
| `--z-explorer-overlay` | 20 | Explorer legend, status strip |
| `--z-explorer-controls` | 30 | LensBar, InfoCard |
| `--z-drawer` | 40 | Node detail drawer, inspector sidebar |
| `--z-dropdown` | 50 | Dropdowns, selects, popovers |
| `--z-modal-backdrop` | 60 | Modal overlay/backdrop |
| `--z-modal` | 70 | Modal content |
| `--z-tooltip` | 80 | Tooltips |
| `--z-toast` | 90 | Toast notifications |
| `--z-skip` | 100 | Skip link (above everything) |

**Rule:** Never use arbitrary z-index values. Always reference a named layer. If a new layer is needed, add it to this table and define the CSS custom property.

```css
:root {
  --z-base: 0;
  --z-sticky: 10;
  --z-explorer-overlay: 20;
  --z-explorer-controls: 30;
  --z-drawer: 40;
  --z-dropdown: 50;
  --z-modal-backdrop: 60;
  --z-modal: 70;
  --z-tooltip: 80;
  --z-toast: 90;
  --z-skip: 100;
}
```

---

## 22. Opacity Scale

Systematic opacity values for consistent transparency across the theme.

| Token | Value | Use |
|-------|-------|-----|
| `--opacity-transparent` | 0 | Fully hidden |
| `--opacity-faint` | 0.03 | Subtle bg (table hover, grid lines) |
| `--opacity-muted` | 0.06 | Subtle borders |
| `--opacity-soft` | 0.10 | Default borders, scrollbar thumb |
| `--opacity-medium` | 0.16 | Emphasis borders |
| `--opacity-semi` | 0.24 | Strong borders |
| `--opacity-accent-bg` | 0.12 | Severity/accent badge backgrounds |
| `--opacity-accent-border` | 0.30 | Severity/accent badge borders |
| `--opacity-disabled` | 0.40 | Disabled elements |
| `--opacity-overlay` | 0.75 | Modal backdrop |
| `--opacity-glass` | 0.90 | Glass surfaces |
| `--opacity-full` | 1 | Full visibility |

All opacity values are applied via `rgba()` on white or the accent color. This keeps the underlying hue consistent while controlling visibility.

---

## 23. Content Density

### 23.1 Density Modes

Two density modes available, toggled via a user preference stored in localStorage.

| Aspect | Comfortable (default) | Compact |
|--------|----------------------|---------|
| Card padding | 24px | 16px |
| Table row height | 48px | 36px |
| Table cell padding | `px-4 py-3` | `px-3 py-1.5` |
| Button height | 40px | 32px |
| Input height | 40px | 32px |
| Section gaps | 24px | 16px |
| Page padding | 24px | 16px |
| Font sizes | As defined | -1px step (body 13px, caption 11px) |

### 23.2 Implementation

```css
/* Comfortable (default) */
:root {
  --density-page-pad: 24px;
  --density-card-pad: 24px;
  --density-gap: 24px;
  --density-row-h: 48px;
  --density-input-h: 40px;
}

/* Compact */
:root[data-density="compact"] {
  --density-page-pad: 16px;
  --density-card-pad: 16px;
  --density-gap: 16px;
  --density-row-h: 36px;
  --density-input-h: 32px;
}
```

Usage in components: `p-[var(--density-card-pad)]` or Tailwind arbitrary value syntax.

---

## 24. Print Styles

When the user prints (e.g., a finding detail for a report):

```css
@media print {
  /* Invert to light for readability and ink saving */
  body {
    background: white !important;
    color: #1a1a1a !important;
    font-size: 12pt;
  }

  /* Hide navigation, sidebar, interactive elements */
  header,
  nav,
  aside,
  .no-print,
  button:not(.print-visible),
  .toast-container,
  [data-radix-popper-content-wrapper] {
    display: none !important;
  }

  /* Cards become bordered boxes */
  .ah-card,
  [class*="rounded-xl"][class*="border"] {
    border: 1px solid #ddd !important;
    background: white !important;
    box-shadow: none !important;
    break-inside: avoid;
  }

  /* Severity badges: text only with border */
  .severity-badge {
    background: transparent !important;
    color: #1a1a1a !important;
    border: 1px solid currentColor !important;
  }

  /* Data values stay monospace */
  .font-mono {
    font-family: 'Courier New', monospace;
  }

  /* Links show URL */
  a[href]::after {
    content: " (" attr(href) ")";
    font-size: 0.85em;
    color: #666;
  }

  /* Charts: use print-optimized static images if available */
  .recharts-wrapper {
    break-inside: avoid;
  }

  /* Page margins */
  @page {
    margin: 1.5cm;
    size: A4;
  }
}
```

---

## 25. CSS Architecture

### 25.1 File Organization

```
ui/src/
  styles/
    globals.css          # Tailwind directives, base layer, CSS custom properties
    scrollbar.css        # Scrollbar overrides
    print.css            # Print media query styles
  theme/
    THEME.md             # This document
    tokens.ts            # Exported JS constants for tokens used in JS (chart colors, etc.)
```

### 25.2 Integration with shadcn/ui

shadcn/ui components use HSL-based CSS custom properties. The theme bridges to this by defining the required `--background`, `--foreground`, etc. variables in the `.dark` class scope.

**Updated `.dark` class variables (replaces current globals.css `.dark` block):**

```css
.dark {
  /* shadcn/ui required variables -- mapped to our semantic tokens */
  --background: 218 53% 3%;              /* surface-base: #050910 */
  --foreground: 210 15% 93%;             /* text-primary: #EDF0F3 */

  --card: 218 50% 10%;                   /* surface-default: #0D1526 */
  --card-foreground: 210 15% 93%;        /* text-primary */

  --popover: 218 47% 12%;               /* surface-raised: #111B2E */
  --popover-foreground: 210 15% 93%;     /* text-primary */

  --primary: 187 72% 42%;               /* accent-primary: #06B6D4 (cyan-500) */
  --primary-foreground: 218 53% 8%;      /* accent-primary-fg: #0A1120 */

  --secondary: 218 42% 15%;             /* surface-raised-2: #151F35 */
  --secondary-foreground: 210 15% 93%;   /* text-primary */

  --muted: 218 42% 15%;                 /* surface-raised-2 */
  --muted-foreground: 213 14% 48%;       /* text-tertiary: #64788F */

  --accent: 218 42% 15%;                /* surface-raised-2 */
  --accent-foreground: 210 15% 93%;      /* text-primary */

  --destructive: 0 84% 60%;             /* severity-critical: #EF4444 */
  --destructive-foreground: 210 15% 93%;

  --border: 218 42% 15%;                /* border-default (~0.10 white equiv) */
  --input: 218 50% 10%;                 /* surface-default */
  --ring: 187 72% 42%;                  /* accent-primary: cyan-500 */

  --radius: 0.75rem;                     /* 12px -- used by shadcn as base radius */
}
```

### 25.3 Tailwind Config Extensions

The following extends are added to `tailwind.config.ts`:

```typescript
// Full Tailwind theme.extend additions
{
  colors: {
    // Keep existing shadcn hsl() references unchanged
    // Add node-kind colors (already present)
    // Add semantic surface colors
    surface: {
      base: '#050910',
      sunken: '#0A1120',
      DEFAULT: '#0D1526',
      raised: '#111B2E',
      'raised-2': '#151F35',
    },
    // Severity (already present, kept for Tailwind class usage)
  },
  borderRadius: {
    lg: 'var(--radius)',
    md: 'calc(var(--radius) - 2px)',
    sm: 'calc(var(--radius) - 4px)',
    xl: '16px',
    '2xl': '20px',
  },
  boxShadow: {
    'glow-cyan': '0 0 20px -4px rgba(6, 182, 212, 0.25)',
    'glow-orange': '0 0 24px -4px rgba(249, 115, 22, 0.25)',
    'glow-red': '0 0 20px -4px rgba(239, 68, 68, 0.30)',
    'glow-green': '0 0 16px -4px rgba(34, 197, 94, 0.25)',
    'glass': '0 8px 32px rgba(0, 0, 0, 0.5)',
  },
  backdropBlur: {
    xs: '4px',
  },
  keyframes: {
    shimmer: {
      '0%': { backgroundPosition: '-200% 0' },
      '100%': { backgroundPosition: '200% 0' },
    },
    'slide-in-right': {
      '0%': { transform: 'translateX(100%)', opacity: '0' },
      '100%': { transform: 'translateX(0)', opacity: '1' },
    },
    'slide-out-right': {
      '0%': { transform: 'translateX(0)', opacity: '1' },
      '100%': { transform: 'translateX(100%)', opacity: '0' },
    },
    'slide-up': {
      '0%': { transform: 'translateY(100%)', opacity: '0' },
      '100%': { transform: 'translateY(0)', opacity: '1' },
    },
    'fade-in': {
      '0%': { opacity: '0' },
      '100%': { opacity: '1' },
    },
    'scale-in': {
      '0%': { transform: 'scale(0.95)', opacity: '0' },
      '100%': { transform: 'scale(1)', opacity: '1' },
    },
  },
  animation: {
    shimmer: 'shimmer 1.5s ease-in-out infinite',
    'slide-in-right': 'slide-in-right 300ms cubic-bezier(0.16, 1, 0.3, 1)',
    'slide-out-right': 'slide-out-right 200ms cubic-bezier(0.7, 0, 0.84, 0)',
    'slide-up': 'slide-up 300ms cubic-bezier(0.16, 1, 0.3, 1)',
    'fade-in': 'fade-in 150ms ease-out',
    'scale-in': 'scale-in 150ms cubic-bezier(0.16, 1, 0.3, 1)',
  },
  zIndex: {
    sticky: '10',
    'explorer-overlay': '20',
    'explorer-controls': '30',
    drawer: '40',
    dropdown: '50',
    'modal-backdrop': '60',
    modal: '70',
    tooltip: '80',
    toast: '90',
    skip: '100',
  },
}
```

### 25.4 CSS Custom Property Naming Convention

```
--{category}-{name}[-{modifier}]

Category:   surface, border, text, accent, severity, feedback, z, density
Name:       descriptive identifier
Modifier:   bg, text, border, fg (foreground), glow (optional)

Examples:
  --surface-default
  --border-subtle
  --text-primary
  --accent-primary-glow
  --severity-critical-bg
  --feedback-error-border
  --z-modal
  --density-card-pad
```

---

## 26. Extensibility Guide

### 26.1 Adding a New Component

When building a new component, follow this checklist:

1. **Pick the surface level.** Is this a page-level container (surface-base), a card (surface-default), a popover (surface-raised), or an overlay (surface-raised-2)?

2. **Pick the border level.** Subtle for static containers, default for interactive containers, emphasis for hover states.

3. **Pick the corner radius.** `radius-xl` (16px) for cards and panels. `radius-lg` (12px) for inner containers. `radius-md` (8px) for inputs and small elements. `radius-full` for pills and toggles.

4. **Define all states** using the state table in section 8. At minimum: default, hover (if interactive), focus-visible (if focusable), disabled (if can be disabled).

5. **Check contrast.** Any text on this component's background must meet the ratios in section 10.1.

6. **Check motion.** If the component appears/disappears, use the enter/exit patterns in section 9.4. If it transitions state, use section 9.3.

7. **Check responsiveness.** How does this component behave at `< md`? Does it need to stack, collapse, or adapt?

### 26.2 Design Decision Principles (when the theme doc does not cover your case)

1. **When in doubt, use the duller option.** A dark dashboard succeeds by making important things pop. Everything else should recede. If you are unsure whether an element should have a glow or a subtle border, use the subtle border.

2. **Glow is earned.** Only elements that respond to user interaction or communicate urgency should glow. Static decorative glow is visual noise.

3. **Match the closest existing pattern.** Before inventing a new visual treatment, find the most similar existing component and adapt it.

4. **Test on both a high-end display and a standard laptop screen.** Subtle background differences that look beautiful on a 4K display may be invisible on a standard 1080p panel.

### 26.3 Token Extension

To add a new semantic token:

1. Define the CSS custom property in the `:root` block of `globals.css`
2. Document it in this theme doc with its hex value, use case, and any contrast requirements
3. If it needs to be used in JavaScript (e.g., chart colors), add it to `theme/tokens.ts`
4. If it maps to a Tailwind color, add it to `tailwind.config.ts` `theme.extend.colors`

---

## 27. Migration from Current Theme

The current codebase uses shadcn/ui's default slate dark theme. Here is the gap analysis and migration plan.

### 27.1 What Changes

| Current | New | Impact |
|---------|-----|--------|
| `--background: 222.2 84% 4.9%` (#020817) | `--background: 218 53% 3%` (#050910) | Slightly lighter, warmer blue undertone |
| `--card: 222.2 84% 4.9%` (same as bg) | `--card: 218 50% 10%` (#0D1526) | Cards now visually distinct from page bg |
| `--border: 217.2 32.6% 17.5%` | `--border: 218 42% 15%` | Slightly subtler borders |
| `--primary: 217.2 91.2% 59.8%` (blue) | `--primary: 187 72% 42%` (cyan) | Accent shifts from blue to cyan |
| `--radius: 0.5rem` | `--radius: 0.75rem` | Larger corner radii |
| No glow effects | Glow-based hover/focus system | New CSS needed |
| No glass surfaces | Glass/backdrop-blur for overlays | New CSS needed |
| Default scrollbars | Custom dark scrollbars | New CSS needed |

### 27.2 What Does NOT Change

- shadcn/ui component structure and class composition
- Tailwind utility class usage patterns
- Node kind color mappings (already correct)
- Severity color values (minor adjustments to badge styling)
- Graph explorer canvas color (#050B18) and hex node fill (#0B1220)
- Edge category colors and styles

### 27.3 Migration Steps

**Phase 1: Foundation (non-breaking)**
1. Update `globals.css` `:root` and `.dark` CSS custom properties to new values
2. Add scrollbar CSS
3. Add selection color CSS
4. Add print CSS
5. Update `--radius` from `0.5rem` to `0.75rem`

**Phase 2: Tailwind Config**
1. Add new `surface` color scale to `tailwind.config.ts`
2. Add `boxShadow` glow utilities
3. Add new keyframes and animations
4. Add z-index scale

**Phase 3: Component Polish (file-by-file)**
1. Update `Card` component to use new radius and border styles
2. Add hover glow to interactive cards
3. Update `NavBar` to use new accent colors
4. Update `Skeleton` to use shimmer animation
5. Update severity badges to use icon + label + color pattern
6. Update table styling for new row hover and border treatment
7. Add glass surface classes to explorer overlay panels

**Phase 4: New Systems**
1. Implement toast notification system
2. Add content density toggle
3. Implement first-run welcome banner
4. Add skip link

Each phase can be merged independently. Phase 1 is purely CSS variable changes and will update the entire app's appearance in one commit. Phases 2-4 are incremental improvements.

---

## Appendix A: Color Contrast Verification Table

Every text/background combination used in the theme, with measured contrast ratios.

| Text Color | Background | Ratio | WCAG Grade | Used For |
|------------|------------|-------|------------|----------|
| #EDF0F3 | #050910 | 17.4:1 | AAA | Primary text on page bg |
| #EDF0F3 | #0D1526 | 15.9:1 | AAA | Primary text on cards |
| #EDF0F3 | #111B2E | 15.0:1 | AAA | Primary text on popovers |
| #B0BEC5 | #050910 | 10.5:1 | AAA | Secondary text on page bg |
| #B0BEC5 | #0D1526 | 9.6:1 | AAA | Secondary text on cards |
| #64788F | #0D1526 | 4.0:1 | AA-Large | Tertiary text (supplementary only) |
| #22D3EE | #0D1526 | 10.1:1 | AAA | Links on cards |
| #06B6D4 | #0D1526 | 7.5:1 | AAA | Accent text/icons on cards |
| #F87171 | #0D1526 | 6.6:1 | AA | Critical severity text on cards |
| #FB923C | #0D1526 | 8.1:1 | AAA | High severity text on cards |
| #FACC15 | #0D1526 | 11.9:1 | AAA | Medium severity text on cards |
| #FFFFFF | #06B6D4 | 2.4:1 | FAIL | White on cyan -- DO NOT USE |
| #0A1120 | #06B6D4 | 7.8:1 | AAA | Dark text on cyan button (preferred) |
| #FFFFFF | #050B18 | 19.7:1 | AAA | Hex node label on canvas |

## Appendix B: Token Quick Reference Card

For quick lookups during development.

```
SURFACES:  base=#050910  sunken=#0A1120  default=#0D1526  raised=#111B2E  raised2=#151F35
BORDERS:   subtle=white/6%  default=white/10%  emphasis=white/16%  strong=white/24%
TEXT:      primary=#EDF0F3  secondary=#B0BEC5  tertiary=#64788F  disabled=#475B7A
ACCENT:    cyan=#06B6D4  orange=#F97316
SEVERITY:  critical=#EF4444  high=#F97316  medium=#EAB308  low=#64788F  info=#3B82F6
RADIUS:    xs=4  sm=6  md=8  lg=12  xl=16  2xl=20  full=9999
DURATION:  instant=50  fast=100  normal=150  moderate=200  slow=300
Z-INDEX:   sticky=10  explorer=20-30  drawer=40  dropdown=50  modal=60-70  tooltip=80  toast=90
```

## Appendix C: Severity Icon Mapping

| Level | Lucide Icon | Shape | Rationale |
|-------|-------------|-------|-----------|
| Critical | `AlertOctagon` | Octagon (stop sign) | Universal "stop/danger" shape |
| High | `AlertTriangle` | Triangle | Universal "warning" shape |
| Medium | `AlertCircle` | Circle | "Attention" shape, lower urgency |
| Low | `Info` | Circle with "i" | Informational |
| Info | `Info` | Circle with "i" | Informational |

This mapping provides shape-based severity recognition independent of color, supporting users with any form of color vision deficiency.
