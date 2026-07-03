# Infinite Gist — Design Tokens & Theme

> Design system for Infinite Gist, a security monitoring platform.
> Brand: sharp, trustworthy, developer-first.

---

## Visual Theme

**Direction:** Clean, precise, low-chrome utility. The interface recedes so the data — findings, severity indicators, correlation links — takes visual priority. Surface colors are cool neutrals with a single accent for interactive elements. No decorative gradients, no glass effects, no ornamental borders.

**Rationale:** Security tools earn trust through clarity, not visual flair. Every pixel either communicates state (severity, status, confidence) or enables action (buttons, links, form controls). Chrome that does neither is noise.

---

## Color Palette

All values in OKLCH for perceptual uniformity. All text/background pairs meet WCAG 2.2 AA (≥4.5:1 contrast).

### Neutral

| Token | Value | Usage |
|-------|-------|-------|
| `--color-bg` | `oklch(99% 0 0)` | Page background |
| `--color-surface` | `oklch(97% 0.005 260)` | Card, sidebar, dropdown backgrounds |
| `--color-border` | `oklch(90% 0.008 260)` | Dividers, table borders, input borders |
| `--color-border-strong` | `oklch(80% 0.01 260)` | Focus rings, active borders |
| `--color-text-secondary` | `oklch(55% 0.015 260)` | Labels, metadata, placeholder text |
| `--color-text` | `oklch(25% 0.02 260)` | Body text |
| `--color-text-strong` | `oklch(12% 0.02 260)` | Headings, primary content |

**Rationale:** Cool-leaning neutrals (260° hue) evoke precision and restraint — a common choice for developer tools. The near-white background (99% lightness) keeps the interface airy without feeling sterile.

### Accent

| Token | Value | Usage |
|-------|-------|-------|
| `--color-accent` | `oklch(55% 0.18 255)` | Primary buttons, links, active states |
| `--color-accent-hover` | `oklch(48% 0.2 255)` | Button hover, link hover |
| `--color-accent-soft` | `oklch(92% 0.04 255)` | Selected rows, active nav background |
| `--color-accent-text` | `oklch(99% 0 0)` | Text on accent backgrounds |

**Rationale:** A medium-saturation blue (255° hue, 0.18 chroma) signals interactivity without the urgency of a brighter blue. It reads as competent, not promotional — right for a security tool.

### Semantic (Severity & Status)

| Token | Value | Usage |
|-------|-------|-------|
| `--color-critical` | `oklch(45% 0.18 30)` | Critical severity badge, text |
| `--color-critical-bg` | `oklch(92% 0.06 30)` | Critical severity badge background |
| `--color-high` | `oklch(50% 0.16 55)` | High severity badge, text |
| `--color-high-bg` | `oklch(93% 0.05 55)` | High severity badge background |
| `--color-medium` | `oklch(60% 0.14 85)` | Medium severity badge, text |
| `--color-medium-bg` | `oklch(95% 0.04 85)` | Medium severity badge background |
| `--color-low` | `oklch(65% 0.08 160)` | Low severity badge, text |
| `--color-low-bg` | `oklch(95% 0.03 160)` | Low severity badge background |
| `--color-success` | `oklch(55% 0.15 150)` | Verified, remediated, healthy |
| `--color-warning` | `oklch(60% 0.15 85)` | Needs attention |
| `--color-error` | `oklch(48% 0.18 30)` | Error states, destructive actions |

**Rationale:** Severity colors follow a warm→cool gradient (critical red → low green), matching the natural perceptual map of "hot" to "cold" risks. Background variants at 92-95% lightness keep badges readable without jarring against the page background.

---

## Typography

### Font Stack

```css
--font-sans: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
--font-mono: "SF Mono", "Cascadia Code", "Fira Code", "JetBrains Mono", Consolas, monospace;
```

**Rationale:** System-ui stack ensures native-feeling text rendering with zero network cost. Monospace is reserved for code snippets, file paths, and evidence references — contexts where character alignment matters.

### Scale

| Token | Size | Line Height | Weight | Usage |
|-------|------|-------------|--------|-------|
| `--fs-xs` | `0.75rem` (12px) | 1.4 | 400 | Metadata, timestamps, table cell secondary |
| `--fs-sm` | `0.875rem` (14px) | 1.5 | 400 | Body, table cells, form labels |
| `--fs-base` | `1rem` (16px) | 1.5 | 400 | Default body text |
| `--fs-lg` | `1.125rem` (18px) | 1.4 | 500 | Section headings, card titles |
| `--fs-xl` | `1.375rem` (22px) | 1.3 | 600 | Page titles, dialog headings |
| `--fs-2xl` | `1.75rem` (28px) | 1.25 | 600 | Dashboard stat values, hero numbers |

**Rationale:** A 1.125 modular scale keeps steps close enough to avoid awkward gaps. Fixed-rem sizing guarantees consistent rendering regardless of user's default font size (respecting the accessibility requirement). 400/500/600 weight gradation provides hierarchy without needing ultra-light or bold faces.

---

## Spacing

```css
--space-1: 0.25rem;   /* 4px  — tight icon/text gaps */
--space-2: 0.5rem;    /* 8px  — inner padding (badges, tags) */
--space-3: 0.75rem;   /* 12px — form element padding */
--space-4: 1rem;      /* 16px — card padding, button padding */
--space-5: 1.5rem;    /* 24px — section gaps, between cards */
--space-6: 2rem;      /* 32px — major section spacing */
--space-8: 3rem;      /* 48px — page margins, dialog padding */
--space-12: 4rem;     /* 64px — layout gutters */
```

**Rationale:** Based on a 4px unit grid. The 1.5× step from 1rem→1.5rem→2rem→3rem provides natural visual rhythm without requiring fractional values.

---

## Component Tokens

### Buttons

| Token | Value |
|-------|-------|
| Primary bg | `--color-accent` |
| Primary text | `--color-accent-text` |
| Primary hover | `--color-accent-hover` |
| Secondary bg | transparent |
| Secondary text | `--color-text` |
| Secondary border | `--color-border` |
| Secondary hover bg | `--color-surface` |
| Danger bg | `--color-error` |
| Danger text | `--color-accent-text` |
| Border radius | `6px` |
| Padding | `0.5rem 1rem` (y x) |
| Font size | `--fs-sm` |
| Font weight | `500` |
| Transition | `background-color 150ms` |

**Rationale:** 6px radius feels intentional without the softness of 8px+. Secondary buttons use an outline style — less visual weight, appropriate for non-primary actions.

### Tables

| Token | Value |
|-------|-------|
| Header bg | `--color-surface` |
| Header text | `--color-text-secondary` |
| Header font | `--fs-sm`, 600 weight |
| Row height | `2.75rem` (44px) |
| Row hover bg | `--color-accent-soft` |
| Cell padding | `0.5rem 0.75rem` |
| Border | `1px solid --color-border` |
| Border radius | `6px` |

**Rationale:** Compact enough to show many findings per page, tall enough to tap on mobile. Header styled as secondary text reduces visual noise — the data rows are the focus.

### Cards

| Token | Value |
|-------|-------|
| Bg | `--color-surface` |
| Border | `1px solid --color-border` |
| Border radius | `8px` |
| Padding | `--space-4` |
| Shadow | `none` |
| Header bottom border | `1px solid --color-border` |

**Rationale:** Flat cards (no shadow) keep the interface grounded. The 8px radius distinguishes cards from inputs (6px) and matches the structural hierarchy.

### Form Controls

| Token | Value |
|-------|-------|
| Input border | `1px solid --color-border` |
| Input focus border | `2px solid --color-accent` |
| Input focus ring | `0 0 0 3px --color-accent-soft` |
| Input border radius | `6px` |
| Input padding | `0.5rem 0.75rem` |
| Input font size | `--fs-sm` |
| Label font size | `--fs-sm` |
| Label font weight | `500` |
| Label gap | `--space-1` |

**Rationale:** Focus ring uses a soft accent halo (3px, low opacity) that doesn't rely solely on color change — shape change (1px → 2px border) provides redundant focus indication.

### Navigation

| Token | Value |
|-------|-------|
| Nav item padding | `0.5rem 0.75rem` |
| Nav item border radius | `6px` |
| Nav item hover bg | `--color-accent-soft` |
| Nav item active bg | `--color-accent-soft` |
| Nav item active text | `--color-accent` |
| Nav item active weight | `600` |
| Nav icon size | `1.25rem` (20px) |
| Nav gap | `--space-1` (icon to label) |

**Rationale:** Navigation uses a soft highlight for active state — signals location without the heaviness of a left-stripe indicator. Consistent 6px radius matches buttons and inputs.

---

## Z-Index Scale

| Token | Value | Usage |
|-------|-------|-------|
| `--z-base` | `0` | Default content |
| `--z-dropdown` | `100` | Dropdown menus, popovers |
| `--z-sticky` | `200` | Sticky headers |
| `--z-modal-backdrop` | `300` | Modal/dialog overlays |
| `--z-modal` | `400` | Modal/dialog content |
| `--z-toast` | `500` | Toast notifications |
| `--z-tooltip` | `600` | Tooltips |

**Rationale:** Gaps of 100 between layers allow inserting new layers (e.g., `--z-sticky + 1` for a sticky sub-header) without reshuffling.

---

## Motion

| Token | Value |
|-------|-------|
| Default duration | `200ms` |
| Fast duration | `150ms` |
| Slow duration | `250ms` |
| Easing (enter) | `ease-out` |
| Easing (exit) | `ease-in` |
| Easing (emphasis) | `cubic-bezier(0.34, 1.56, 0.64, 1)` (spring) |

### Rules

- **No decorative motion.** Every animation communicates a state change (open/close, appear/disappear, loading/done).
- **Respect `prefers-reduced-motion`.** When detected, all transitions and animations reduce to `0ms` or opacity-only cross-fades.
- **Duration correlates with distance.** Small UI changes (button hover, color shift) use 150ms. Panel slides and modal openings use 200-250ms.

**Rationale:** Brief, purposeful motion supports the "developer-tool pacing" principle. Users should never wait for an animation to finish before interacting.

---

## Breakpoints

| Token | Value | Target |
|-------|-------|--------|
| `--bp-sm` | `375px` | Minimum supported width |
| `--bp-md` | `768px` | Tablet / narrow desktop |
| `--bp-lg` | `1024px` | Desktop |
| `--bp-xl` | `1280px` | Wide desktop |

**Rationale:** Mobile-first scale that matches common device widths. The 375px minimum ensures iPhone SE / foldable compatibility per WCAG reflow requirements.

---

*Design tokens defined: 2026-06-29*
