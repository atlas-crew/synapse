# Atlas Crew Brand System

> **Version**: 3.0 | **Updated**: December 2025
> **Font**: Google Font `Rubik` | Office fallback `Calibri`

---

## Table of Contents

1. [Brand Foundation](#brand-foundation)
2. [Color System](#color-system)
3. [Typography](#typography)
4. [Logo](#logo)
5. [Light Theme](#light-theme)
6. [Dark Theme](#dark-theme)
7. [Buttons & Interactive Elements](#buttons--interactive-elements)
8. [Layout & Components](#layout--components)
9. [Imagery & Icons](#imagery--icons)
10. [CSS Reference](#css-reference)
11. [AI Prompt](#ai-prompt)
12. [Quick Reference](#quick-reference)
13. [Quality Checklist](#quality-checklist)

---

## Brand Foundation

### Brand Promise
**Enabling a Secure and Available Digital World**

**Tagline**: "Always Secure. Always Available."
- Capitalize each word, period after each phrase
- Never display without Atlas Crew logo nearby

### Brand Principles

| Principle | Description |
|-----------|-------------|
| Curiosity | Ask questions, learn new things, think outside the box |
| Creativity | Find great images, play with color, keep it simple |
| Consistency | Build credibility, reputation, and trust |
| Innovation | Find better ways; drive new opportunities |

### Brand Personality
Innovators. Problem solvers. Trusted partners. Solution architects. Engineers.
Confident. Smart. Curious. Bold. Always learning. Customer-centric.

---

## Color System

### Primary Colors

| Name | HEX | RGB | Pantone | Usage |
|------|-----|-----|---------|-------|
| **Atlas Crew Blue** | `#0057B7` | 0, 87, 183 | 2935 C | Primary brand, CTAs, links |
| **Navy Blue** | `#001E62` | 0, 30, 98 | 2758 C | Dark backgrounds, headers, primary text |
| **White** | `#FFFFFF` | 255, 255, 255 | — | Light backgrounds, text on dark |

### Secondary Colors

| Name | HEX | RGB | Pantone | Usage |
|------|-----|-----|---------|-------|
| **Sky Blue** | `#529EEC` | 82, 158, 236 | 292 C | Dark theme links, accents |
| **Magenta** | `#D62598` | 214, 37, 152 | Pink C | **Accent only** — badges, highlights, buttons |
| **Black** | `#000000` | 0, 0, 0 | Black | Dark backgrounds, body text |

### Accent Colors

| Name | HEX | RGB | Usage |
|------|-----|-----|-------|
| **Purple** | `#440099` | 68, 0, 153 | Charts, illustrations |
| **Orange** | `#E35205` | 227, 82, 5 | Warnings, emphasis |
| **Cloud Blue** | `#5E8AB4` | 94, 138, 180 | Charts, alternative to gray |
| **Green** | `#00B140` | 0, 177, 64 | Success states |
| **Red** | `#EF3340` | 239, 51, 64 | Error states |

### Tints & Shades

| Base | Light Tint | Medium | Dark Shade | Darker |
|------|------------|--------|------------|--------|
| Atlas Crew Blue `#0057B7` | `#F0F4F8` | `#7CBAFF` | `#004189` | `#00174A` |
| Navy `#001E62` | `#DFE8F0` | `#003EC8` | `#00174A` | — |
| Sky Blue `#529EEC` | `#BEDDFF` | — | `#3D77B1` | — |
| Magenta `#D62598` | `#E979C2` | — | `#A01B72` | — |

### UI Neutrals

| Name | HEX | Usage |
|------|-----|-------|
| Light Gray | `#F0F4F8` | Section backgrounds (light theme) |
| Medium Gray | `#DFE8F0` | Cards, subtle backgrounds, gridlines |
| Dark Gray | `#404040` | Secondary text (light theme) |
| Mid Gray | `#7F7F7F` | Muted text, disabled states |
| Card Dark | `#0A1A3A` | Dark theme cards |

### Contrast Rules

- **Light text**: Use on `#001E62`, `#000000`, `#00174A`, `#0A1A3A`
- **Dark text**: Use on `#FFFFFF`, `#F0F4F8`, `#DFE8F0`
- **Magenta**: Accent only — never dominant, never behind body text
- **Logo**: Never on accent color backgrounds
- **Accessibility**: WCAG 2.1 AA minimum (4.5:1 for text)

---

## Typography

### Font Family

**Primary**: Rubik (Google Font)
```html
<link href="https://fonts.googleapis.com/css2?family=Rubik:wght@300;400;500;600;700&display=swap" rel="stylesheet">
```

**Fallback**: Calibri (MS Office)

### Font Weights

| Weight | Value | Usage |
|--------|-------|-------|
| Rubik Light | 300 | H1, H2, H3, H4, large headlines |
| Rubik Regular | 400 | Body copy, paragraphs, subheads |
| Rubik Medium | 500 | H5, H6, buttons, navigation, labels |
| Rubik SemiBold | 600 | Links, small buttons |
| Rubik Bold | 700 | Eyebrows, ALL-CAPS labels (sparingly) |

### Type Scale

| Element | Size | Line Height | Weight |
|---------|------|-------------|--------|
| Eyebrow | 16px / 1rem | 1.2 | Bold 700, ALL-CAPS, tracking 0.1em |
| H1 | 48px / 3rem | 56px | Light 300 |
| H2 | 32px / 2rem | 40px | Light 300 |
| H3 | 28px / 1.75rem | 36px | Light 300 |
| H4 | 24px / 1.5rem | 32px | Light 300 |
| H5 | 20px / 1.25rem | 28px | Medium 500 |
| H6 | 16px / 1rem | 24px | Medium 500 |
| Subhead | 20px / 1.25rem | 28px | Regular 400 |
| Body | 16px / 1rem | 24px | Regular 400 |
| Small | 14px | 20px | Regular 400 |

### Typography Rules

- Ragged-right alignment (no justified text)
- Optical kerning enabled
- No hyphenation
- Avoid ALL CAPS except eyebrows/small labels
- Smart quotes (" ") for dialogue; inch marks (") for measurements
- Keep "Atlas Crew" and product names on same line

---

## Logo

### Approved Colors
**Only**: Atlas Crew Blue, Navy Blue, White, Black
**Never**: Magenta, gradients, drop shadows, other colors

### Clear Space
Minimum = height of white triangle inside "A" (referred to as "X")
With tagline: double the "X" space

### Placement Priority
1. **Top-left** (preferred)
2. Top-right (acceptable)
3. Bottom-left (acceptable)
4. ~~Bottom-right~~ (avoid)

### Minimum Size

| Medium | Minimum |
|--------|---------|
| Print | 0.5 inches @ 300 DPI |
| Screen | 50 pixels @ 72 DPI |

### Logo Don'ts
- Never bend, shear, rotate, or distort
- Never add drop shadows or effects
- Never place on busy or low-contrast backgrounds
- Never use unapproved colors
- Never separate "Atlas Crew" from "Networks" in text

---

## Light Theme

### Backgrounds

| Layer | Color |
|-------|-------|
| Base | `#FFFFFF` |
| Sections | `#F0F4F8` |
| Cards | `#DFE8F0` |

### Text

| Type | Color |
|------|-------|
| Primary | `#001E62` (Navy) |
| Secondary | `#404040` |
| Links | `#0057B7` |
| Links (hover) | `#003EC8` |

### Buttons

| Type | Default | Hover | Text |
|------|---------|-------|------|
| Primary (filled) | `#0057B7` | `#004189` | `#FFFFFF` |
| Primary (magenta) | `#D62598` | `#A01B72` | `#FFFFFF` |
| Secondary (outline) | 2px `#001E62` border | Fill `#DFE8F0` | `#001E62` |

---

## Dark Theme

### Backgrounds

| Layer | Color |
|-------|-------|
| Hero/Headers | `#001E62` (Navy) |
| Content blocks | `#000000` or `#00174A` |
| Cards | `#0A1A3A` |

### Text

| Type | Color |
|------|-------|
| Primary | `#F0F4F8` |
| Secondary | `#DFE8F0` |
| Links | `#529EEC` (Sky Blue) |
| Links (hover) | `#7CBAFF` |

### Buttons

| Type | Default | Hover | Text |
|------|---------|-------|------|
| Primary (filled) | `#529EEC` | `#7CBAFF` | `#FFFFFF` |
| Secondary (outline) | 2px `#F0F4F8` border | Fill `#003EC8` | `#FFFFFF` |

---

## Buttons & Interactive Elements

### ⚠️ CRITICAL RULES

1. **Square corners only** — NO rounded corners, NO border-radius
2. **No slanted/angled edges**
3. **Title Case labels** ("Learn More" not "LEARN MORE")

### Button Specifications

| Size | Height | Font | Padding |
|------|--------|------|---------|
| Large (Primary) | 56px | Rubik Medium 16px | 0 32px |
| Medium (Outline) | 48px | Rubik Medium 14px | 0 24px |
| Small (Tertiary) | 40px | Rubik SemiBold 12px | 0 20px |

### Button CSS

```css
/* Primary Button - Atlas Crew Blue */
.btn-primary {
  font-family: 'Rubik', sans-serif;
  font-weight: 500;
  font-size: 16px;
  height: 56px;
  padding: 0 32px;
  background-color: #0057B7;
  color: #FFFFFF;
  border: none;
  border-radius: 0; /* CRITICAL: No rounded corners */
  cursor: pointer;
}
.btn-primary:hover {
  background-color: #004189;
}

/* Primary Button - Magenta variant */
.btn-primary-magenta {
  background-color: #D62598;
}
.btn-primary-magenta:hover {
  background-color: #A01B72;
}

/* Outlined Button */
.btn-outlined {
  font-family: 'Rubik', sans-serif;
  font-weight: 500;
  font-size: 14px;
  height: 48px;
  padding: 0 24px;
  background-color: transparent;
  color: #0057B7;
  border: 2px solid #0057B7;
  border-radius: 0;
  cursor: pointer;
}
.btn-outlined:hover {
  background-color: #D62598;
  border-color: #D62598;
  color: #FFFFFF;
}

/* Secondary Button - Navy */
.btn-secondary {
  font-family: 'Rubik', sans-serif;
  font-weight: 600;
  font-size: 12px;
  height: 40px;
  padding: 0 20px;
  background-color: #001E62;
  color: #FFFFFF;
  border: none;
  border-radius: 0;
  cursor: pointer;
}
.btn-secondary:hover {
  background-color: #00174A;
}
```

### Links

```css
.link {
  font-family: 'Rubik', sans-serif;
  font-weight: 600;
  font-size: 16px;
  color: #0057B7;
  text-decoration: none;
}
.link::after {
  content: ' >';
}
.link:hover {
  color: #003EC8;
}

/* Dark theme */
.dark .link {
  color: #529EEC;
}
.dark .link:hover {
  color: #7CBAFF;
}
```

---

## Layout & Components

### Landing Page Templates

| Size | Structure |
|------|-----------|
| Small | Hero + 1–2 modules (quick conversion) |
| Medium | Hero + 3–4 content blades + CTA |
| Large | Full hero + multiple blades + outcomes + resources + CTA |

### Required Elements

- Navigation/Menu
- Hero with clear headline
- CTA above the fold
- Footer

### Layout Patterns

**Diagonal Split** — Signature Atlas Crew treatment: diagonal line dividing white from Navy areas

```css
.hero-diagonal::after {
  content: '';
  position: absolute;
  top: 0;
  right: 0;
  width: 50%;
  height: 100%;
  background: #FFFFFF;
  clip-path: polygon(20% 0, 100% 0, 100% 100%, 0 100%);
}
```

**Section Alternation** — Cycle through:
1. White `#FFFFFF`
2. Light Gray `#F0F4F8`
3. Navy `#001E62`
4. Atlas Crew Blue `#0057B7`

### Cards

```css
.card {
  background: #FFFFFF;
  border: none;
  border-radius: 0; /* No rounded corners */
  box-shadow: 0 2px 8px rgba(0, 30, 98, 0.1);
}

.dark .card {
  background: #0A1A3A;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
}
```

---

## Imagery & Icons

### Photography Priorities (in order)

1. **Relevant** to message
2. **Authentic** — natural, not staged
3. **Non-cliché** — no handshakes, puzzle pieces, hooded hackers

### Photo Requirements

✅ Do:
- Bold, memorable, uncluttered
- Natural lighting
- Diverse and inclusive
- Brand colors when possible
- Story-driven

❌ Don't:
- Generic stock photos
- Over-saturated or heavily processed
- Dark, gloomy tones
- Cluttered compositions

### Icon Styles

| Style | Usage |
|-------|-------|
| Premium multi-color | White backgrounds only |
| Two-color | General use (blue/magenta) |
| White in colored circle | Feature highlights |
| One-color | Technical diagrams, minimal UI |
| Font Awesome | Navigation and utility icons |

### Icon Rules
- Clean lines, no drop shadows
- Colorize with brand palette only
- No gradients unless from toolkit

---

## CSS Reference

```css
:root {
  /* =========================================
     PRIMARY COLORS
     ========================================= */
  --ac-blue: #0057B7;
  --ac-navy: #001E62;
  --ac-white: #FFFFFF;

  /* =========================================
     SECONDARY COLORS
     ========================================= */
  --ac-sky-blue: #529EEC;
  --ac-magenta: #D62598;
  --ac-black: #000000;

  /* =========================================
     ACCENT COLORS
     ========================================= */
  --ac-purple: #440099;
  --ac-orange: #E35205;
  --ac-cloud-blue: #5E8AB4;
  --ac-green: #00B140;
  --ac-red: #EF3340;

  /* =========================================
     UI NEUTRALS
     ========================================= */
  --ac-gray-light: #F0F4F8;
  --ac-gray-medium: #DFE8F0;
  --ac-gray-dark: #404040;
  --ac-gray-mid: #7F7F7F;
  --ac-card-dark: #0A1A3A;

  /* =========================================
     TINTS & SHADES
     ========================================= */
  --ac-blue-light: #7CBAFF;
  --ac-blue-dark: #004189;
  --ac-blue-darker: #00174A;
  --ac-sky-light: #BEDDFF;
  --ac-sky-dark: #3D77B1;
  --ac-magenta-light: #E979C2;
  --ac-magenta-dark: #A01B72;

  /* =========================================
     HOVER STATES
     ========================================= */
  --ac-hover-light: #003EC8;
  --ac-hover-dark: #7CBAFF;

  /* =========================================
     TYPOGRAPHY
     ========================================= */
  --font-stack: 'Rubik', 'Calibri', -apple-system, BlinkMacSystemFont, sans-serif;
  --font-weight-light: 300;
  --font-weight-regular: 400;
  --font-weight-medium: 500;
  --font-weight-semibold: 600;
  --font-weight-bold: 700;

  /* =========================================
     SPACING
     ========================================= */
  --spacing-xs: 4px;
  --spacing-sm: 8px;
  --spacing-md: 16px;
  --spacing-lg: 24px;
  --spacing-xl: 32px;
  --spacing-2xl: 48px;
  --spacing-3xl: 64px;

  /* =========================================
     BUTTON HEIGHTS
     ========================================= */
  --btn-height-lg: 56px;
  --btn-height-md: 48px;
  --btn-height-sm: 40px;
}

/* =========================================
   GLOBAL RESETS FOR BRAND
   ========================================= */
button, .btn, .card, input, select, textarea {
  border-radius: 0; /* No rounded corners */
}
```

---

## AI Prompt

Use this drop-in prompt when instructing an AI to design for Atlas Crew:

```
You are designing for Atlas Crew. Follow these rules:

PALETTE:
- Primary: #0057B7 (Atlas Crew Blue), #001E62 (Navy), #FFFFFF (White)
- Secondary: #529EEC (Sky Blue), #D62598 (Magenta - sparingly), #000000 (Black)
- Accents: #440099 (Purple), #E35205 (Orange), #5E8AB4 (Cloud Blue), #00B140 (Green), #EF3340 (Red)
- Neutrals: #F0F4F8, #DFE8F0 backgrounds; #404040, #7F7F7F text; #0A1A3A dark cards

TYPOGRAPHY:
- Font: Rubik (Light 300 for headings, Regular 400 for body, Medium 500 for buttons)
- Ragged-right alignment, optical kerning, no hyphenation
- Avoid ALL CAPS except eyebrows/small labels

BUTTONS:
- SQUARE CORNERS ONLY (no rounded, no slanted)
- Primary: filled Blue/Magenta with white text
- Secondary: outline with Navy stroke
- Hover: darken light themes (#004189), lighten dark themes (#7CBAFF)
- Title Case labels

LAYOUT:
- Clean, bold hero with CTA above the fold
- Landing structures: Small (1-2 modules), Medium (3-4), Large (multiple blades)
- Generous white space, section tints instead of heavy borders

THEMES:
- Light: white/tint backgrounds (#FFFFFF, #F0F4F8), navy text (#001E62)
- Dark: navy/black backgrounds (#001E62, #000000), light text (#F0F4F8), sky-blue links (#529EEC)
- Maintain WCAG 2.1 AA contrast (4.5:1 for text)

IMAGERY:
- Authentic, uncluttered, brand-colored
- Avoid stock clichés (handshakes, puzzle pieces, hooded hackers)
- Logo only in approved colors, never on accent backgrounds

Default to primary blues on white with Rubik when unsure.
```

---

## Quick Reference

### HEX Codes at a Glance

```
PRIMARY
  Atlas Crew Blue     #0057B7
  Navy         #001E62
  White        #FFFFFF

SECONDARY
  Sky Blue     #529EEC
  Magenta      #D62598
  Black        #000000

ACCENTS
  Purple       #440099
  Orange       #E35205
  Cloud Blue   #5E8AB4
  Green        #00B140
  Red          #EF3340

NEUTRALS
  Light Gray   #F0F4F8
  Medium Gray  #DFE8F0
  Dark Gray    #404040
  Mid Gray     #7F7F7F
  Card Dark    #0A1A3A

HOVER STATES
  Blue Dark    #004189
  Link Hover   #003EC8
  Sky Light    #7CBAFF
```

### Typography Quick Reference

```
FONT: Rubik (Google Fonts)

WEIGHTS
  Headlines    Light 300
  Body         Regular 400
  Buttons/Nav  Medium 500
  Links        SemiBold 600
  Eyebrows     Bold 700

SIZES
  H1           48px
  H2           32px
  H3           28px
  H4           24px
  H5           20px
  H6           16px
  Body         16px
  Small        14px
```

### Button Quick Reference

```
SHAPE: Rectangular only (border-radius: 0)
TEXT: Title Case

PRIMARY (Large)
  Height: 56px
  Font: Rubik Medium 16px
  Color: #0057B7 → hover #004189
  
OUTLINED (Medium)
  Height: 48px
  Font: Rubik Medium 14px
  Border: 2px solid
  
SECONDARY (Small)
  Height: 40px
  Font: Rubik SemiBold 12px
  Color: #001E62 → hover #00174A
```

---

## Quality Checklist

### Critical (Must Fix)
- [ ] No rounded button corners
- [ ] Rubik font loaded and used
- [ ] Colors match brand palette
- [ ] Logo in approved colors only
- [ ] CTA above the fold

### Major (Should Fix)
- [ ] Correct font weights (Light for headlines, not Bold)
- [ ] Correct button heights and styles
- [ ] Proper hover states
- [ ] Good image selection (relevant, authentic, non-cliché)
- [ ] Sufficient contrast ratios

### Minor (Polish)
- [ ] Consistent spacing
- [ ] Icon sizing uniform
- [ ] Section background alternation

---

## Resources

| Resource | Location |
|----------|----------|
| Logos | `./Logos/Atlas Crew/` |
| Photos | `./Photos/` |
| Color Palette | `./ac-palette-labeled.png` |
| Icons | `./NEW-Atlas Crew-Icons-Toolkit-September-2025.pptx` |
| Fonts | Google Fonts: `Rubik` |
| Contact | marcom-DL@Atlas CrewNetworks.com |
| Trademarks | Atlas CrewNetworks.com/company/legal/trademarks |

---

*Atlas Crew, the Atlas Crew logo, ACOS, Thunder, Harmony, and SSL Insight are trademarks or registered trademarks of AtlasCrew, LLC*
