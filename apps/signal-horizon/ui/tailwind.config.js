/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    // Override default border-radius - design system requires 0 everywhere
    borderRadius: {
      none: '0',
      DEFAULT: '0',
    },
    extend: {
      colors: {
        // Atlas Crew brand palette (Signal Horizon Design System)
        ac: {
          // Primary (60/25/10 rule)
          blue: '#0057B7',           // Atlas Crew Blue - 25% interactive elements
          navy: '#001E62',           // Navy Blue - 60% dominant surfaces
          magenta: '#D62598',        // Magenta - 10% alerts, key metrics
          white: '#FFFFFF',
          black: '#000000',
          // Accent colors (data visualization)
          orange: '#C24900',         // Warnings (darkened for WCAG AA contrast)
          green: '#008731',          // Success (darkened for WCAG AA contrast)
          red: '#BF3A30',            // Critical, blocked (design system spec)
          purple: '#A400FF',         // Anomalies (design system spec)
          sky: '#3298BC',            // Informational (design system spec)
          'sky-blue': '#3298BC',
          // Tints
          'blue-tint': '#70BAF7',
          'magenta-tint': '#E97BC1',
          // Shades
          'blue-shade': '#004189',
          'navy-shade': '#001E6A',
          'magenta-shade': '#A60B72',
          'magenta-darker': '#6D0A50',
          // Extended shades for backward compatibility
          'blue-dark': '#004189',
          'blue-darker': '#001E6A',
          'gray-mid': '#7F7F7F',
          'sky-light': '#BEDDFF',
          'card-dark': '#0A1A3A',
          // Legacy - keep for transition
          cloud: '#5EAB44',
        },
        // Mappings for Hub UI
        accent: {
          primary: '#0057B7', // Atlas Crew Blue
          secondary: '#001E62', // Atlas Crew Navy
          magenta: '#D62598',
        },
        // CtrlX design system colors (existing)
        navy: {
          50: '#f0f4f8',
          100: '#d9e2ec',
          200: '#bcccdc',
          300: '#9fb3c8',
          400: '#829ab1',
          500: '#627d98',
          600: '#486581',
          700: '#334e68',
          800: '#243b53',
          900: '#1e3a5f',
          950: '#102a43',
        },
        ctrlx: {
          primary: '#001E62',        // Navy - design system primary
          success: '#008731',        // Atlas Crew Green (contrast-safe)
          warning: '#C24900',        // Atlas Crew Orange (contrast-safe)
          danger: '#BF3A30',         // Atlas Crew Red (design system)
          info: '#3298BC',           // Sky Blue (design system)
        },
        risk: {
          low: '#008731',            // Atlas Crew Green (contrast-safe)
          medium: '#C24900',         // Atlas Crew Orange (contrast-safe)
          high: '#C24900',           // Atlas Crew Orange (contrast-safe)
          critical: '#D62598',       // Magenta for critical (design system)
        },
        method: {
          get: '#008731',            // Atlas Crew Green (contrast-safe)
          post: '#0057B7',           // Atlas Crew Blue
          put: '#C24900',            // Atlas Crew Orange (contrast-safe)
          patch: '#440099',          // Atlas Crew Purple
          delete: '#BF3A30',         // Atlas Crew Red
        },
        surface: {
          base: 'var(--surface-base)',
          subtle: 'var(--surface-subtle)',
          card: 'var(--surface-card)',
          inset: 'var(--surface-inset)',
          overlay: 'var(--surface-overlay)',
          hero: 'var(--surface-hero)',
        },
        ink: {
          primary: 'var(--text-primary)',
          secondary: 'var(--text-secondary)',
          muted: 'var(--text-muted)',
          inverse: 'var(--text-inverse)',
        },
        border: {
          subtle: 'var(--border-subtle)',
          strong: 'var(--border-strong)',
          inset: 'var(--border-inset)',
        },
        link: {
          DEFAULT: 'var(--link)',
          hover: 'var(--link-hover)',
        },
        focus: {
          DEFAULT: 'var(--focus-ring)',
        },
        accent: {
          DEFAULT: 'var(--accent)',
          hover: 'var(--accent-hover)',
        },
        success: 'var(--ac-green)',
        warning: 'var(--ac-orange)',
        danger: 'var(--ac-red)',
        info: 'var(--ac-sky-blue)',
        // Legacy class support mapped to Atlas Crew tokens
        horizon: {
          50: 'var(--ac-gray-light)',
          100: 'var(--ac-sky-light)',
          200: 'var(--ac-blue-light)',
          300: 'var(--ac-sky-blue)',
          400: 'var(--ac-blue)',
          500: 'var(--ac-blue)',
          600: 'var(--ac-blue-dark)',
          700: 'var(--ac-hover-light)',
          800: 'var(--ac-blue-darker)',
          900: 'var(--ac-navy)',
          950: 'var(--ac-black)',
        },
        gray: {
          50: 'var(--surface-base)',
          100: 'var(--surface-subtle)',
          200: 'var(--surface-card)',
          300: 'var(--border-subtle)',
          400: 'var(--text-muted)',
          500: 'var(--text-secondary)',
          600: 'var(--text-primary)',
          700: 'var(--surface-inset)',
          800: 'var(--surface-subtle)',
          900: 'var(--surface-card)',
          950: 'var(--surface-base)',
        },
        blue: {
          50: 'var(--ac-gray-light)',
          100: 'var(--ac-sky-light)',
          200: 'var(--ac-blue-light)',
          300: 'var(--ac-sky-blue)',
          400: 'var(--ac-blue)',
          500: 'var(--ac-blue)',
          600: 'var(--ac-blue-dark)',
          700: 'var(--ac-hover-light)',
          800: 'var(--ac-blue-darker)',
          900: 'var(--ac-navy)',
        },
        green: {
          400: 'var(--ac-green)',
          500: 'var(--ac-green)',
          600: 'var(--ac-green)',
        },
        red: {
          400: 'var(--ac-red)',
          500: 'var(--ac-red)',
          600: 'var(--ac-red)',
        },
        yellow: {
          400: 'var(--ac-orange)',
          500: 'var(--ac-orange)',
          600: 'var(--ac-orange)',
        },
        orange: {
          400: 'var(--ac-orange)',
          500: 'var(--ac-orange)',
          600: 'var(--ac-orange)',
        },
        purple: {
          400: 'var(--ac-purple)',
          500: 'var(--ac-purple)',
          600: 'var(--ac-purple)',
        },
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'ping-slow': 'ping 2s cubic-bezier(0, 0, 0.2, 1) infinite',
      },
      fontFamily: {
        sans: ['Rubik', 'Calibri', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Menlo', 'monospace'],
      },
      boxShadow: {
        card: '0 2px 8px var(--shadow-color)',
        'card-strong': '0 6px 16px var(--shadow-color-strong)',
      },
    },
  },
  plugins: [require('@tailwindcss/typography')],
};
