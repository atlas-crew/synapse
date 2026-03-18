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
        // Signal Horizon Design System — Vivid + Slate + Arc Violet
        ac: {
          // Primary — Vivid Blue
          blue: '#1E90FF',
          navy: '#0B4F8A',
          // Accent — Arc Violet (replaces magenta)
          magenta: '#8B5CF6',
          white: '#FFFFFF',
          black: '#000000',
          // Semantic colors (6-role system)
          orange: '#F59E0B',         // Warning
          green: '#10B981',          // Success
          red: '#EF4444',            // Danger
          purple: '#8B5CF6',         // Accent (anomaly folded in)
          sky: '#06B6D4',            // Info (cyan)
          'sky-blue': '#06B6D4',
          // Tints
          'blue-tint': '#7EC8FF',
          'magenta-tint': '#C4B5FD',
          // Shades
          'blue-shade': '#0A6ED8',
          'navy-shade': '#083D6C',
          'magenta-shade': '#6D28D9',
          'magenta-darker': '#4C1D95',
          // Extended shades
          'blue-dark': '#0A6ED8',
          'blue-darker': '#0B4F8A',
          'gray-mid': '#6B7D96',
          'sky-light': '#67E8F9',
          'card-dark': '#101828',
          // Legacy - keep for transition
          cloud: '#06B6D4',
        },
        // Mappings for Hub UI
        accent: {
          primary: '#1E90FF',
          secondary: '#0B4F8A',
          magenta: '#8B5CF6',
        },
        // Slate scale (replaces navy scale)
        navy: {
          50: '#EEF2F7',
          100: '#D4DCE8',
          200: '#B0BDD0',
          300: '#8899b0',
          400: '#6B7D96',
          500: '#475A72',
          600: '#2a3f5c',
          700: '#1e2d44',
          800: '#131c2e',
          900: '#0c1220',
          950: '#080e1a',
        },
        ctrlx: {
          primary: '#0B4F8A',
          success: '#10B981',
          warning: '#F59E0B',
          danger: '#EF4444',
          info: '#06B6D4',
        },
        risk: {
          low: '#10B981',
          medium: '#F59E0B',
          high: '#F59E0B',
          critical: '#EF4444',       // Red for critical (not accent)
        },
        method: {
          get: '#10B981',
          post: '#1E90FF',
          put: '#F59E0B',
          patch: '#06B6D4',
          delete: '#EF4444',
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
        sans: ['Recursive', 'ui-monospace', 'system-ui', 'sans-serif'],
        mono: ['Recursive', 'ui-monospace', 'monospace'],
      },
      boxShadow: {
        card: '0 2px 8px var(--shadow-color)',
        'card-strong': '0 6px 16px var(--shadow-color-strong)',
      },
    },
  },
  plugins: [require('@tailwindcss/typography')],
};
