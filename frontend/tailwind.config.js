/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#000000',
        surface: { DEFAULT: '#0a0a0a', raised: '#111113', overlay: '#161618' },
        border: { DEFAULT: '#1e1e22', subtle: '#27272a', muted: '#3f3f46' },
        text: { DEFAULT: '#ededed', secondary: '#a1a1aa', muted: '#71717a', dim: '#52525b' },
        accent: '#0070f3',
        'accent-hover': '#0060df',
        success: '#10b981',
        warning: '#f59e0b',
        error: '#ef4444',
        'error-dim': '#f87171'
      },
      fontFamily: {
        sans: ['Geist', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace']
      }
    },
  },
  plugins: [],
}
