/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        graphite: {
          950: '#070a0e',
          900: '#0b0f15',
          850: '#111722',
          800: '#161f2e',
          700: '#222f44',
          600: '#334155',
        },
        cyber: {
          cyan: '#00f2fe',
          teal: '#06b6d4',
          emerald: '#10b981',
          amber: '#f59e0b',
          rose: '#f43f5e',
          purple: '#a855f7',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Courier New', 'monospace'],
      },
      boxShadow: {
        'cyan-glow': '0 0 20px -3px rgba(6, 182, 212, 0.25)',
        'rose-glow': '0 0 20px -3px rgba(244, 63, 94, 0.25)',
      },
    },
  },
  plugins: [],
}
