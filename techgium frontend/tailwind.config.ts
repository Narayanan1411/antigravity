import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#0a0a0a",
        foreground: "#ededed",
        card: "#141414",
        border: "#262626",
        primary: "#3b82f6",
        success: "#22c55e",
        warning: "#eab308",
        alert: "#f97316",
        critical: "#ef4444",
      },
    },
  },
  plugins: [],
  darkMode: 'class',
};
export default config;
