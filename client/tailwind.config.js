const withMT = require("@material-tailwind/react/utils/withMT");
const plugin = require("tailwindcss/plugin");

module.exports = withMT({
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],

  theme: {
    extend: {
      screens: {},

      gridTemplateColumns: {
        16: "repeat(16, minmax(0, 1fr))",
      },

      backgroundImage: {},

      fontFamily: {
        outfit: ["var(--font-outfit)"],
        sans: ["var(--font-outfit)"],
      },

      colors: {},
    },
  },

  plugins: [
    plugin(function ({ addUtilities }) {
      const newUtilities = {};

      addUtilities(newUtilities);
    }),
  ],
});
