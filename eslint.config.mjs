import js from "@eslint/js";
import globals from "globals";

export default [
  {
    ignores: ["frontend/static/vendor/**"],
  },
  js.configs.recommended,
  {
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.jquery,
        ...globals.node,
        L: "readonly",
        bootstrap: "readonly",
      },
    },
    rules: {
      "no-unused-vars": "warn",
    },
  },
];
