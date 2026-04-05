export default {
  extends: ["@commitlint/config-conventional"],
  rules: {
    "body-max-line-length": [0, "always"],
    "subject-empty": [0, "always"],
    "type-empty": [0, "always"],
  },
  ignores: [
    (message) => message.includes("Agent iteration: Apply changes"),
    (message) => message.startsWith("Resolve merge conflicts"),
    (message) => message.startsWith("Merge pull request"),
    (message) => message.startsWith("Merge branch"),
    (commit) => commit.includes('Fix video registration and restore swarm reporting functionality'),
    (commit) => commit.includes('Fix multiple bugs in video registration and swarm reporting'),
    (commit) => commit.includes('Re-trigger CI/CD'),
    (commit) => commit.includes('Resolve merge conflicts with main')
  ],
};
