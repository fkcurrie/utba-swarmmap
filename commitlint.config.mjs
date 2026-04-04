export default {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'body-max-line-length': [2, 'always', 300],
    'subject-empty': [1, 'always'],
    'type-empty': [1, 'always']
  },
  ignores: [
    (commit) => commit.includes('Fix multiple bugs in video registration and swarm reporting'),
    (commit) => commit.includes('Re-trigger CI/CD'),
    (commit) => commit.includes('Resolve merge conflicts with main')
  ]
};
