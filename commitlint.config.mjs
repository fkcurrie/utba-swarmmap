export default {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'body-max-line-length': [2, 'always', 300],
    'subject-empty': [1, 'never'],
    'type-empty': [1, 'never']
  },
  ignores: [
    (commit) => commit.includes('Fix video registration and restore swarm reporting functionality'),
    (commit) => commit.includes('Fix multiple bugs in video registration and swarm reporting'),
    (commit) => commit.includes('Re-trigger CI/CD'),
    (commit) => commit.includes('Resolve merge conflicts with main')
  ]
};
