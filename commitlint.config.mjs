export default {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'body-max-line-length': [2, 'always', 120]
  },
  ignores: [(message) => message.includes('Agent iteration: Apply changes')]
};
