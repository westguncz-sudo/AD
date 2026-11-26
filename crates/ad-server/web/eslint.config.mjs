// Kontrola JavaScriptu rozhraní. Spustí se příkazem:
//   npx eslint js/
// Není to podmínka překladu — slouží k tomu, aby se v rozhraní
// nehromadily nepoužité proměnné a překlepy ve jménech.
export default [
  {
    files: ['js/**/*.js'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: {
        document: 'readonly',
        window: 'readonly',
        location: 'readonly',
        fetch: 'readonly',
        setTimeout: 'readonly',
        console: 'readonly',
        URLSearchParams: 'readonly',
        Node: 'readonly',
        MutationObserver: 'readonly',
        Date: 'readonly',
        Promise: 'readonly',
        Math: 'readonly',
        Number: 'readonly',
        String: 'readonly',
        Boolean: 'readonly',
        Object: 'readonly',
        Array: 'readonly',
        JSON: 'readonly',
        Error: 'readonly',
      },
    },
    rules: {
      'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      'no-undef': 'error',
      'no-var': 'error',
      'prefer-const': 'error',
      eqeqeq: ['error', 'always'],
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-eval': 'error',
      // Do stránky se text vkládá jen přes textContent — innerHTML by
      // znamenal, že se cizí text chová jako HTML.
      'no-restricted-properties': ['error',
        { property: 'innerHTML', message: 'Používej textContent nebo el(), ne innerHTML.' },
        { property: 'outerHTML', message: 'Používej textContent nebo el(), ne outerHTML.' },
      ],
      'no-restricted-globals': ['error',
        { name: 'eval', message: 'eval se nepoužívá.' },
      ],
    },
  },
];
