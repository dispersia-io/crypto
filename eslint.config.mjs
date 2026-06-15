import prettier from 'eslint-config-prettier';
import { configs, configure } from 'eslint-config-woofmeow';

const eslintConfig = configure(
  { ignores: ['translator/wasm.js', 'translator/wasm.d.ts'] },
  configs.typescript,
  prettier,
);

// eslint-disable-next-line no-restricted-exports
export default eslintConfig;
