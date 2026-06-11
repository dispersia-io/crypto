<!--
⚠️ IMPORTANT:

1. Your PR title MUST follow the Conventional Commits standard (e.g., "feat(wasm): implement secure key generation").
2. Your PR MUST be targeted against the 'canary' branch. PRs targeting 'main' will be closed.
-->

📝 **Description**

<!-- Please include a summary of the changes and the related issue. Describe the rationale behind adding, modifying, or removing cryptography logic, Rust core features, or JS/TS translator methods. -->

🔗 **Related Issue**

<!-- If this PR fixes an open issue, please link it here (e.g., "Closes #123"). -->

🔍 **Type of Change**

<!-- Please delete options that are not relevant. -->

- [ ] 🐛 Bug fix (non-breaking change which fixes an issue, e.g., fixing a panic in Rust or a TS type error)
- [ ] ✨ New feature (e.g., new cryptographic algorithm or JS/TS API method)
- [ ] 💥 Breaking change (e.g., modifying the WASM API signature or removing a public method)
- [ ] 📚 Documentation update
- [ ] 🛠️ Refactoring / Chore (e.g., dependency updates, internal scripts, cargo/yarn maintenance)

✅ **Checklist**

<!-- Please review this checklist before submitting your PR. -->

- [ ] I have targeted the `canary` branch.
- [ ] My PR title follows the Conventional Commits standard.
- [ ] I have read the `CONTRIBUTING.md` document.
- [ ] I have run `yarn install` and/or `cargo check` to ensure dependency integrity.
- [ ] I have run `yarn typecheck` and `yarn build` successfully (compiling both Rust WASM and TS).
- [ ] I have run `yarn test` and all tests (Rust & Jest) passed.
- [ ] I have run `yarn lint:strict` (ESLint & Clippy) and my changes generate no warnings.
- [ ] I have run `yarn format:fix` (Prettier & rustfmt) to ensure code style compliance.

🧪 **How Has This Been Tested?**

<!-- Please describe how you verified your changes. -->

- [ ] **Rust Core**: Ran `yarn test:rs` to verify internal logic.
- [ ] **TS Integration**: Ran `yarn test:js` to verify the public API and WASM initialization.
- [ ] **Manual Verification**: (e.g., tested with a local link in a real browser environment)
