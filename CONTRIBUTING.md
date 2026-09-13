# Contributing to webhook-hmac-kit

Thanks for helping out. This covers what you need to get going.

## Getting started

### 1. Fork and clone

```bash
# Fork the repo on GitHub, then:
git clone https://github.com/<your-username>/webhook-hmac-kit.git
cd webhook-hmac-kit
npm install
```

You need Node 22 or newer (see `engines` in `package.json`).

### 2. Create a branch

```bash
git checkout -b feat/my-feature
# or: fix/my-bugfix, docs/my-change
```

Branch names use the same prefixes as commits: `feat/`, `fix/`, `docs/`, `chore/`, `test/`, `refactor/`.

### 3. Build, check and test

```bash
npm run build       # bundle with tsup
npm run typecheck   # tsc --noEmit
npm run test        # run the suite once with vitest
npm run test:watch  # watch mode while you work
npm run lint        # biome check
npm run lint:fix    # biome check --write, auto-fixes what it can
npm run format      # biome format --write
```

Lint and format both go through Biome, so there is nothing else to configure. Run `npm run lint:fix` before you push and it sorts most style nits for you.

### 4. Submit a pull request

```bash
git push origin feat/my-feature
```

Open a PR against `main`, fill in the template, and link the issue with `Closes #123`. CI has to be green before it can merge, see below.

## Tests

The suite lives in `test/`. A few things worth knowing:

- **Test vectors.** `test/vectors.ts` and `test/standard-webhooks-vectors.ts` hold known sign/verify pairs. If you touch the wire format or the canonical string, these are what catch you. Do not edit a vector to make a test pass unless the vector itself is wrong, and say so if it is.
- **Property tests.** `test/canonical.property.test.ts` uses fast-check to throw generated input at the canonicalisation. Add property tests for anything with an invariant that should hold for all inputs, not just the cases you thought of.
- **Smoke tests.** `test/smoke/` runs the built package on Node, Deno and Bun in CI. This library exists to behave the same on every Web Crypto runtime, so if your change is runtime-sensitive, check it holds on all three.

New behaviour needs a test. Bug fixes need a test that fails before the fix and passes after.

## Code style

- Biome handles lint and formatting. Match what `npm run lint:fix` and `npm run format` produce.
- Web Crypto only. No Node-only crypto, no `Buffer` in library code, nothing that would break on Deno, Bun or Workers.
- Keep the public API surface small. New exports are a deliberate choice, not a default.

## Commits

Conventional commits: `type: description`.

Types: `feat`, `fix`, `chore`, `docs`, `test`, `refactor`.

Commits and tags must be signed. Set up SSH or GPG signing and turn on `commit.gpgsign` before you start, or your commits will not verify.

## CI

Every PR runs the `CI` workflow: typecheck, lint, test and build across the Node matrix, plus a smoke run on Node, Deno and Bun. The branch ruleset requires one check, `gate`, which only passes when every job above passed. If `gate` is red, the PR cannot merge, so check the failing job in the Actions tab.

## Code of Conduct

This project follows the [Contributor Covenant](./CODE_OF_CONDUCT.md). Please read it before taking part.
