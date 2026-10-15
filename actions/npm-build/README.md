# npm build

The build half of the release chain. It produces one sealed npm tarball and writes
nothing outside the runner. Release and publish are separate actions. The whole flow is
in [ADR-0008](../../docs/adr/0008-supply-chain-actions.md) and
[`.github/workflows/release.yml`](../../.github/workflows/release.yml).

1. Runs `npm ci --ignore-scripts` from the lockfile.
2. Builds one esbuild bundle: `--bundle --minify --tree-shaking=true --packages=external`,
   with an optional byte budget.
3. Works out the next version from conventional commits and writes it into `package.json`
   in the runner only.
4. Runs `npm pack` once and fails if the tarball holds anything beyond the bundle
   directory, `package.json`, README, LICENSE and CHANGELOG.

## Requirements

- `actions/checkout` with `fetch-depth: 0`.
- `esbuild` pinned in the package's `devDependencies` and lockfile.
- `files` in `package.json` covering the bundle, with `main` or `exports` pointing at it.

| Input | Default | |
|---|---|---|
| `entry` | required | Bundle entry, relative to `working-directory` |
| `working-directory` | `.` | Package directory |
| `out-file` | `dist/index.js` | Bundle output |
| `format` / `platform` / `target` | `esm` / `node` / `node22` | esbuild settings |
| `max-bundle-bytes` | `0` (off) | Size budget |
| `node-version` | `22` | |

Outputs:
- `version` and `tag`: both empty when there is nothing to release.
- `tarball`: absolute path. Its directory holds nothing else, so the checksums and bundles
  can sit beside it.
- `bundle-bytes`.

## Versioning

Commits since the last `v*` tag that touch the package directory decide the bump:
`type!:` or `BREAKING CHANGE` means major, `feat` means minor, and anything else means
patch. With no such commits, nothing is released. The base is the higher of the npm
registry's version and the last tag. A version raised by hand in `package.json` wins when it
is ahead.
