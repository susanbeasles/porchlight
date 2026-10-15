# npm trusted publish

Composite action that builds a tree-shaken, minified bundle, checks that the package holds
only that bundle, picks the next version from commits, and publishes to npmjs.org through
OIDC trusted publishing with provenance. It then cuts a GitHub release at the built commit.
It accepts no npm token. Design notes: [ADR-0008](../../docs/adr/0008-supply-chain-actions.md).

## Requirements

- Job permissions: `contents: write` and `id-token: write`.
- `actions/checkout` with `fetch-depth: 0` and `persist-credentials: false`.
- A trusted publisher on npmjs.com for this repository and the calling workflow file (and
  environment, if you use one). Set the package to disallow token publishing afterwards.
- A public repository: npm provenance is only generated for public source repositories.
- `esbuild` pinned in the package's `devDependencies` and `package-lock.json`.
- `package.json` `files` covering the bundle directory, and `main`/`exports` pointing at it.

## Usage

```yaml
- id: npm
  uses: ./actions/npm-trusted-publish
  with:
    working-directory: packages/example
    entry: src/index.ts
    max-bundle-bytes: "65536"
```

A complete workflow: [`docs/ci/release.yml`](../../docs/ci/release.yml).

| Input | Default | |
|---|---|---|
| `entry` | required | Bundle entry, relative to `working-directory` |
| `working-directory` | `.` | Package directory |
| `out-file` | `dist/index.js` | Bundle output |
| `format` / `platform` / `target` | `esm` / `node` / `node22` | esbuild settings |
| `max-bundle-bytes` | `0` (off) | Size budget; fails the job when exceeded |
| `node-version` / `npm-version` | `22` / `11.5.1` | npm 11.5.1+ is required for OIDC |
| `release` | `true` | Create the GitHub release |
| `dry-run` | `false` | Build, version and pack only; allowed on any event |

Outputs: `version`, `tag` (both empty when there is nothing to release), `tarball`
(absolute path of the exact tarball published, ready for `cosign-attest`), `bundle-bytes`.

## Versioning

Commits since the last `v*` tag that touch the package directory decide the bump:
`type!:` or `BREAKING CHANGE` means major, `feat` means minor, and anything else means
patch. With no such commits the action does nothing, so re-runs are safe. The base is the
registry's current version, and a manifest version raised by hand wins when it is ahead.
The bump lives only in the runner. Nothing is committed back.

## Verify a published version

```sh
npm audit signatures          # in a project that depends on the package
```

The package page on npmjs.com links to the provenance, which names the workflow run and commit.
