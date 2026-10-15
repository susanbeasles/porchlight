# npm release activation

`npm.json` is the single switch for the npm release chain (ADR-0008). While `enabled` is
`false`, `release.yml` stops after its gate job and `deploy.yml` refuses to run, so nothing
is built, signed, released or published.

To activate, open one reviewed change that sets:

| Field | Meaning |
|---|---|
| `enabled` | `true` |
| `directory` | Package directory, relative to the repository root |
| `name` | The exact `name` in that directory's `package.json` |
| `entry` | Bundle entry point, relative to `directory` |
| `out_file` | Bundle output, relative to `directory` (default `dist/index.js`) |
| `max_bundle_bytes` | Size budget for the bundle; `0` disables it |

The gate refuses activation unless:

- the directory holds `package.json` and `package-lock.json`;
- the package name matches `name`;
- the package is not `private`;
- `repository` points at this GitHub repository, which npm provenance requires;
- `esbuild` is a pinned `devDependency`.

Before activating, do the one-time setup:

1. On npmjs.com, add a trusted publisher for `deploy.yml` with environment `npm`.
2. Create the `npm` environment and allow tags `v*` to deploy to it.
3. Turn on release immutability.

Add `release/` to CODEOWNERS so that activation needs your review.
