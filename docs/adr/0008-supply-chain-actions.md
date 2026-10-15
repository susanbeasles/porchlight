# ADR-0008: Supply-chain slices: npm trusted publishing and out-of-band cosign

Status: proposed
Date: 2026-10-15
Amends: SPEC.md §2 (layout), §9 (slices S1, S2)

## Context

The owner asked for two small, focused composite GitHub Actions: one that publishes to
npmjs.org with OIDC, provenance, a tree-shaken minimal bundle, automated versioning and a
GitHub release on every push to `main`; and one that signs and attests artifacts with
cosign over plain OIDC, out of band, without the GitHub attestations API. Porchlight has no
npm package today, so both are generic and live in `actions/`, separate from the product.

## Decision

**No long-lived credentials.** S1 refuses to run when `NODE_AUTH_TOKEN` is set and does not
pass `registry-url` to `setup-node`, which would write an `.npmrc` that reads that variable.
npm 11.5.1+ exchanges the job's OIDC token for a short-lived, package-scoped publish
credential. S2 uses Fulcio keyless certificates bound to the same OIDC identity. Neither
action reads a secret.

**Build integrity.** `npm ci --ignore-scripts` from the lockfile; esbuild comes from the
package's own pinned devDependency, not a floating global. The bundle is
`--bundle --minify --tree-shaking=true --packages=external`, so runtime dependencies stay
declared (and visible to `npm audit`) instead of being inlined. After `npm pack` the
tarball's file list is checked against an allow-list (the bundle directory, `package.json`,
README, LICENSE, CHANGELOG); anything else fails the job. The exact tarball that was checked
is the one published, released and signed.

**Versioning.** Conventional commits since the last `v*` tag that touch the package
directory: a `!` or `BREAKING CHANGE` means major, `feat` means minor, anything else means patch. No
commits means no release, which keeps re-runs idempotent. The base is the version in the registry, so
a lost tag cannot cause a downgrade. A manifest version raised by hand wins when it is
ahead. The bump is written to `package.json` in the runner only. Nothing is pushed back to
`main`: no bot commits and no write-capable git credential in the job. The tag is created
server-side by `gh release create --target $GITHUB_SHA`.

**Out-of-band signing.** S2 installs cosign through the official
`sigstore/cosign-installer`, pinned by commit SHA, and runs `sign-blob` and `attest-blob`
(SLSA v1 predicate). Bundles are written as `<file>.sigstore.json` and
`<file>.intoto.sigstore.json` and optionally uploaded to the release. The step verifies
both bundles against the exact workflow identity
(`https://github.com/$GITHUB_WORKFLOW_REF`) and the GitHub issuer before it returns, so an
unverifiable bundle is never handed on. Verification needs only cosign and the public
Sigstore roots, not GitHub.

**Disclosure guard.** Keyless signing writes the artifact digest, repository and workflow
path to the public Rekor log. S2 refuses private repositories unless the caller sets
`allow-private-repo: true`.

**Pinning.** Every third-party action is pinned by full commit SHA. Composite actions
inherit the caller's permissions, so the example workflow sets `permissions: {}` at the
top and grants `contents: write` and `id-token: write` to the one job, in an `npm`
environment the owner can gate with required reviewers.

**Scope of C1.** C1 (no network) constrains the shipped app and extension. These actions
are CI tooling, never linked into or shipped with the product, so C1 does not apply to them.
`scripts/check` runs their unit tests when Node is present.

## Consequences

- npm's own provenance and the cosign bundles are two independent attestations of the
  same tarball. The npm one is checked by `npm audit signatures`; the cosign one is checked
  with `cosign verify-blob` and needs no GitHub or npm.
- Publish happens before cosign signs. If S2 fails after S1 publishes, the npm version
  still carries npm provenance, but the release has no cosign bundles and the run is red.
  To sign before publishing, split the publish into a second job that runs after `dry-run`
  and S2. That is deferred until an actual package exists.
- The provenance comes from the same job that builds, so it is SLSA Build L2, not L3. L3
  needs the signing to run in an isolated reusable workflow. Callers that sign from a
  reusable workflow set `certificate-identity` to that workflow's ref.
- `.github/workflows/` is off-limits to agents (CLAUDE.md), so the workflow ships as
  `docs/ci/release.yml` for the owner to copy.
- The cosign v3 command line was written from the documentation and is not exercised in
  this repository's CI. The self-verify step fails closed if a flag behaves differently.
