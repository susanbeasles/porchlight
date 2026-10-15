# ADR-0008: Sealed releases, then npm deploy from the sealed artifacts

Status: proposed
Date: 2026-10-15
Amends: SPEC.md §2 (layout), §9 (slices S1, S2)

## Context

The owner wants npm publishing through OIDC with provenance, a tree-shaken minimal bundle,
automatic versioning, and out-of-band cosign signing through the official cosign action
(not the GitHub attestations API). The owner also set the shape: the GitHub release is
sealed first, with every standard artifact (tarball, checksums, signature and provenance
bundles), and npm publishing is a separate deploy workflow that ships those sealed
artifacts. The release starts as a draft and goes live only once complete. Porchlight has no
npm package today, so the actions are generic and live in `actions/`, apart from the product.

## Decision

Two workflows, four small composite actions.

```
push to main ─ release.yml (contents:write, id-token:write, actions:write)
  npm-build          npm ci --ignore-scripts; esbuild bundle; version; npm pack; allow-list
  sealed-release     draft: new tag only, draft at $GITHUB_SHA
  cosign-attest      SHA256SUMS; sign-blob + attest-blob (SLSA v1) each; self-verify
  sealed-release     publish: upload; download each asset back, compare sha256;
                     publish (the tag is created now); check the tag points at $GITHUB_SHA
  gh workflow run deploy.yml --ref vX.Y.Z -f tag=vX.Y.Z
                                   │
deploy.yml at the tag (contents:read, id-token:write, environment npm)
  npm-trusted-publish  download the release; verify the SHA256SUMS signature, the checksums,
                       the tarball's signature and provenance against release.yml@main;
                       provenance commit == $GITHUB_SHA; tarball version == tag;
                       npm publish <tarball> --provenance; registry integrity == sealed sha512
```

**Build once, publish those bytes.** The deploy job builds nothing. The tarball npm
receives is the one checksummed, signed and released, and the deploy proves it twice:
before publishing, against the signed checksums, and after, against the registry's
`dist.integrity`.

**Draft, then live.** Assets are attached to a draft that nobody can consume. The release
is published only after every asset has been downloaded back by id and matched against the
local file. On GitHub a draft has no tag yet, so the tag only ever points at a complete
release. With release immutability on (repository setting), that release's assets and tag
cannot change afterwards. A re-run reuses its own draft (same tag, same commit) and
removes stray assets from it. Any other release carrying the tag is refused.

**Why dispatch, not `on: release`.** Events caused by `GITHUB_TOKEN` do not start
workflows, except `workflow_dispatch` and `repository_dispatch`. Dispatching with
`--ref <tag>` also means the deploy runs the workflow and action code that were released,
and npm provenance names the tagged commit. The deploy refuses to run on any other ref.

**Separation of duties.** Only the release job can sign (cosign identity
`release.yml@refs/heads/main`). Only the deploy job can publish to npm (trusted publisher
bound to `deploy.yml` and environment `npm`, which can require a human reviewer). Each job
gets only the permissions its step needs. Neither job holds a long-lived secret. The deploy
refuses `NODE_AUTH_TOKEN`, and `setup-node` is not given `registry-url`, which would write
an `.npmrc` that reads that token.

**Versioning.** Conventional commits since the last `v*` tag that touch the package: a `!` or
`BREAKING CHANGE` means major, `feat` means minor, anything else means patch, and no commits means no
release. The base is the higher of the registry's version and the last tag, because a
sealed release can be live before its deploy. A manifest version raised by hand wins when
it is ahead. Nothing is committed back to `main`.

**Idempotent deploy.** If npm already has the version with identical integrity, the deploy
succeeds without publishing. Different bytes for that version fail the deploy. A late deploy of an
older version publishes under `v<major>-backport` instead of moving `latest` backwards.

**Disclosure guard.** Keyless signing writes the digest, repository and workflow to the
public Rekor log, so `cosign-attest` refuses private repositories unless
`allow-private-repo: true`. npm provenance also requires a public repository.

**Pinning and scope.** Third-party actions are pinned by commit SHA. The workflows set
`permissions: {}` at the top and grant per job. C1 (no network) constrains the shipped
product. These actions are CI tooling and are never linked into it.

## Consequences

- Recovery is simple. A release with a failed deploy is retried with
  `gh workflow run deploy.yml --ref vX.Y.Z -f tag=vX.Y.Z`. A failed release run leaves only
  a draft, which the next run of the same commit reuses.
- If deploys are skipped, the GitHub release can be ahead of npm, and versioning accounts
  for it.
- The provenance comes from the same job that builds, so it is SLSA Build L2, not L3.
- `.github/workflows/` is off-limits to agents, so both workflows live in `docs/ci/` for the
  owner to copy.
- `actions/tests/run.sh` runs the full chain offline against stateful stubs of `gh`,
  `cosign` and `npm`, and `scripts/check` runs it. The real cosign v3 flags, gh's handling
  of drafts and the npm OIDC exchange are proven only by the first real run. Every one of
  them fails closed.
