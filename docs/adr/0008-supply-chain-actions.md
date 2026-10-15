# ADR-0008: Sealed releases, then npm deploy from the sealed artifacts

Status: proposed
Date: 2026-10-15
Amends: SPEC.md §2 (layout), §9 (slices S1, S2)

## Context

The owner wants npm publishing through OIDC trusted publishing with provenance, a
tree-shaken minimal bundle, automatic versioning, and out-of-band cosign signing with the
official cosign action rather than the GitHub attestations API. The owner set the shape:

- The GitHub release is sealed first. It holds the tarball, the checksums, and the signature
  and provenance bundles.
- The release starts as a draft and goes live only once complete.
- A separate deploy workflow publishes those sealed bytes to npm.

The owner's review added five requirements:

1. Activation is an explicit, reviewed change, never inferred from changed paths.
2. The job that runs build tooling holds no write, signing or publishing authority.
3. The deploy checks that every identifier of the release agrees.
4. Unverified real-world behavior stays listed as an acceptance gap.
5. No deletion until the canonical installation is verified.

Porchlight has no npm package today, so the chain ships inactive.

## Decision

### Activation

`release/npm.json` is the only switch. It is committed with `"enabled": false`. In that state
`release.yml` stops after a read-only gate job and `deploy.yml` refuses to run.

Activating is one reviewed change. It sets `enabled`, `directory`, `name` and `entry`.
`actions/release-gate` then refuses the change unless:

- the package directory holds a `package.json` and a lockfile;
- the package name equals the activated name;
- the package is not private;
- `repository` points at this GitHub repository (npm provenance requires it);
- `esbuild` is an exact-version devDependency.

The deploy re-reads the activation file at the release tag. The tarball must carry the
activated name. A path filter is not used as a switch, because it only says which paths a
push changed.

### Jobs and authority

```
release.yml (push to main; permissions: {} at the top, then per job)
  gate      contents: read     release-gate; outputs enabled=false and stops unless activated
  build     contents: read     npm ci --ignore-scripts, esbuild, version, npm pack;
                               records name + sha256; uploads artifact npm-tarball
  sign      contents: read     artifact-check (digest == build's); cosign-attest writes
            id-token: write    SHA256SUMS, signs + attests tarball and SHA256SUMS, self-verifies;
                               uploads artifact npm-sealed
  release   contents: write    artifact-check (exact 6 files, digest, SHA256SUMS line);
                               cosign-attest verify-only; sealed-release draft -> upload ->
                               read every asset back by id -> publish -> tag == commit
  dispatch  actions: write     gh workflow run deploy.yml --ref <tag> -f tag=<tag>

deploy.yml (workflow_dispatch only; environment npm; contents: read, id-token: write)
  release-gate at the tag (must be enabled); npm-trusted-publish:
    event == workflow_dispatch; ref == refs/tags/<input tag>
    release is published; release tag == input; release target == this commit
    tag ref is a lightweight tag on this commit
    SHA256SUMS signature, checksums, tarball signature and provenance verify against
      release.yml@refs/heads/main; provenance gitCommit == this commit
    tarball version == tag; tarball name == activated name
    npm publish <sealed tarball> --provenance (OIDC; NODE_AUTH_TOKEN refused)
    registry dist.integrity == sha512 of the sealed tarball
```

Only `build` runs third-party code (npm dependencies and esbuild). It holds read access
and nothing else: no OIDC token, no release write and no dispatch. Signing happens before
the draft exists, so the job that can write the repository never holds a signing identity.
The release job verifies the bundles before anything becomes public. The release goes live
only after every uploaded asset has been read back and matched. Each job is separate, so a
failure leaves the earlier stages' outputs intact and nothing partly public.

### Build once

The tarball is packed once, in `build`. Its sha256 is a job output. `artifact-check`
compares it at each handoff, alongside download-artifact's own digest check. The release
publishes those bytes. The deploy builds nothing and publishes those bytes. It checks them
before publishing, against the signed checksums, and after, against the registry's
`dist.integrity`.

### Other decisions

- **Why dispatch, not `on: release`.** Events caused by `GITHUB_TOKEN` do not start
  workflows, except `workflow_dispatch` and `repository_dispatch`. Running the deploy at
  `--ref <tag>` also means it uses the activation file, workflow and action code that were
  released, and npm provenance names the tagged commit.
- **Versioning.** Conventional commits since the last `v*` tag that touch the package
  decide the bump: a `!` or `BREAKING CHANGE` means major, `feat` means minor, and anything
  else means patch. No such commits means no release. The base is the higher of the registry
  version and the last tag, because a sealed release can be live before its deploy. Nothing
  is committed back.
- **Idempotent deploy.** If npm already holds the same integrity, the deploy succeeds
  without publishing. Different bytes fail. A late deploy of an older version publishes
  under `v<major>-backport`, so `latest` never moves backwards.
- **Disclosure guard.** Keyless signing writes the digest, repository and workflow to the
  public Rekor log, so `cosign-attest` refuses private repositories unless explicitly
  allowed.
- **Pinning.** Third-party actions are pinned by commit SHA (resolved with `git ls-remote`):
  - `actions/checkout` `3d3c42e…`
  - `actions/setup-node` `820762…`
  - `actions/upload-artifact` v7.0.2 `cf430e0…`
  - `actions/download-artifact` v8.0.2 `9000827…`
  - `sigstore/cosign-installer` v4.1.2 `6f9f177…`
- **C1.** C1 (no network) constrains the shipped product. These actions are CI tooling.

## Installation

`.github/workflows/` is protected. These say so:

- `CLAUDE.md`: "Never modify … .github/workflows/".
- `.agent-guard/policy.json`: `protected_write_paths` includes `.github/workflows/**`.
- `.claude/settings.json`: denies `Write(./.github/workflows/**)` and
  `Edit(./.github/workflows/**)`.

The final workflow contents therefore live in `docs/ci/`. `docs/ci/install-workflows.patch`
adds them as `.github/workflows/release.yml` and `.github/workflows/deploy.yml`. The owner
applies that patch. `docs/ci/` stays until the installed workflows are verified. Removing it
and repointing references is a later change.

## Acceptance

What is proven offline (`scripts/check`):

- **Versioning:** unit tests.
- **Workflow and action schema:** `action-validator`.
- **The whole chain, job by job** (`actions/tests/run.sh`): runs against stateful stubs of
  `gh`, `cosign` and `npm`. It covers the gate, every handoff, verify-only, draft and
  publish, and every deploy refusal.

The stubs prove the scripts' logic and failure handling. They do not prove real service
behavior.

Not yet proven. Each needs a controlled real check, and each fails closed until it passes:

| Gap | Controlled check that closes it |
|---|---|
| cosign v3.1.3 `sign-blob`/`attest-blob --bundle` and both verify commands. Matches cosign's published docs, never run here | In a throwaway public repository, run `cosign-attest` from a `workflow_dispatch` workflow, then run both verify commands from another machine |
| `gh release upload <tag>` finding a draft by its pending tag | Same throwaway repository: draft, upload, view, publish with `sealed-release` |
| GitHub keeping `target_commitish` as the SHA after publish, and the tag being lightweight | The same run; `deploy` checks both |
| Asset read-back by id with `Accept: application/octet-stream` | The same run |
| npm OIDC exchange and `npm publish <tarball> --provenance` | First deploy of a real package, or a scoped throwaway package, through the `npm` environment; then `npm audit signatures` |
| Release immutability blocking later asset or tag changes | After the first real release, attempt an asset upload and confirm it is refused |

The chain is not production-proven until those pass.

## Consequences

- Recovery is simple. A release whose deploy failed is retried with
  `gh workflow run deploy.yml --ref vX.Y.Z -f tag=vX.Y.Z`. A failed release run leaves only
  a draft, which the next run on the same commit reuses.
- If deploys are skipped, the GitHub release can be ahead of npm, and versioning accounts
  for it.
- The provenance is generated inside the workflow that builds, so it is SLSA Build L2, not
  L3.
- Every push to main runs the gate job (seconds, read-only), even while inactive.
