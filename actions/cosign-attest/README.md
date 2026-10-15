# cosign attest

Composite action for keyless Sigstore signing and SLSA v1 provenance, out of band. It uses
the job's GitHub OIDC identity and the official `sigstore/cosign-installer`, and it never
calls the GitHub attestations API. For each subject it writes two bundles next to the file:

- `<file>.sigstore.json`: the `cosign sign-blob` signature bundle.
- `<file>.intoto.sigstore.json`: the `cosign attest-blob` SLSA v1 provenance bundle.

Both bundles are verified against the workflow identity before the step succeeds. Design
notes: [ADR-0008](../../docs/adr/0008-supply-chain-actions.md).

## Requirements

- Job permission `id-token: write`.
- `jq` on the runner (present on GitHub-hosted runners).
- Signing publishes the file digest, repository and workflow path to the public Rekor log.
  Private repositories are refused unless `allow-private-repo: "true"`.

## Usage

```yaml
- uses: ./actions/cosign-attest
  with:
    subjects: |
      dist/*.tgz
      build/**/*.zip
    checksums-file: dist/SHA256SUMS   # optional: written over the subjects, then signed too
```

| Input | Default | |
|---|---|---|
| `subjects` | required | Newline-separated files or globs. Each line must match at least one file |
| `cosign-release` | `v3.1.3` | cosign version |
| `predicate-type` | `slsaprovenance1` | `attest-blob --type` |
| `certificate-identity` | this workflow at this ref | Set it when signing from a reusable workflow |
| `checksums-file` | empty | Write `sha256  basename` per subject here and sign it as well |
| `allow-private-repo` | `false` | See the Rekor note above |

Outputs:
- `bundles`: newline-separated paths.
- `files`: the subjects, the checksums file and every bundle, which is everything to release.
- `certificate-identity`.

Uploading is left to the caller. [`sealed-release`](../sealed-release) does it for the
release chain.

## Verify anywhere

Only cosign is needed, with no GitHub account and no token:

```sh
ID='https://github.com/susanbeasles/porchlight/.github/workflows/release.yml@refs/heads/main'
ISSUER='https://token.actions.githubusercontent.com'

cosign verify-blob --bundle pkg.tgz.sigstore.json \
  --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER" pkg.tgz

cosign verify-blob-attestation --bundle pkg.tgz.intoto.sigstore.json --type slsaprovenance1 \
  --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER" pkg.tgz
```

Pin the exact identity as shown. A regexp that matches any workflow in the repository also
accepts signatures from pull-request or ad-hoc workflows.
