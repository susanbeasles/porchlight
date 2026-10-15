# npm trusted publish

The deploy half of the release chain. It publishes a sealed GitHub release to npmjs.org
and builds nothing. See [ADR-0008](../../docs/adr/0008-supply-chain-actions.md) and
[`docs/ci/deploy.yml`](../../docs/ci/deploy.yml).

1. Refuses to run unless the event is `workflow_dispatch`, the ref is
   `refs/tags/<input tag>`, OIDC is available, and no `NODE_AUTH_TOKEN` is set.
2. Checks that the release is published under the input tag, that its target is this
   run's commit, and that the tag is a lightweight tag on that commit. It then downloads
   the release and checks that it holds exactly one `.tgz` plus `SHA256SUMS` and the
   bundles.
3. Verifies, with cosign, against the release workflow's identity
   (`release.yml@refs/heads/main` by default):
   - the `SHA256SUMS` signature;
   - every checksum;
   - the tarball's signature;
   - its SLSA provenance.
4. Checks that the verified provenance names this run's commit, that the version in the
   tarball matches the tag, and that its name equals `package-name`, the name activated in
   `release/npm.json` at the tag.
5. Runs `npm publish <tarball> --provenance` through OIDC trusted publishing. It then
   waits until the registry's `dist.integrity` equals the sha512 of the sealed tarball.

Re-runs are safe. If the version is already on npm with the same bytes, the job succeeds
without publishing. If it is there with different bytes, the job fails. An older version
deployed late goes out under `v<major>-backport`, so `latest` never moves backwards.

## Requirements

- `workflow_dispatch`, run at the tag: `gh workflow run deploy.yml --ref v1.2.3 -f tag=v1.2.3`.
- Permissions `contents: read` and `id-token: write`.
- A trusted publisher on npmjs.com for this repository, `deploy.yml`, and environment
  `npm`. Afterwards, disallow token publishing for the package.
- The `npm` environment's deployment rule must allow tags `v*`.
- A public repository. npm provenance and public Rekor need one.

| Input | Default | |
|---|---|---|
| `tag` | required | Release to publish |
| `package-name` | required | The activated package name (`release-gate` output at the tag) |
| `signer-identity` | `https://github.com/<repo>/.github/workflows/release.yml@refs/heads/main` | Who must have signed it |
| `dry-run` | `false` | Verify everything, publish nothing |
| `node-version` / `npm-version` / `cosign-release` | `22` / `11.5.1` / `v3.1.3` | |

## Verify as a consumer

```sh
npm audit signatures                       # npm provenance, in a project using the package
gh release download v1.2.3 -R susanbeasles/porchlight && sha256sum -c SHA256SUMS
cosign verify-blob --bundle SHA256SUMS.sigstore.json SHA256SUMS \
  --certificate-identity https://github.com/susanbeasles/porchlight/.github/workflows/release.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
