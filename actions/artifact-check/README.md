# artifact check

Checks a job-to-job handoff in the release chain. This keeps the build-once contract across
privilege boundaries ([ADR-0008](../../docs/adr/0008-supply-chain-actions.md)).

- The directory holds exactly the expected files: the tarball, plus SHA256SUMS and four
  bundles when `signed: "true"`.
- The tarball's sha256 equals the digest the build job recorded.
- When signed, `SHA256SUMS` is exactly the line `<sha256>  <tarball>`.

Outputs `files`, the absolute paths of the handoff, which `sealed-release` publishes.

```yaml
- uses: ./actions/artifact-check
  with:
    dir: ${{ runner.temp }}/sealed
    tarball: ${{ needs.build.outputs.tarball }}
    sha256: ${{ needs.build.outputs.sha256 }}
    signed: "true"
```
