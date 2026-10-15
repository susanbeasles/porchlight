# release gate

Reads [`release/npm.json`](../../release/npm.json), the single reviewed switch for the npm
release chain ([ADR-0008](../../docs/adr/0008-supply-chain-actions.md)).

- **Inactive** (`enabled` is not `true`): outputs `enabled=false`, writes a notice, and
  succeeds. The workflows skip every later job, so nothing is built, signed or published.
- **Active:** refuses unless the package directory, lockfile and entry exist, the package
  name matches `name`, the package is not private, `repository` points at this GitHub
  repository, and `esbuild` is an exact-version devDependency. It then outputs `enabled`,
  `directory`, `name`, `entry`, `out-file` and `max-bundle-bytes`.

`release.yml` runs it in a read-only job before building. `deploy.yml` runs it at the
release tag and requires the tarball to carry the activated name.
