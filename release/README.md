# npm release activation

`npm.json` is the single switch for the npm release chain (ADR-0008). While `enabled` is
`false`, `release.yml` stops after its gate job and `deploy.yml` refuses to run, so nothing
is built, signed, released or published.

## Activating (agent procedure)

An agent activates the chain with one PR. The owner's part is to approve and merge that PR,
nothing else.

1. **Package.** Add or prepare the package with:
   - a lockfile and an exact-version `esbuild` devDependency;
   - `repository` pointing at this GitHub repository;
   - `files` covering the bundle.

   Run `scripts/check`.
2. **Activation.** Set these fields in `npm.json`:

   | Field | Value |
   |---|---|
   | `enabled` | `true` |
   | `directory` | Package directory, relative to the repository root |
   | `name` | The exact `name` in that directory's `package.json` |
   | `entry` | Bundle entry point, relative to `directory` |
   | `out_file` | Bundle output, relative to `directory` (default `dist/index.js`) |
   | `max_bundle_bytes` | Size budget for the bundle; `0` disables it |

   The gate refuses the change unless:
   - the directory holds `package.json` and `package-lock.json`;
   - the name matches;
   - the package is not `private`;
   - `repository` points here, which npm provenance requires;
   - `esbuild` is pinned.

   The agent runs the gate locally before pushing:

   ```sh
   CONFIG=release/npm.json GITHUB_REPOSITORY=susanbeasles/porchlight \
     GITHUB_OUTPUT=/dev/stdout bash actions/release-gate/gate.sh
   ```
3. **Repository settings.** Using the GitHub API, the agent:
   - creates the `npm` environment;
   - limits its deployments to tags matching `v*`;
   - adds the owner as a required reviewer;
   - turns on release immutability.

   These need admin permission. If the agent's GitHub App lacks it, the agent reports the
   exact refusal and the setting, and the owner makes that one change.
4. **npm trusted publisher.** This is bound to the owner's npm account and 2FA, so no agent can
   set it. The agent states the exact values in the activation PR:
   - repository `susanbeasles/porchlight`;
   - workflow `deploy.yml`;
   - environment `npm`.

   It also asks the owner to disallow token publishing afterwards. The first deploy then
   proves the configuration: the OIDC exchange either succeeds or fails with npm's error.
5. **Review requirement.** The activation PR proposes adding `release/` to `CODEOWNERS`. That is a
   protected path, so the agent writes it only at the owner's direction, through an approval
   prompt.
6. **After merge.** The agent watches the first `release.yml` run and the `deploy.yml` run it
   dispatches. It then checks, from outside the pipeline:
   - `cosign verify-blob` against the release assets;
   - `npm audit signatures`;
   - that the registry integrity matches the release asset.

   Each check that passes closes an acceptance gap in ADR-0008.
