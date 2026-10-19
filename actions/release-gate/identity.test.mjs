import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { validateIdentity, verifyArtifact } from './identity.mjs';
const hash = x => createHash('sha256').update(x).digest('hex');
test('replaced artifact plus matching builder hash cannot satisfy independent identity', () => {
  const root = mkdtempSync(join(tmpdir(), 'porchlight-identity-'));
  try {
    mkdirSync(join(root, 'pkg'));
    writeFileSync(join(root, 'pkg/package-lock.json'), '{}');
    const config = { directory: 'pkg', artifact_identity: { filename: 'pkg.tgz', sha256: hash('reviewed'), source_tree: 'a'.repeat(40), package_lock_sha256: hash('{}') } };
    const id = validateIdentity(config, root, () => 'a'.repeat(40));
    writeFileSync(join(root, 'pkg.tgz'), 'reviewed');
    verifyArtifact(id, root, 'pkg.tgz');
    writeFileSync(join(root, 'pkg.tgz'), 'attacker');
    const builderDigest = hash('attacker');
    assert.notEqual(builderDigest, id.sha256);
    assert.throws(() => verifyArtifact(id, root, 'pkg.tgz'), /independently reviewed bytes/);
    assert.throws(() => validateIdentity(config, root, () => 'b'.repeat(40)), /source\/dependency/);
    writeFileSync(join(root, 'pkg/package-lock.json'), '{"modified":true}');
    assert.throws(() => validateIdentity(config, root, () => 'a'.repeat(40)), /source\/dependency/);
    assert.throws(() => validateIdentity({ directory: 'pkg' }, root), /required before activation/);
    rmSync(join(root, 'pkg.tgz'));
    symlinkSync('pkg/package-lock.json', join(root, 'pkg.tgz'));
    assert.throws(() => verifyArtifact(id, root, 'pkg.tgz'), /canonical/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
