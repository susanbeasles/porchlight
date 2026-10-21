// Independent expected bytes come from the reviewed source checkout, never build outputs.
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { resolve, relative, sep } from 'node:path';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const digest = bytes => createHash('sha256').update(bytes).digest('hex');
function regular(root, name) {
  const path = resolve(root, name);
  const rel = relative(root, path);
  if (!rel || rel.startsWith('..' + sep) || rel === '..' || realpathSync(path) !== path)
    throw Error('identity path must be canonical and inside checkout');
  const info = lstatSync(path);
  if (!info.isFile() || info.nlink !== 1 || info.size > 64 * 1024 * 1024) throw Error('identity input must be a single regular file');
  return path;
}
export function validateIdentity(config, root, tree = directory => execFileSync('/usr/bin/git',
  ['-C', root, 'rev-parse', '--verify', `HEAD:${directory}`], { encoding: 'utf8', env: { PATH: '/usr/bin:/bin', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' } }).trim()) {
  const id = config.artifact_identity;
  if (!id || !/^[a-f0-9]{64}$/.test(id.sha256 ?? '') ||
      !/^[a-f0-9]{64}$/.test(id.package_lock_sha256 ?? '') ||
      !/^[a-f0-9]{40}$/.test(id.source_tree ?? '') ||
      !/^[A-Za-z0-9._-]+\.tgz$/.test(id.filename ?? ''))
    throw Error('independently reviewed artifact identity is required before activation');
  const directory = config.directory;
  if (typeof directory !== 'string' || !/^[A-Za-z0-9_./-]+$/.test(directory) || directory.startsWith('/') || directory.split('/').some(x => x === '..' || x === '.' || !x))
    throw Error('invalid identity source directory');
  const lock = regular(root, `${directory}/package-lock.json`);
  if (digest(readFileSync(lock)) !== id.package_lock_sha256 || tree(directory) !== id.source_tree)
    throw Error('reviewed source/dependency identity does not match checkout');
  return id;
}
export function verifyArtifact(id, dir, filename) {
  if (filename !== id.filename) throw Error('artifact filename differs from reviewed identity');
  const path = regular(realpathSync(dir), filename);
  if (digest(readFileSync(path)) !== id.sha256) throw Error('artifact differs from independently reviewed bytes');
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const root = realpathSync(process.cwd());
    const config = JSON.parse(readFileSync(regular(root, process.env.CONFIG || 'release/npm.json'), 'utf8'));
    const id = validateIdentity(config, root);
    if (process.argv[2] === 'verify') verifyArtifact(id, process.env.DIR, process.env.TARBALL);
    else if (process.argv[2] !== 'validate') throw Error('expected validate or verify');
  } catch (error) { process.stderr.write(`release identity: ${error.message}\n`); process.exitCode = 1; }
}
