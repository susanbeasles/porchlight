// Next version from Conventional Commits since the last release tag.
// The base is the higher of the registry's version and the last v* tag: a sealed GitHub
// release can be live before its npm deploy finishes, and neither may be reused.
// Every push with new commits releases: breaking -> major, feat -> minor, anything else -> patch.
// Writes the version into package.json (no git commit, no git tag) and to $GITHUB_OUTPUT.

import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const SEMVER = /^(\d+)\.(\d+)\.(\d+)$/;

export function parse(v) {
  const m = String(v ?? "").match(SEMVER);
  if (!m) throw new Error(`not a plain x.y.z version: ${JSON.stringify(v)}`);
  return m.slice(1).map(Number);
}

export function compare(a, b) {
  const [x, y] = [parse(a), parse(b)];
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i];
  return 0;
}

/** "major" | "minor" | "patch" from full commit messages. */
export function level(messages) {
  let out = "patch";
  for (const msg of messages) {
    const subject = msg.split("\n", 1)[0];
    if (/^\w+(\([^)]*\))?!:/.test(subject) || /^BREAKING[ -]CHANGE:/m.test(msg)) return "major";
    if (/^feat(\([^)]*\))?:/.test(subject)) out = "minor";
  }
  return out;
}

export function bump(version, kind) {
  const [maj, min, pat] = parse(version);
  if (kind === "major") return `${maj + 1}.0.0`;
  if (kind === "minor") return `${maj}.${min + 1}.0`;
  return `${maj}.${min}.${pat + 1}`;
}

/**
 * published: latest version on npm, or null if the package was never published.
 * tagged: version of the last v* release tag, or null if there is none.
 * manifest: version in package.json. messages: commits since the last release tag.
 * Returns the version to release, or null when there is nothing new.
 */
export function next({ published, tagged = null, manifest, messages }) {
  if (messages.length === 0) return null;
  const known = [published, tagged].filter((v) => v !== null);
  if (known.length === 0) return parse(manifest) && manifest; // first release: as declared
  const released = known.reduce((a, b) => (compare(a, b) >= 0 ? a : b));
  const candidate = bump(released, level(messages));
  // A manually raised package.json version wins if it is ahead of the computed one.
  return compare(manifest, candidate) > 0 ? manifest : candidate;
}

function sh(cmd, args) {
  return execFileSync(cmd, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

function publishedVersion(name) {
  try {
    return sh("npm", ["view", name, "version"]) || null;
  } catch (e) {
    if (/E404|404 Not Found/.test(String(e.stderr))) return null;
    throw e;
  }
}

function lastTag() {
  try {
    return sh("git", ["describe", "--tags", "--abbrev=0", "--match", "v[0-9]*.[0-9]*.[0-9]*"]);
  } catch {
    return null; // no release tag yet: every commit counts
  }
}

function commitsSince(tag) {
  const raw = sh("git", ["log", "--format=%B%x00", tag ? `${tag}..HEAD` : "HEAD", "--", "."]);
  return raw.split("\0").map((s) => s.trim()).filter(Boolean);
}

function main() {
  const pkg = JSON.parse(readFileSync("package.json", "utf8"));
  if (pkg.private) throw new Error("package.json is private; refusing to publish");
  const published = publishedVersion(pkg.name);
  const tag = lastTag();
  const tagged = tag && /^v\d+\.\d+\.\d+$/.test(tag) ? tag.slice(1) : null;
  const messages = commitsSince(tag);
  const version = next({ published, tagged, manifest: pkg.version, messages });
  const out = process.env.GITHUB_OUTPUT;
  if (version === null) {
    console.log(`version: no commits since the last release of ${pkg.name}; nothing to publish`);
    if (out) appendFileSync(out, "version=\ntag=\n");
    return;
  }
  sh("npm", ["version", version, "--no-git-tag-version", "--allow-same-version"]);
  console.log(`version: ${pkg.name} npm ${published ?? "-"} tag ${tagged ?? "-"} -> ${version} from ${messages.length} commits`);
  if (out) appendFileSync(out, `version=${version}\ntag=v${version}\n`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  try {
    main();
  } catch (e) {
    console.log(`::error title=npm build::${e.message}`);
    process.exit(1);
  }
}
