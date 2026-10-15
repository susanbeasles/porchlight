// Next version from Conventional Commits since the last release tag.
// The npm registry is the source of truth for what is already out; tags mark where.
// Every push with new commits releases: breaking -> major, feat -> minor, anything else -> patch.
// Writes the version into package.json (no git commit, no git tag) and to $GITHUB_OUTPUT.

import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const SEMVER = /^(\d+)\.(\d+)\.(\d+)$/;

export function parse(v) {
  const m = SEMVER.exec(v ?? "");
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
 * manifest: version in package.json. messages: commits since the last release tag.
 * Returns the version to publish, or null when there is nothing new.
 */
export function next({ published, manifest, messages }) {
  if (messages.length === 0) return null;
  if (published === null) return parse(manifest) && manifest; // first release: as declared
  const base = compare(manifest, published) > 0 ? manifest : published;
  const candidate = bump(published, level(messages));
  // A manually raised package.json version wins if it is ahead of the computed one.
  return compare(base, candidate) > 0 ? base : candidate;
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

function commitsSinceLastTag() {
  let range = "HEAD";
  try {
    const tag = sh("git", ["describe", "--tags", "--abbrev=0", "--match", "v[0-9]*.[0-9]*.[0-9]*"]);
    range = `${tag}..HEAD`;
  } catch {
    // no release tag yet: every commit counts
  }
  const raw = sh("git", ["log", "--format=%B%x00", range, "--", "."]);
  return raw.split("\0").map((s) => s.trim()).filter(Boolean);
}

function main() {
  const pkg = JSON.parse(readFileSync("package.json", "utf8"));
  if (pkg.private) throw new Error("package.json is private; refusing to publish");
  const published = publishedVersion(pkg.name);
  const messages = commitsSinceLastTag();
  const version = next({ published, manifest: pkg.version, messages });
  const out = process.env.GITHUB_OUTPUT;
  if (version === null) {
    console.log(`version: no commits since the last release of ${pkg.name}; nothing to publish`);
    if (out) appendFileSync(out, "version=\ntag=\n");
    return;
  }
  sh("npm", ["version", version, "--no-git-tag-version", "--allow-same-version"]);
  console.log(`version: ${pkg.name} ${published ?? "(unpublished)"} -> ${version} from ${messages.length} commits`);
  if (out) appendFileSync(out, `version=${version}\ntag=v${version}\n`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  try {
    main();
  } catch (e) {
    console.log(`::error title=npm trusted publish::${e.message}`);
    process.exit(1);
  }
}
