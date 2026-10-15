import assert from "node:assert/strict";
import { test } from "node:test";

import { bump, compare, level, next, parse } from "./version.mjs";

test("parse rejects anything but x.y.z", () => {
  assert.deepEqual(parse("1.2.3"), [1, 2, 3]);
  for (const bad of ["1.2", "v1.2.3", "1.2.3-rc.1", "", undefined]) assert.throws(() => parse(bad));
});

test("compare orders numerically", () => {
  assert.ok(compare("1.10.0", "1.9.9") > 0);
  assert.equal(compare("2.0.0", "2.0.0"), 0);
});

test("level from conventional commits", () => {
  assert.equal(level(["docs: x", "chore: y"]), "patch");
  assert.equal(level(["fix(core): x", "feat: y"]), "minor");
  assert.equal(level(["feat(api)!: drop v1"]), "major");
  assert.equal(level(["refactor: x\n\nBREAKING CHANGE: removed y"]), "major");
  assert.equal(level(["Merge pull request #7"]), "patch");
});

test("bump resets lower parts", () => {
  assert.equal(bump("1.2.3", "major"), "2.0.0");
  assert.equal(bump("1.2.3", "minor"), "1.3.0");
  assert.equal(bump("1.2.3", "patch"), "1.2.4");
});

test("next: nothing new means no release", () => {
  assert.equal(next({ published: "1.0.0", manifest: "1.0.0", messages: [] }), null);
});

test("next: first publish uses the manifest version as is", () => {
  assert.equal(next({ published: null, manifest: "0.1.0", messages: ["feat: x"] }), "0.1.0");
});

test("next: bumps from the registry, not from a stale manifest", () => {
  assert.equal(next({ published: "1.4.2", manifest: "1.0.0", messages: ["fix: x"] }), "1.4.3");
  assert.equal(next({ published: "1.4.2", manifest: "1.4.2", messages: ["feat: x"] }), "1.5.0");
});

test("next: a manually raised manifest wins when ahead", () => {
  assert.equal(next({ published: "1.4.2", manifest: "2.0.0", messages: ["fix: x"] }), "2.0.0");
});

test("next: a live release tag ahead of npm is never reused", () => {
  // v1.5.0 was sealed and released, but its npm deploy has not run yet.
  assert.equal(next({ published: "1.4.2", tagged: "1.5.0", manifest: "1.0.0", messages: ["fix: x"] }), "1.5.1");
  assert.equal(next({ published: null, tagged: "0.1.0", manifest: "0.1.0", messages: ["feat: x"] }), "0.2.0");
});

test("next: npm ahead of the tags still wins", () => {
  assert.equal(next({ published: "2.0.0", tagged: "1.9.0", manifest: "1.0.0", messages: ["fix: x"] }), "2.0.1");
});
