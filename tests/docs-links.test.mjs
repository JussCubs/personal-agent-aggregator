import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

function markdownFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    if (["node_modules", ".git", "dist", ".scratch"].includes(entry)) continue;
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) out.push(...markdownFiles(path));
    else if (entry.endsWith(".md")) out.push(path);
  }
  return out;
}

/** GitHub's heading anchors: lowercase, punctuation dropped, spaces to hyphens, duplicates numbered. */
function anchors(markdown) {
  const seen = new Map();
  const out = new Set();
  let fenced = false;
  for (const line of markdown.split("\n")) {
    if (/^```/.test(line)) fenced = !fenced;
    if (fenced) continue;
    const match = /^#{1,6}\s+(.*?)\s*#*\s*$/.exec(line);
    if (!match) continue;
    const base = match[1].toLowerCase().replace(/[^\p{L}\p{N}\s_-]/gu, "").replace(/\s/g, "-");
    const count = seen.get(base) ?? 0;
    seen.set(base, count + 1);
    out.add(count === 0 ? base : `${base}-${count}`);
  }
  return out;
}

test("every relative Markdown link points at an existing file and heading", () => {
  const problems = [];
  for (const file of markdownFiles(ROOT)) {
    const text = readFileSync(file, "utf8").replace(/```[\s\S]*?```/g, "");
    for (const match of text.matchAll(/\]\(([^)\s]+)\)/g)) {
      const target = match[1];
      if (/^(https?:|mailto:)/.test(target)) continue;
      const [pathPart, anchor] = target.split("#");
      const resolved = pathPart ? resolve(dirname(file), pathPart) : file;
      if (pathPart.startsWith("../../compare") || pathPart.startsWith("../../releases")) continue; // GitHub release links in CHANGELOG
      if (!existsSync(resolved)) {
        problems.push(`${relative(ROOT, file)}: ${target} (missing file)`);
        continue;
      }
      if (anchor && resolved.endsWith(".md") && !anchors(readFileSync(resolved, "utf8")).has(anchor)) {
        problems.push(`${relative(ROOT, file)}: ${target} (missing heading)`);
      }
    }
  }
  assert.deepEqual(problems, []);
});
