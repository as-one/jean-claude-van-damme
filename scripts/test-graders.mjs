// Offline checks for the eval suite. No model calls, no dependencies.
// Usage: node scripts/test-graders.mjs [evals-directory]
// LLM graders are only checked for structure; their judgment needs `claude plugin eval`.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(process.argv[2] ?? join(here, "..", "evals"));

// Cases in which the skill is expected to stay unused.
const NEGATIVE_CASES = new Set(["ignores-unrelated-request"]);

const skillCall = (name) => JSON.stringify({ skill: name });
const SKILL_SAMPLES = {
  match: [
    skillCall("jean-claude-van-damme"),
    skillCall("jean-claude-van-damme:jean-claude-van-damme"),
    '{"skill" : "jean-claude-van-damme", "args": "diff"}',
  ],
  reject: [
    skillCall("security-review"),
    skillCall("jean-claude-van-damme-extra"),
    '{"args": "jean-claude-van-damme"}',
  ],
};

// Every regex or input_match grader needs samples here.
const SAMPLES = {
  "real-sql-injection/report-format.md": {
    match: [
      "- Location: a.js:8\n- Path: q -> query\n- Impact: data read\n- Fix: bind it",
      "**location:** a.js\n**path:** q\n**fix:** bind",
    ],
    reject: [
      "There is a SQL injection. Use bound parameters.",
      "- Fix: bind it\n- Path: q\n- Location: a.js",
      "- Location: a.js\n- Fix: bind it",
    ],
  },
};

const errors = [];
const fail = (where, message) => errors.push(`${where}: ${message}`);

function parse(file) {
  const found = /^---\n([\s\S]*?)\n---\n?([\s\S]*)$/.exec(readFileSync(file, "utf8"));
  if (!found) return null;
  const meta = {};
  for (const line of found[1].split("\n")) {
    const pair = /^([A-Za-z_]+):\s*(.*)$/.exec(line);
    if (!pair) continue;
    let value = pair[2].trim();
    if (value.length > 1 && value.startsWith("'") && value.endsWith("'")) {
      value = value.slice(1, -1).replaceAll("''", "'");
    }
    meta[pair[1]] = value;
  }
  return { meta, body: found[2].trim() };
}

function checkPattern(where, pattern, flags, samples) {
  let regex;
  try {
    regex = new RegExp(pattern, flags);
  } catch (error) {
    fail(where, `invalid regular expression (${error.message})`);
    return 0;
  }
  if (!samples?.match?.length || !samples?.reject?.length) {
    fail(where, "no match and reject samples in scripts/test-graders.mjs");
    return 0;
  }
  const test = (text) => {
    regex.lastIndex = 0;
    return regex.test(text);
  };
  for (const text of samples.match) {
    if (!test(text)) fail(where, `should match ${JSON.stringify(text)}`);
  }
  for (const text of samples.reject) {
    if (test(text)) fail(where, `should not match ${JSON.stringify(text)}`);
  }
  return samples.match.length + samples.reject.length;
}

const cases = readdirSync(root, { withFileTypes: true })
  .filter((entry) => entry.isDirectory() && entry.name !== "results")
  .map((entry) => entry.name)
  .sort();
if (cases.length === 0) fail(root, "no eval cases found");

let graderCount = 0;
let sampleCount = 0;
const usedSamples = new Set();

for (const name of cases) {
  const promptFile = join(root, name, "prompt.md");
  const graderDir = join(root, name, "graders");

  if (!existsSync(promptFile)) {
    fail(name, "missing prompt.md");
  } else {
    const prompt = parse(promptFile);
    if (!prompt) fail(name, "prompt.md has no frontmatter");
    else {
      for (const key of ["description", "model", "allowed_tools"]) {
        if (!prompt.meta[key]) fail(name, `prompt.md is missing "${key}"`);
      }
      if (!prompt.body) fail(name, "prompt.md has an empty prompt");
    }
  }

  const graders = existsSync(graderDir)
    ? readdirSync(graderDir).filter((file) => file.endsWith(".md")).sort()
    : [];
  if (graders.length === 0) fail(name, "no graders");

  const expected = NEGATIVE_CASES.has(name) ? "skill-not-fired.md" : "skill-fired.md";
  if (!graders.includes(expected)) fail(name, `missing graders/${expected}`);

  for (const file of graders) {
    const id = `${name}/${file}`;
    const grader = parse(join(graderDir, file));
    graderCount += 1;
    if (!grader) {
      fail(id, "no frontmatter");
      continue;
    }
    const { meta, body } = grader;
    if (meta.type === "llm") {
      if (!/\bPASS\b/.test(body) || !/\bFAIL\b/.test(body)) {
        fail(id, "rubric must state both PASS and FAIL conditions");
      }
    } else if (meta.type === "regex") {
      if (!meta.pattern) fail(id, 'regex grader without "pattern"');
      else {
        usedSamples.add(id);
        sampleCount += checkPattern(id, meta.pattern, meta.flags ?? "", SAMPLES[id]);
      }
    } else if (meta.type === "tool_used") {
      if (!meta.tool) fail(id, 'tool_used grader without "tool"');
      if (meta.input_match) {
        const isSkill = meta.tool === "Skill";
        if (!isSkill) usedSamples.add(id);
        sampleCount += checkPattern(
          id,
          meta.input_match,
          "",
          isSkill ? SKILL_SAMPLES : SAMPLES[id],
        );
      }
      if (file === "skill-not-fired.md" && meta.max !== "0") {
        fail(id, 'a negative trigger grader needs "max: 0"');
      }
    } else {
      fail(id, `unknown grader type "${meta.type}"`);
    }
  }
}

for (const id of Object.keys(SAMPLES)) {
  if (!usedSamples.has(id)) fail(id, "samples refer to a grader that does not exist");
}

if (errors.length > 0) {
  console.error(errors.map((error) => `FAIL ${error}`).join("\n"));
  process.exit(1);
}
console.log(`OK: ${cases.length} cases, ${graderCount} graders, ${sampleCount} pattern samples`);
