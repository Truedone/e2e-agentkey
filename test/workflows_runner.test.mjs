// AK-REV1-AC01 (issue 6): a workflow that takes its runner from a repository variable falls back to ubuntu-latest, so
// a fork or any repository without the variable can still run it. Every file under .github/workflows is read
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const DIR = new URL('../.github/workflows/', import.meta.url);

test('every runs-on that reads a variable has a fallback runner', () => {
  const files = fs.readdirSync(DIR).filter((f) => /\.ya?ml$/.test(f));
  assert.ok(files.length >= 2, `${files.length} workflows`);
  let seen = 0;
  for (const f of files) {
    for (const [line] of fs.readFileSync(new URL(f, DIR), 'utf8').matchAll(/^\s*runs-on:.*$/gm)) {
      if (!/\bvars\./.test(line)) continue;
      seen++;
      assert.match(line, /\$\{\{\s*vars\.[A-Z_]+\s*\|\|\s*'ubuntu-latest'\s*\}\}/, `${f}: ${line.trim()}`);
    }
  }
  assert.ok(seen >= 2, `${seen} runs-on lines read a variable`);
});
