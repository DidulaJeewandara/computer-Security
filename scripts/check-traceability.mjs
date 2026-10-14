// [JDH] Fails when any R1-R10 or T1-T8 has no linked test in traceability.yaml (P0-JDH-1)
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

export const REQUIREMENTS = Array.from({ length: 10 }, (_, i) => `R${i + 1}`);
export const THREATS = Array.from({ length: 8 }, (_, i) => `T${i + 1}`);
const ALL_IDS = [...REQUIREMENTS, ...THREATS];
const STATUSES = ['open', 'done'];
const TASK_ID = /^P\d-[A-Z]{3}-\d+$/;

/**
 * Pure check over the parsed file. Returns a list of problems, each naming the
 * offending task, requirement or threat; an empty list means the matrix passes.
 *
 * @param {unknown} rows parsed traceability.yaml
 * @param {{ taskIds?: Set<string>, fileExists?: (path: string) => boolean }} [opts]
 */
export function checkTraceability(rows, opts = {}) {
  const { taskIds, fileExists = () => true } = opts;
  const problems = [];
  if (!Array.isArray(rows)) return ['traceability.yaml must be a list of task rows'];

  const covered = new Set();
  const seen = new Set();

  rows.forEach((row, i) => {
    const where = row && typeof row.task === 'string' && row.task ? row.task : `row ${i + 1}`;
    if (!row || typeof row !== 'object') {
      problems.push(`${where}: not a mapping`);
      return;
    }
    if (typeof row.task !== 'string' || !TASK_ID.test(row.task)) {
      problems.push(`${where}: no linked task ID`);
    } else {
      if (seen.has(row.task)) problems.push(`${where}: listed more than once`);
      seen.add(row.task);
      if (taskIds && !taskIds.has(row.task))
        problems.push(`${where}: task ID not found in prompt.md`);
    }
    if (!STATUSES.includes(row.status)) problems.push(`${where}: status must be open or done`);

    const discharges = Array.isArray(row.discharges) ? row.discharges : [];
    if (!Array.isArray(row.discharges)) problems.push(`${where}: discharges must be a list`);
    for (const id of discharges) {
      if (!ALL_IDS.includes(id)) problems.push(`${where}: unknown requirement or threat ${id}`);
    }

    const tests = Array.isArray(row.tests)
      ? row.tests.filter((t) => typeof t === 'string' && t.trim())
      : [];
    if (tests.length === 0) problems.push(`${where}: no linked test`);
    if (row.status === 'done') {
      for (const t of tests)
        if (!fileExists(t)) problems.push(`${where}: done, but test file ${t} does not exist`);
    }

    if (row.role !== 'supporting-infrastructure' && tests.length > 0) {
      for (const id of discharges) covered.add(id);
    }
  });

  for (const id of ALL_IDS) {
    if (!covered.has(id)) {
      const kind = id.startsWith('R') ? 'requirement' : 'threat';
      problems.push(`${id}: ${kind} has no linked test`);
    }
  }
  return problems;
}

/** Task IDs as prompt.md writes them in its headings, e.g. "1 · P0-UDK-1 — ...". */
export function taskIdsFromPrompt(promptText) {
  return new Set(promptText.match(/\bP\d-[A-Z]{3}-\d+\b/g) ?? []);
}

function main() {
  const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
  const rows = parse(readFileSync(resolve(root, 'traceability.yaml'), 'utf8'));
  const taskIds = taskIdsFromPrompt(readFileSync(resolve(root, 'prompt.md'), 'utf8'));
  const problems = checkTraceability(rows, {
    taskIds,
    fileExists: (p) => existsSync(resolve(root, p)),
  });
  if (problems.length > 0) {
    console.error(`traceability check failed (${problems.length}):`);
    for (const p of problems) console.error(`  - ${p}`);
    process.exit(1);
  }
  console.log(
    `traceability check passed: ${ALL_IDS.length} requirements and threats linked across ${rows.length} tasks`,
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
