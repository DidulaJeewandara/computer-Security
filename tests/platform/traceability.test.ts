// [JDH] P0-JDH-1: the traceability check fails, and names the gap, when a requirement is unlinked
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import {
  checkTraceability,
  REQUIREMENTS,
  taskIdsFromPrompt,
  THREATS,
} from '../../scripts/check-traceability.mjs';

type Row = { task: string; status: string; discharges: string[]; role?: string; tests: string[] };

const realRows = (): Row[] => parse(readFileSync('traceability.yaml', 'utf8'));
const taskIds = taskIdsFromPrompt(readFileSync('prompt.md', 'utf8'));

const fullRow: Row = {
  task: 'P0-JDH-1',
  status: 'open',
  discharges: [...REQUIREMENTS, ...THREATS],
  tests: ['a.test.ts'],
};

describe('checkTraceability', () => {
  it('passes on the committed traceability.yaml', () => {
    expect(checkTraceability(realRows(), { taskIds })).toEqual([]);
  });

  it('fails and names the requirement when one requirement is deliberately unlinked', () => {
    const rows = realRows().map((r) => ({
      ...r,
      discharges: r.discharges.filter((id) => id !== 'R7'),
    }));
    expect(checkTraceability(rows, { taskIds })).toEqual(['R7: requirement has no linked test']);
  });

  it('names a threat with no linked test', () => {
    const rows = [{ ...fullRow, discharges: fullRow.discharges.filter((id) => id !== 'T5') }];
    expect(checkTraceability(rows)).toContain('T5: threat has no linked test');
  });

  it('does not count supporting-infrastructure rows as coverage', () => {
    const problems = checkTraceability([{ ...fullRow, role: 'supporting-infrastructure' }]);
    expect(problems).toHaveLength(REQUIREMENTS.length + THREATS.length);
  });

  it('fails a row with no linked test, and does not count its claims', () => {
    const problems = checkTraceability([{ ...fullRow, tests: [] }]);
    expect(problems).toContain('P0-JDH-1: no linked test');
    expect(problems).toContain('R1: requirement has no linked test');
  });

  it('fails a row with no task ID', () => {
    const noTask: Partial<Row> = { ...fullRow };
    delete noTask.task;
    expect(checkTraceability([noTask])).toContain('row 1: no linked task ID');
  });

  it('fails a task ID that is not in prompt.md', () => {
    expect(checkTraceability([{ ...fullRow, task: 'P9-XYZ-9' }], { taskIds })).toContain(
      'P9-XYZ-9: task ID not found in prompt.md',
    );
  });

  it('fails a done row whose test file does not exist, but allows it on an open row', () => {
    const missing = () => false;
    expect(checkTraceability([{ ...fullRow, status: 'done' }], { fileExists: missing })).toContain(
      'P0-JDH-1: done, but test file a.test.ts does not exist',
    );
    expect(checkTraceability([fullRow], { fileExists: missing })).toEqual([]);
  });

  it('rejects an unknown status, an unknown ID and a duplicated task', () => {
    const problems = checkTraceability([
      { ...fullRow, status: 'maybe' },
      { ...fullRow, discharges: ['R11'] },
    ]);
    expect(problems).toContain('P0-JDH-1: status must be open or done');
    expect(problems).toContain('P0-JDH-1: unknown requirement or threat R11');
    expect(problems).toContain('P0-JDH-1: listed more than once');
  });
});

describe('pnpm trace:check', () => {
  it('exits 0 on the committed matrix', () => {
    const out = execFileSync(process.execPath, ['scripts/check-traceability.mjs'], {
      encoding: 'utf8',
    });
    expect(out).toContain('traceability check passed');
  });
});
