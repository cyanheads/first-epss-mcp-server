/**
 * @fileoverview Date and pasted-CVE input compatibility and bounded parsing.
 * @module tests/services/epss/input-contracts.test
 */
import { z } from '@cyanheads/mcp-ts-core';
import { describe, expect, it } from 'vitest';
import { cvesSchema, dateSchema } from '@/mcp-server/tools/schemas.js';
import { normalizeCve } from '@/services/epss/normalization.js';

describe('date input compatibility', () => {
  it('advertises the linear blank-or-date pattern', () => {
    expect(z.toJSONSchema(dateSchema).pattern).toBe('^\\s*(?:\\d{4}-\\d{2}-\\d{2}\\s*)?$');
  });
  it.each(['', ' ', '\t\n', '\u2003', '\u00a0', '2024-02-29', '\u2003 2024-02-29\n'])(
    'preserves accepted date %j',
    (value) => {
      expect(dateSchema.parse(value)).toBe(value);
    },
  );
  it.each(['2024-02-30', '2021-04-13', 'bad'])('rejects invalid date %j', (value) => {
    expect(dateSchema.safeParse(value).success).toBe(false);
  });
});

describe('pasted CVE compatibility', () => {
  it.each([
    '\u2010',
    '\u2011',
    '\u2012',
    '\u2013',
    '\u2014',
    '\u2015',
    '\u2212',
    '\uFE63',
    '\uFF0D',
  ])('canonicalizes dash %s', (dash) => {
    expect(normalizeCve(` cve${dash}2026${dash}1000 `)).toBe('CVE-2026-1000');
  });
  it.each([' ', '\t', '\n', '\r\n', ',', ';', '\u2003'])('splits delimiter %j', (separator) => {
    expect(cvesSchema.parse(`CVE-2026-1000${separator}CVE-2026-1001`)).toEqual([
      'CVE-2026-1000',
      'CVE-2026-1001',
    ]);
  });
});

describe('linear caller-text parsing', () => {
  it.each([' ', '\n', ' \n', '[', '[[', 'CVE−', 'CVE-CVE-'])(
    'bounds CPU over repeated prefix %j',
    (prefix) => {
      const pattern = new RegExp(z.toJSONSchema(dateSchema).pattern!);
      const samples: number[] = [];
      for (const size of [5000, 20000, 80000, 320000]) {
        const value = `${prefix.repeat(Math.ceil(size / prefix.length)).slice(0, size)}\n!`;
        const start = process.threadCpuUsage();
        for (let i = 0; i < 100; i++) {
          expect(pattern.test(value)).toBe(false);
          expect(normalizeCve(value)).toContain('!');
        }
        const cpu = process.threadCpuUsage(start);
        const micros = cpu.user + cpu.system;
        expect(micros).toBeLessThan(2_000_000);
        samples.push(micros);
      }
      expect(samples[3]! / Math.max(samples[0]!, 1000)).toBeLessThan(256);
    },
    15000,
  );
});
