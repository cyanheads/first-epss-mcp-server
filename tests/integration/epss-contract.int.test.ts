/**
 * @fileoverview Caller contracts through real EPSS handlers, policies and HTTP parsing.
 * @module tests/integration/epss-contract.int.test
 */
import type { z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  epssGetScores,
  epssGetTimeseries,
  epssListReference,
  epssPrioritizeCves,
  epssQueryThreshold,
} from '@/mcp-server/tools/definitions/index.js';
import { accountingText } from '@/mcp-server/tools/format.js';
import { measuredSurfaces, serializedBytes } from '@/mcp-server/tools/response-budget.js';
import { disposeEpssService, initEpssService, shiftDate } from '@/services/epss/index.js';

const dns = vi.hoisted(() => ({
  lookup: vi.fn(async () => [{ address: '93.184.216.34', family: 4 }]),
  resolve4: vi.fn(async () => ['93.184.216.34']),
  resolve6: vi.fn(async () => []),
}));
vi.mock('node:dns/promises', () => dns);

const date = '2026-10-18';
const realNow = Date.now.bind(Date);
const cve = (n: number) => `CVE-2026-${1000 + n}`;
const ids = (n: number) => Array.from({ length: n }, (_, i) => cve(i));
const row = (id = cve(0), extra: Record<string, unknown> = {}) => ({
  cve: id,
  epss: '0.1',
  percentile: '0.9',
  date,
  ...extra,
});
let calls: URL[];
let api: (url: URL) => Response;
function envelope(url: URL, data: unknown[], total = data.length) {
  return Response.json({
    status: 'OK',
    'status-code': 200,
    total,
    data,
    limit: Number(url.searchParams.get('limit')),
    offset: Number(url.searchParams.get('offset') ?? 0),
  });
}
type Result = Awaited<ReturnType<typeof runToolContract>>;
function text(result: Result) {
  return result.content.flatMap((block) => (block.type === 'text' ? [block.text] : [])).join('\n');
}
function success<T>(result: Result, schema: z.ZodType<T>): T {
  expect(result.isError, text(result)).not.toBe(true);
  return schema.parse(result.structuredContent);
}
function scoreParity(
  value: {
    cve: string;
    epss: number;
    percentile: number;
    date: string;
    modelVersion?: string | undefined;
    modelVersionSource: string;
  },
  rendered: string,
) {
  expect(rendered).toContain(
    `| ${value.cve} | ${value.epss} | ${value.percentile} | ${value.date} | ${value.modelVersion ?? 'unavailable'} | ${value.modelVersionSource} |`,
  );
}
function provenanceParity(
  value: z.infer<typeof epssGetScores.output>['provenance'],
  rendered: string,
) {
  expect(rendered).toContain(`Source: ${value.source}`);
  expect(rendered).toContain(`API URL: ${value.apiUrl}`);
  expect(rendered).toContain(`Retrieved at: ${value.retrievedAt}`);
  expect(rendered).toContain(`Requested date: ${value.requestedDate ?? 'latest available'}`);
  expect(rendered).toContain(`Score dates: ${value.scoreDates.join(', ') || 'none'}`);
  const m = value.modelMetadata;
  expect(rendered).toContain(`Model metadata status: ${m.status}`);
  expect(rendered).toContain(`Model metadata source URL: ${m.sourceUrl ?? 'unavailable'}`);
  expect(rendered).toContain(`Model metadata score date: ${m.scoreDate ?? 'unavailable'}`);
  expect(rendered).toContain(`Model metadata version: ${m.modelVersion ?? 'unavailable'}`);
  expect(rendered).toContain(`Model metadata explanation: ${m.explanation ?? 'none'}`);
}
function errorParity(result: Result, code: number, reason?: string, hint?: string) {
  expect(result.isError).toBe(true);
  expect(result.structuredContent).toMatchObject({
    error: { code, ...(reason ? { data: { reason } } : {}) },
  });
  if (reason) expect(text(result)).toContain(reason);
  if (hint) {
    expect(result.structuredContent).toMatchObject({ error: { data: { recovery: { hint } } } });
    expect(text(result)).toContain(hint);
  }
}
beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(new Date(`${date}T15:00:00Z`));
  vi.spyOn(Date, 'now').mockImplementation(realNow);
  calls = [];
  api = (url) =>
    envelope(
      url,
      (url.searchParams.get('cve') ?? '')
        .split(',')
        .filter(Boolean)
        .map((id) => row(id)),
    );
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.href === 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz') {
        return new Response(
          `#model_version:v2026.06.15,score_date:${date}T12:00:00Z\ncve,epss,percentile\n`,
        );
      }
      if (url.origin !== 'https://api.first.org' || url.pathname !== '/data/v1/epss')
        throw new Error(`Unexpected URL ${url}`);
      calls.push(url);
      return api(url);
    }),
  );
  initEpssService();
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.useRealTimers();
});
afterAll(() => disposeEpssService());

function batchBudgetTests() {
  it('characterizes normalized first-occurrence order and processed invalid entries', async () => {
    const result = await runToolContract(epssGetScores, {
      cves: ['invalid', cve(2), cve(1), cve(2)],
      date,
    });
    const value = success(result, epssGetScores.output);
    expect(value.processedCount).toBe(3);
    expect(value.duplicateCount).toBe(1);
    expect(value.unscoredCves).toHaveLength(1);
    expect(value.unscoredCves[0]?.cve).toBe('INVALID');
    expect(value.scores.map((score) => score.cve)).toEqual([cve(1), cve(2)]);
  });

  it('bounds accounting dominated escaped identifiers on both assembled surfaces', async () => {
    const cves = Array.from({ length: 5000 }, (_, i) => `${i}\\\\|"${'X'.repeat(110)}`);
    const result = await runToolContract(epssGetScores, { cves, date });
    success(result, epssGetScores.output);
    expect(Buffer.byteLength(JSON.stringify(result.content))).toBeLessThanOrEqual(65536);
    expect(Buffer.byteLength(JSON.stringify(result.structuredContent))).toBeLessThanOrEqual(65536);
  });

  it('bounds fifty complete histories on both assembled surfaces', async () => {
    api = (url) =>
      envelope(
        url,
        (url.searchParams.get('cve') ?? '').split(',').map((id) =>
          row(id, {
            'time-series': Array.from({ length: 30 }, (_, i) => ({
              epss: '0.1',
              percentile: '0.9',
              date: shiftDate(date, -i - 1),
            })),
          }),
        ),
      );
    const result = await runToolContract(epssGetTimeseries, { cves: ids(50), date });
    success(result, epssGetTimeseries.output);
    expect(Buffer.byteLength(JSON.stringify(result.content))).toBeLessThanOrEqual(65536);
    expect(Buffer.byteLength(JSON.stringify(result.structuredContent))).toBeLessThanOrEqual(65536);
  });

  it.each([false, true])(
    'continues prioritization without loss, severity supplied=%s',
    async (withSeverity) => {
      const cves = [
        ...ids(501)
          .reverse()
          .map((id) => ({ cve: id, ...(withSeverity ? { cvssBaseScore: 8 } : {}) })),
        { cve: 'invalid' },
        { cve: cve(500), ...(withSeverity ? { cvssBaseScore: 8 } : {}) },
      ];
      const seen: string[] = [];
      let batchOffset = 0;
      let snapshot: string | undefined;
      for (let page = 0; page < 5; page++) {
        const result = await runToolContract(epssPrioritizeCves, {
          cves,
          batchOffset,
          date: snapshot,
          severityThreshold: 9,
          likelihood: { metric: 'percentile', threshold: 0.8 },
        });
        const value = success(result, epssPrioritizeCves.output);
        expect(serializedBytes(result.content)).toBeLessThanOrEqual(65536);
        expect(serializedBytes(result.structuredContent)).toBeLessThanOrEqual(65536);
        const rows = [
          ...Object.values(value.tiers).flat(),
          ...value.epssOnly,
          ...value.unscoredCves,
        ];
        expect(rows.length).toBeGreaterThan(0);
        expect(rows).toHaveLength(value.returnedCount!);
        expect(value.thresholds).toEqual({
          severityThreshold: 9,
          likelihood: { metric: 'percentile', threshold: 0.8 },
        });
        expect(text(result)).toContain('likelihood metric: percentile');
        const expected = [...new Set(cves.map((entry) => entry.cve.toUpperCase()))].slice(
          batchOffset,
          batchOffset + value.returnedCount!,
        );
        expect(new Set(rows.map((entry) => entry.cve))).toEqual(new Set(expected));
        for (const row of rows) {
          if ('cvssBaseScore' in row) expect(row.cvssBaseScore).toBe(8);
          seen.push(row.cve);
        }
        snapshot ??= value.provenance.scoreDates[0];
        if (batchOffset > 0) expect(calls.at(-1)?.searchParams.get('date')).toBe(date);
        if (value.nextBatchOffset === undefined) break;
        expect(value.nextBatchOffset).toBeGreaterThan(batchOffset);
        expect(value.nextBatchOffset).toBe(batchOffset + value.returnedCount!);
        expect(text(result)).toContain(`batchOffset=${value.nextBatchOffset}`);
        batchOffset = value.nextBatchOffset;
      }
      expect(seen).toHaveLength(502);
      expect(new Set(seen).size).toBe(502);
    },
  );

  it('advances invalid entries and normalized duplicates through the same original batch', async () => {
    const cves = Array.from({ length: 5000 }, (_, i) => `${i}\\\\|"${'X'.repeat(110)}`);
    cves[1] = cves[0]!;
    let batchOffset = 0;
    const seen: string[] = [];
    for (let page = 0; page < 30; page++) {
      const result = await runToolContract(epssGetScores, { cves, date, batchOffset });
      const value = success(result, epssGetScores.output);
      expect(value.unscoredCves.length).toBeGreaterThan(0);
      expect(value.duplicateCount).toBe(1);
      expect(value.unscoredCves.map((entry) => entry.cve)).toEqual(
        [...new Set(cves)].slice(batchOffset, batchOffset + value.returnedCount!),
      );
      expect(value.deferredCvesComplete).toBe(value.deferredCves.length === value.deferredCount);
      expect(value.withheldCvesComplete).toBe(value.withheldCves!.length === value.withheldCount);
      expect(value.returnedCount! + value.withheldCount!).toBe(value.processedCount);
      expect(serializedBytes(result.content)).toBeLessThanOrEqual(65536);
      expect(serializedBytes(result.structuredContent)).toBeLessThanOrEqual(65536);
      seen.push(...value.unscoredCves.map((entry) => entry.cve));
      if (value.nextBatchOffset === undefined) break;
      expect(value.nextBatchOffset).toBeGreaterThan(batchOffset);
      batchOffset = value.nextBatchOffset;
    }
    expect(seen).toEqual([...new Set(cves)]);
    expect(calls).toHaveLength(0);
  });

  it('matches the actual enriched framework surfaces including escaping', async () => {
    const result = await runToolContract(epssGetScores, { cves: ['bad\\|"id'], date });
    const domain = success(result, epssGetScores.output);
    const expected = measuredSurfaces(
      domain,
      epssGetScores.format!(domain),
      (result.structuredContent as Record<string, unknown>).notice as string,
    );
    expect(result.content).toEqual(expected.content);
    expect(result.structuredContent).toEqual(expected.structuredContent);
    expect(serializedBytes(result.content)).toBe(Buffer.byteLength(JSON.stringify(result.content)));
  });

  it('continues full histories in original input order without clipping observations', async () => {
    api = (url) =>
      envelope(
        url,
        (url.searchParams.get('cve') ?? '').split(',').map((id) =>
          row(id, {
            'time-series': Array.from({ length: 30 }, (_, i) => ({
              epss: '0.1',
              percentile: '0.9',
              date: shiftDate(date, -i - 1),
            })),
          }),
        ),
      );
    const cves = ids(50).reverse();
    const seen: string[] = [];
    let batchOffset = 0;
    for (let page = 0; page < 5; page++) {
      const result = await runToolContract(epssGetTimeseries, { cves, date, batchOffset });
      const value = success(result, epssGetTimeseries.output);
      expect(value.items.length).toBeGreaterThan(0);
      expect(new Set(value.items.map((item) => item.current.cve))).toEqual(
        new Set(cves.slice(batchOffset, batchOffset + value.returnedCount!)),
      );
      for (const item of value.items) {
        expect(item.series).toHaveLength(30);
        expect(item.series[0]?.date).toBe(shiftDate(date, -30));
        expect(item.series.at(-1)?.date).toBe(shiftDate(date, -1));
        seen.push(item.current.cve);
      }
      expect(serializedBytes(result.content)).toBeLessThanOrEqual(65536);
      expect(serializedBytes(result.structuredContent)).toBeLessThanOrEqual(65536);
      if (value.nextBatchOffset === undefined) break;
      expect(value.nextBatchOffset).toBeGreaterThan(batchOffset);
      batchOffset = value.nextBatchOffset;
    }
    expect(seen).toHaveLength(50);
    expect(new Set(seen)).toEqual(new Set(cves));
  });

  it.each([false, true])('bounds 500 score or omitted entries, omitted=%s', async (omitted) => {
    if (omitted) api = (url) => envelope(url, []);
    const result = await runToolContract(epssGetScores, { cves: ids(501), date });
    const value = success(result, epssGetScores.output);
    expect(value.processedCount).toBe(500);
    expect(value.returnedCount).toBeGreaterThan(0);
    expect(value.scores.length + value.unscoredCves.length).toBe(value.returnedCount);
    expect(value.returnedCount! + value.withheldCount!).toBe(500);
    expect(value.deferredCves).toEqual([cve(500)]);
    expect(value.deferredCvesComplete).toBe(true);
    expect(serializedBytes(result.content)).toBeLessThanOrEqual(65536);
    expect(serializedBytes(result.structuredContent)).toBeLessThanOrEqual(65536);
  });

  it.each([epssGetScores, epssGetTimeseries, epssPrioritizeCves])(
    'returns explicit empty past-end and rejects invalid offsets for $name',
    async (definition) => {
      const cves =
        definition.name === 'epss_prioritize_cves' ? [{ cve: cve(0), cvssBaseScore: 5 }] : [cve(0)];
      const result = await runToolContract(definition, { cves, batchOffset: 100, date });
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject({
        batchOffset: 100,
        requestedCount: 1,
        processedCount: 0,
        returnedCount: 0,
        withheldCount: 0,
        deferredCount: 0,
        deferredCvesComplete: true,
        withheldCvesComplete: true,
      });
      expect(result.structuredContent).not.toHaveProperty('nextBatchOffset');
      expect(text(result)).toContain('Batch offset: 100; returned count: 0');
      expect(calls).toHaveLength(0);
      for (const batchOffset of [-1, 0.5, Number.MAX_SAFE_INTEGER + 1]) {
        const invalid = await runToolContract(definition, { cves, batchOffset });
        errorParity(invalid, JsonRpcErrorCode.InvalidParams);
      }
    },
  );

  it('declares unavailable pinned prioritization snapshots on both error surfaces', async () => {
    api = () =>
      new Response(JSON.stringify({ 'status-code': 422, message: ['listNoResults'] }), {
        status: 422,
      });
    const result = await runToolContract(epssPrioritizeCves, {
      cves: [{ cve: cve(0), cvssBaseScore: 8 }],
      date: '2026-10-17',
    });
    errorParity(
      result,
      JsonRpcErrorCode.ValidationError,
      'snapshot_unavailable',
      'Call the same tool with another date or omit date for latest available data.',
    );
  });
}

describe('sparse history and official metadata redirect regressions', () => {
  it('verifies current model provenance through the official dated CSV redirect', async () => {
    const headerUrls: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL | Request) => {
        const url = new URL(input instanceof Request ? input.url : String(input));
        if (url.origin === 'https://api.first.org' && url.pathname === '/data/v1/epss') {
          calls.push(url);
          return api(url);
        }
        if (url.href === 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz') {
          headerUrls.push(url.href);
          return new Response(null, {
            status: 302,
            headers: { location: 'epss_scores-2026-10-18.csv.gz' },
          });
        }
        if (url.href === 'https://epss.empiricalsecurity.com/epss_scores-2026-10-18.csv.gz') {
          headerUrls.push(url.href);
          return new Response(
            '#model_version:v2026.06.15,score_date:2026-10-18T12:00:00Z\ncve,epss,percentile\n',
          );
        }
        throw new Error(`Unexpected URL ${url}`);
      }),
    );
    const result = await runToolContract(epssGetScores, { cves: [cve(0)] });
    const value = success(result, epssGetScores.output);
    expect(value.provenance.modelMetadata).toEqual({
      status: 'verified',
      sourceUrl: 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz',
      scoreDate: date,
      modelVersion: 'v2026.06.15',
    });
    expect(value.scores[0]).toMatchObject({
      modelVersion: 'v2026.06.15',
      modelVersionSource: 'csv_header',
    });
    expect(headerUrls).toEqual([
      'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz',
      'https://epss.empiricalsecurity.com/epss_scores-2026-10-18.csv.gz',
    ]);
    scoreParity(value.scores[0]!, text(result));
    provenanceParity(value.provenance, text(result));
    expect(text(result)).not.toContain('could not be verified');
  });

  it('retains the calendar window from thirty sparse preceding observations', async () => {
    const observations = Array.from({ length: 32 }, (_, i) => ({
      date: shiftDate(date, -i - 1),
      epss: (i + 1) / 100,
      percentile: 0.9,
    })).filter((score) => !['2026-10-17', '2026-09-28'].includes(score.date));
    expect(observations).toHaveLength(30);
    api = (url) => envelope(url, [row(cve(0), { epss: 0.8, 'time-series': observations })]);
    const result = await runToolContract(epssGetTimeseries, { cves: [cve(0)] });
    const value = success(result, epssGetTimeseries.output);
    const item = value.items[0]!;
    const retained = observations
      .filter((score) => score.date >= '2026-09-18')
      .sort((a, b) => a.date.localeCompare(b.date));
    expect(item.series).toHaveLength(28);
    expect(
      item.series.map(({ date: day, epss, percentile }) => ({ date: day, epss, percentile })),
    ).toEqual(retained);
    expect(item.requestedWindow).toEqual({ startDate: '2026-09-18', endDate: '2026-10-17' });
    expect(item.observedWindow).toEqual({
      startDate: '2026-09-18',
      endDate: '2026-10-16',
      observationCount: 28,
    });
    expect(item.missingDates).toEqual(['2026-09-28', '2026-10-17']);
    expect(item.delta7d).toBe(0.8 - 0.07);
    expect(item.delta30d).toBe(0.8 - 0.3);
    expect(item.unavailableDeltas).toEqual([]);
    expect(item.deltaComparisons).toEqual([
      { days: 7, baselineDate: '2026-10-11', endpointDate: date, crossesModelBoundary: false },
      { days: 30, baselineDate: '2026-09-18', endpointDate: date, crossesModelBoundary: false },
    ]);
    const rendered = text(result);
    for (const score of [item.current, ...item.series]) scoreParity(score, rendered);
    expect(rendered).not.toContain('2026-09-16');
    expect(rendered).not.toContain('| 2026-09-17 |');
    expect(rendered).toContain('Missing dates: 2026-09-28, 2026-10-17');
    expect(rendered).toContain('observation count: 28');
    expect(rendered).toContain(`delta7d: ${item.delta7d}; delta30d: ${item.delta30d}`);
    provenanceParity(value.provenance, rendered);
  });
});

describe('batch response byte budget', batchBudgetTests);

describe('threshold response byte budget', () => {
  it('describes an empty deferred preview without calling unqueried entries absent', () => {
    const rendered = accountingText(
      {
        requestedCount: 2,
        processedCount: 1,
        duplicateCount: 0,
        unscoredCves: [],
        deferredCves: [],
        deferredCount: 1,
        deferredCvesComplete: false,
        batchOffset: 0,
        nextBatchOffset: 1,
      },
      'epss_get_scores',
    );
    expect(rendered).toContain(
      '## Deferred CVEs\nPreview omitted; 1 deferred identifiers have not been queried.',
    );
    expect(rendered).not.toContain('original severity inputs');
  });
  it('bounds complete enriched surfaces for 10000 candidates', async () => {
    const candidates = ids(10000).map((id) => row(id, { date: '2026-10-17' }));
    api = (url) => envelope(url, candidates);
    const result = await runToolContract(epssQueryThreshold, { minEpss: 0, limit: 10000 });
    const value = success(result, epssQueryThreshold.output);
    expect(value.scores.length).toBeGreaterThan(0);
    expect(serializedBytes(result.content)).toBeLessThanOrEqual(65536);
    expect(serializedBytes(result.structuredContent)).toBeLessThanOrEqual(65536);
    expect(value.pagination.examinedCount).toBe(10000);
    expect(value.pagination.returnedCount).toBeLessThan(10000);
    expect(value.pagination).toMatchObject({
      budgetLimited: true,
      withheldCount: 10000 - value.scores.length,
      nextOffset: value.scores.length,
    });
    expect(result.structuredContent).not.toHaveProperty('matchOffsets');
    const notice = (result.structuredContent as Record<string, unknown>).notice as string;
    expect(notice).toContain('Response byte budget reached');
    expect(notice).toContain('The current CSV header does not verify the returned score date.');
    expect(measuredSurfaces(value, epssQueryThreshold.format!(value), notice)).toEqual({
      content: result.content,
      structuredContent: result.structuredContent,
    });
    expect(text(result)).toContain(`withheldCount: ${10000 - value.scores.length}`);
    expect(calls).toHaveLength(1);
  });
  it.each([false, true])(
    'recovers every match across capped candidate re-slices (year filter=%s)',
    async (withYear) => {
      const candidates = Array.from({ length: 4000 }, (_, i) =>
        row(`CVE-${withYear && i % 3 !== 1 ? 2025 : 2026}-${10000 + i}`, {
          epss: (4000 - i) / 4000,
        }),
      );
      const expected = candidates.filter((entry) => !withYear || entry.cve.startsWith('CVE-2026-'));
      expect(expected.length).toBeGreaterThan(0);
      api = (url) => {
        const start = Number(url.searchParams.get('offset'));
        return envelope(
          url,
          candidates.slice(start, start + Number(url.searchParams.get('limit'))),
          candidates.length,
        );
      };
      const collected: string[] = [];
      let offset = 0;
      let pages = 0;
      let pinnedDate: string | undefined;
      for (; pages < 40; pages++) {
        const result = await runToolContract(epssQueryThreshold, {
          minEpss: 0,
          ...(withYear ? { year: 2026 } : {}),
          limit: 10000,
          offset,
          ...(pinnedDate ? { date: pinnedDate } : {}),
        });
        const value = success(result, epssQueryThreshold.output);
        expect(value.scores.length).toBeGreaterThan(0);
        const remaining = candidates.slice(offset);
        const matches = remaining.filter((entry) => !withYear || entry.cve.startsWith('CVE-2026-'));
        expect(value.scores.map((score) => score.cve)).toEqual(
          matches.slice(0, value.scores.length).map((entry) => entry.cve),
        );
        expect(value.pagination.examinedCount).toBe(remaining.length);
        expect(value.pagination.total).toBe(withYear ? null : candidates.length);
        expect(serializedBytes(result.content)).toBeLessThanOrEqual(65536);
        expect(serializedBytes(result.structuredContent)).toBeLessThanOrEqual(65536);
        for (const score of value.scores) scoreParity(score, text(result));
        provenanceParity(value.provenance, text(result));
        collected.push(...value.scores.map((score) => score.cve));
        pinnedDate = value.provenance.scoreDates[0];
        if (!value.pagination.hasMore) {
          expect(value.pagination.nextOffset).toBeUndefined();
          break;
        }
        const withheld = matches[value.scores.length]!;
        const expectedNext = candidates.findIndex((entry) => entry.cve === withheld.cve);
        expect(value.pagination).toMatchObject({
          budgetLimited: true,
          withheldCount: matches.length - value.scores.length,
          nextOffset: expectedNext,
        });
        expect(expectedNext).toBeGreaterThan(offset);
        offset = value.pagination.nextOffset!;
      }
      expect(pages).toBeGreaterThan(1);
      expect(pages).toBeLessThan(40);
      expect(collected).toEqual(expected.map((entry) => entry.cve));
      expect(new Set(collected).size).toBe(collected.length);
      expect(calls).toHaveLength(pages + 1);
      for (const call of calls.slice(1)) {
        expect(call.searchParams.get('date')).toBe(date);
        expect(call.searchParams.get('limit')).toBe('10000');
        expect(call.searchParams.get('epss-gt')).toBe('0');
        expect(call.searchParams.get('q')).toBe(withYear ? '2026' : null);
      }
      const past = await runToolContract(epssQueryThreshold, {
        minEpss: 0,
        ...(withYear ? { year: 2026 } : {}),
        limit: 10000,
        offset: candidates.length + 1,
        date: pinnedDate,
      });
      const value = success(past, epssQueryThreshold.output);
      expect(value.scores).toEqual([]);
      expect(value.pagination).toMatchObject({
        examinedCount: 0,
        returnedCount: 0,
        hasMore: false,
      });
      expect(value.pagination.nextOffset).toBeUndefined();
      expect(text(past)).toContain('No scored records.');
      expect(serializedBytes(past.content)).toBeLessThanOrEqual(65536);
      expect(serializedBytes(past.structuredContent)).toBeLessThanOrEqual(65536);
    },
    30000,
  );
  it('characterizes original candidate order and examined counts before exact-year filtering', async () => {
    api = (url) => envelope(url, [row('CVE-2025-1000'), row(cve(2)), row(cve(1))], 4);
    const result = await runToolContract(epssQueryThreshold, { year: 2026 });
    const value = success(result, epssQueryThreshold.output);
    expect(value.scores.map((score) => score.cve)).toEqual([cve(2), cve(1)]);
    expect(value.pagination).toMatchObject({ examinedCount: 3, returnedCount: 2, nextOffset: 3 });
    expect(value.filters).toMatchObject({ year: 2026, limit: 100, offset: 0 });
    for (const score of value.scores) scoreParity(score, text(result));
    provenanceParity(value.provenance, text(result));
    expect(calls).toHaveLength(1);
  });
});

describe('score lookup caller contract', () => {
  it('normalizes comma/newline input, deduplicates and distinguishes zero, invalid and absent', async () => {
    api = (url) => envelope(url, [row(cve(0), { epss: 0, percentile: 0 })]);
    const result = await runToolContract(epssGetScores, {
      cves: ` cve-2026-1000 ,\n${cve(0)},bad\\|id,${cve(1)}`,
      date: '  ',
    });
    const value = success(result, epssGetScores.output);
    expect(value).toMatchObject({
      requestedCount: 3,
      processedCount: 3,
      duplicateCount: 1,
      deferredCves: [],
      scores: [{ cve: cve(0), epss: 0, percentile: 0 }],
      unscoredCves: [
        { cve: 'BAD\\|ID', reason: 'invalid_format' },
        { cve: cve(1), reason: 'not_returned' },
      ],
    });
    expect(calls[0]?.searchParams.get('cve')).toBe(`${cve(0)},${cve(1)}`);
    expect(calls[0]?.searchParams.has('date')).toBe(false);
    const rendered = text(result);
    scoreParity(value.scores[0]!, rendered);
    provenanceParity(value.provenance, rendered);
    expect(rendered).toContain('Requested count: 3; processed count: 3; duplicate count: 1');
    expect(rendered).toContain('BAD\\\\\\|ID: invalid_format');
    for (const missing of value.unscoredCves) expect(rendered).toContain(missing.guidance);
  });
  it('sorts equal probability by CVE and preserves explicit historical provenance', async () => {
    api = (url) =>
      envelope(url, [
        row(cve(2), { date: '2025-01-01' }),
        row(cve(1), { date: '2025-01-01', epss: 0.8 }),
        row(cve(0), { date: '2025-01-01' }),
      ]);
    const result = await runToolContract(epssGetScores, { cves: ids(3), date: ' 2025-01-01 ' });
    const value = success(result, epssGetScores.output);
    expect(value.scores.map((score) => score.cve)).toEqual([cve(1), cve(0), cve(2)]);
    expect(value.provenance.requestedDate).toBe('2025-01-01');
    for (const score of value.scores) scoreParity(score, text(result));
    provenanceParity(value.provenance, text(result));
  });
  it.each([
    { tool: epssGetScores, cap: 500 },
    { tool: epssGetTimeseries, cap: 50 },
  ])(
    'accounts for $tool.name cap with each deferred ID once and its next call',
    async ({ tool, cap }) => {
      const result = await runToolContract(tool, { cves: ids(cap + 2) });
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject({
        requestedCount: cap + 2,
        processedCount: cap,
        duplicateCount: 0,
        deferredCves: ids(cap + 2).slice(cap),
        deferredCvesComplete: true,
      });
      for (const id of ids(cap + 2).slice(cap)) {
        expect(text(result).split(id)).toHaveLength(2);
        expect(calls.some((url) => url.searchParams.get('cve')?.split(',').includes(id))).toBe(
          false,
        );
      }
      expect(text(result)).toContain(`Call ${tool.name} with the original cves`);
      expect(result.structuredContent).toHaveProperty('notice');
      expect(text(result)).toContain('Some CVEs were deferred');
    },
  );
  it('keeps invalid-only lookup empty with an actionable caveat and no I/O', async () => {
    const result = await runToolContract(epssGetScores, { cves: ['bad'] });
    const value = success(result, epssGetScores.output);
    expect(value.scores).toEqual([]);
    expect(value.unscoredCves).toMatchObject([{ reason: 'invalid_format' }]);
    expect(text(result)).toContain('No scored records.');
    expect(text(result)).toContain('No requested CVEs');
    const notice =
      "No requested CVEs were returned by EPSS. Call epss_list_reference with topic='coverage' before interpreting the missing scores.";
    expect(result.structuredContent).toMatchObject({ notice });
    expect(text(result)).toContain(notice);
    expect(calls).toEqual([]);
  });
  it('accepts framework-repaired numeric scalar CVEs as explicitly invalid identifiers', async () => {
    const result = await runToolContract(epssGetScores, { cves: 4 });
    const value = success(result, epssGetScores.output);
    expect(value.unscoredCves).toMatchObject([{ cve: '4', reason: 'invalid_format' }]);
    expect(value.requestedCount).toBe(1);
    expect(text(result)).toContain('4: invalid_format');
    expect(calls).toEqual([]);
  });
});

describe('inclusive prioritization policy', () => {
  it('canonicalizes Unicode dash duplicates before conflicting severity checks', async () => {
    const result = await runToolContract(epssPrioritizeCves, {
      cves: [
        { cve: cve(0), cvssBaseScore: 7 },
        { cve: cve(0).replaceAll('-', '−'), cvssBaseScore: 8 },
      ],
    });
    expect(result.structuredContent).toMatchObject({
      error: { data: { reason: 'conflicting_cvss' } },
    });
    expect(calls).toEqual([]);
  });
  it('names prioritization and retains severity and policy in missing-score recovery', async () => {
    api = (url) => envelope(url, []);
    const result = await runToolContract(epssPrioritizeCves, {
      cves: [{ cve: cve(0), cvssBaseScore: 8 }],
      severityThreshold: 6,
      likelihood: { metric: 'percentile', threshold: 0.8 },
    });
    const missing = success(result, epssPrioritizeCves.output).unscoredCves[0]!;
    expect(missing.guidance).toContain('epss_prioritize_cves');
    expect(missing.guidance).toContain('cvssBaseScore');
    expect(missing.guidance).toContain('likelihood');
    expect(text(result)).toContain(missing.guidance);
  });
  it('classifies every cell, equality, missing/zero severity and deterministic ties', async () => {
    const probabilities = [0.1, 0.099, 0.1, 0.099, 0.8, 0.1, 0.1, 0.1];
    api = (url) =>
      envelope(
        url,
        probabilities.map((epss, i) => row(cve(i), { epss, percentile: 0.99 })),
      );
    const severities = [7, 7, 0, 6.9, undefined, 8, 8, 7];
    const result = await runToolContract(epssPrioritizeCves, {
      cves: severities.map((cvssBaseScore, i) => ({
        cve: cve(i),
        ...(cvssBaseScore === undefined ? {} : { cvssBaseScore }),
      })),
    });
    const value = success(result, epssPrioritizeCves.output);
    expect(value.thresholds).toEqual({
      severityThreshold: 7,
      likelihood: { metric: 'epss', threshold: 0.1 },
    });
    expect(
      Object.fromEntries(
        Object.entries(value.tiers).map(([tier, rows]) => [tier, rows.map((score) => score.cve)]),
      ),
    ).toEqual({
      act_now: [cve(5), cve(6), cve(0), cve(7)],
      scheduled: [cve(1)],
      monitor: [cve(2)],
      defer: [cve(3)],
    });
    expect(value.epssOnly).toMatchObject([{ cve: cve(4), highLikelihood: true }]);
    const rendered = text(result);
    for (const [tier, rows] of Object.entries(value.tiers)) {
      expect(rendered).toContain(`## ${tier}`);
      for (const score of rows) {
        expect(score.highSeverity).toBe(score.cvssBaseScore >= 7);
        expect(score.highLikelihood).toBe(score.epss >= 0.1);
        scoreParity(score, rendered);
        expect(rendered).toContain(
          `${score.cve}: CVSS base score: ${score.cvssBaseScore}; highSeverity: ${score.highSeverity}; highLikelihood: ${score.highLikelihood}`,
        );
      }
    }
    for (const score of value.epssOnly) {
      scoreParity(score, rendered);
      expect(rendered).toContain(score.guidance);
    }
    provenanceParity(value.provenance, rendered);
    expect(rendered).toContain('likelihood metric: epss; likelihood threshold: 0.1');
  });
  it('uses percentile only when explicitly selected and preserves omitted score severity', async () => {
    api = (url) => envelope(url, [row(cve(0), { epss: 0.01, percentile: 0.95 })]);
    const result = await runToolContract(epssPrioritizeCves, {
      cves: [
        { cve: cve(0), cvssBaseScore: 10 },
        { cve: cve(1), cvssBaseScore: 0 },
      ],
      likelihood: { metric: 'percentile', threshold: 0.95 },
    });
    const value = success(result, epssPrioritizeCves.output);
    expect(value.tiers.act_now).toMatchObject([{ cve: cve(0), epss: 0.01, highLikelihood: true }]);
    expect(value.unscoredCves).toMatchObject([
      { cve: cve(1), reason: 'not_returned', cvssBaseScore: 0 },
    ]);
    expect(text(result)).toContain('likelihood metric: percentile; likelihood threshold: 0.95');
    expect(text(result)).toContain(`${cve(1)}: not_returned; CVSS base score: 0`);
    expect(text(result)).toContain(value.unscoredCves[0]!.guidance);
    scoreParity(value.tiers.act_now[0]!, text(result));
  });
  it.each(
    [
      [7, 8],
      [undefined, 0],
      [0, undefined],
    ].map((scores) => ({ scores })),
  )('rejects canonical duplicate conflict $scores before I/O', async ({ scores }) => {
    const result = await runToolContract(epssPrioritizeCves, {
      cves: scores.map((score, i) => ({
        cve: i ? ` ${cve(0).toLowerCase()} ` : cve(0),
        ...(score === undefined ? {} : { cvssBaseScore: score }),
      })),
    });
    errorParity(
      result,
      JsonRpcErrorCode.ValidationError,
      'conflicting_cvss',
      epssPrioritizeCves.errors![0]!.recovery,
    );
    expect(calls).toEqual([]);
  });
  it('deduplicates identical zero severity and defers above its work cap', async () => {
    const result = await runToolContract(epssPrioritizeCves, {
      cves: [
        ...ids(501).map((id) => ({ cve: id, cvssBaseScore: 0 })),
        { cve: cve(0), cvssBaseScore: 0 },
      ],
    });
    const value = success(result, epssPrioritizeCves.output);
    expect(value).toMatchObject({
      requestedCount: 501,
      processedCount: 500,
      duplicateCount: 1,
      deferredCves: [cve(500)],
    });
    expect(value.tiers.monitor.length).toBeGreaterThan(0);
    expect(value.tiers.monitor).toHaveLength(value.returnedCount!);
    expect(value.returnedCount! + value.withheldCount!).toBe(500);
    expect(text(result).split(cve(500))).toHaveLength(2);
    expect(text(result)).toContain('Call epss_prioritize_cves with the original cves');
  });
});

describe('exact-date history policy', () => {
  it.each(['2021-04-14', '2021-05-14', '2021-05-15'])(
    'bounds preceding anchors at FIRST coverage: %s',
    async (anchor) => {
      api = (url) => envelope(url, [row(cve(0), { date: anchor })]);
      const result = await runToolContract(epssGetTimeseries, { cves: [cve(0)], date: anchor });
      const item = success(result, epssGetTimeseries.output).items[0]!;
      if (anchor === '2021-05-15') {
        expect(item.previousAnchorDate).toBe('2021-04-14');
        expect(text(result)).toContain('Previous anchor date: 2021-04-14');
      } else {
        expect(item.previousAnchorDate).toBeUndefined();
        expect(text(result)).not.toContain('Previous anchor date:');
      }
      expect(item.current.date).toBe(anchor);
      expect(calls).toHaveLength(1);
    },
  );
  it('continues into the adjacent older window without overlap or gaps', async () => {
    api = (url) => envelope(url, [row(cve(0), { date: url.searchParams.get('date') ?? date })]);
    const first = await runToolContract(epssGetTimeseries, { cves: [cve(0)] });
    const one = success(first, epssGetTimeseries.output).items[0]!;
    const second = await runToolContract(epssGetTimeseries, {
      cves: [cve(0)],
      date: one.previousAnchorDate,
    });
    const two = success(second, epssGetTimeseries.output).items[0]!;
    expect(shiftDate(two.current.date, 1)).toBe(one.requestedWindow.startDate);
    expect(two.requestedWindow.endDate).toBe(shiftDate(two.current.date, -1));
    expect(calls).toHaveLength(2);
    expect(text(second)).toContain(`Previous anchor date: ${two.previousAnchorDate}`);
  });
  it('points to the preceding anchor without fetching another window', async () => {
    const result = await runToolContract(epssGetTimeseries, { cves: [cve(0)] });
    const item = success(result, epssGetTimeseries.output).items[0]!;
    expect(item).toHaveProperty('previousAnchorDate', '2026-09-17');
    expect(text(result)).toContain(`{"cves":["${cve(0)}"],"date":"2026-09-17"}`);
    expect(calls).toHaveLength(1);
  });
  it('rounds only derived deltas and attributes implicit preceding observations like explicit history', async () => {
    api = (url) =>
      envelope(url, [
        row(cve(0), {
          epss: '0.50001',
          'time-series': [{ date: '2026-09-18', epss: '0.5', percentile: '0.9' }],
        }),
      ]);
    const implicit = await runToolContract(epssGetTimeseries, { cves: [cve(0)] });
    const explicit = await runToolContract(epssGetTimeseries, { cves: [cve(0)], date });
    const one = success(implicit, epssGetTimeseries.output).items[0]!;
    const two = success(explicit, epssGetTimeseries.output).items[0]!;
    expect(one.delta30d).toBe(0.00001);
    expect(one.current.epss).toBe(0.50001);
    expect(one.current.modelVersionSource).toBe('csv_header');
    expect(one.series).toEqual(two.series);
    expect(one.series[0]?.modelVersionSource).toBe('published_schedule');
    expect(text(implicit)).toContain('delta30d: 0.00001');
    scoreParity(one.series[0]!, text(implicit));
  });
  it('retains nested observations, exact deltas, gaps, ties and a model transition', async () => {
    const anchor = '2026-06-15';
    const observations = [
      { date: '2026-06-14', epss: 0.8, percentile: 0.99 },
      { date: '2026-05-16', epss: 0.2, percentile: 0.4 },
      { date: '2026-06-08', epss: 0.3, percentile: 0.5 },
    ];
    api = (url) =>
      envelope(url, [
        row(cve(0), { date: anchor, epss: 0.8, percentile: 0.99, 'time-series': observations }),
      ]);
    const result = await runToolContract(epssGetTimeseries, { cves: [cve(0)], date: anchor });
    const value = success(result, epssGetTimeseries.output);
    const item = value.items[0]!;
    expect(item).toMatchObject({
      current: { cve: cve(0), date: anchor, epss: 0.8 },
      series: [
        { date: '2026-05-16', epss: 0.2 },
        { date: '2026-06-08', epss: 0.3 },
        { date: '2026-06-14', epss: 0.8 },
      ],
      requestedWindow: { startDate: '2026-05-16', endDate: '2026-06-14' },
      observedWindow: { startDate: '2026-05-16', endDate: '2026-06-14', observationCount: 3 },
      unavailableDeltas: [],
      deltaComparisons: [
        { days: 7, baselineDate: '2026-06-08', endpointDate: anchor, crossesModelBoundary: true },
        { days: 30, baselineDate: '2026-05-16', endpointDate: anchor, crossesModelBoundary: true },
      ],
      peak: { epss: 0.8, dates: ['2026-06-14', anchor] },
      modelBoundariesCrossed: [{ date: anchor, fromModel: 'EPSS v4', toModel: 'EPSS v5' }],
      modelBoundaryCoverageThrough: date,
    });
    expect(item.delta7d).toBe(0.8 - 0.3);
    expect(item.delta30d).toBe(0.6);
    expect(item.missingDates).toEqual(
      Array.from({ length: 30 }, (_, i) => shiftDate(anchor, i - 30)).filter(
        (day) => !observations.some((score) => score.date === day),
      ),
    );
    const rendered = text(result);
    for (const score of [item.current, ...item.series]) scoreParity(score, rendered);
    provenanceParity(value.provenance, rendered);
    expect(rendered).toContain('Requested window: 2026-05-16 through 2026-06-14');
    expect(rendered).toContain(
      'Observed window: 2026-05-16 through 2026-06-14; observation count: 3',
    );
    expect(rendered).toContain(`Missing dates: ${item.missingDates.join(', ')}`);
    expect(rendered).toContain(
      `delta7d: ${item.delta7d}; delta30d: ${item.delta30d}; unavailable deltas (days): none`,
    );
    for (const comparison of item.deltaComparisons)
      expect(rendered).toContain(
        `${comparison.days} days; baseline date: ${comparison.baselineDate}; endpoint date: ${comparison.endpointDate}; crosses model boundary: true`,
      );
    expect(rendered).toContain('Peak EPSS: 0.8; dates: 2026-06-14, 2026-06-15');
    expect(rendered).toContain('2026-06-15: EPSS v4 → EPSS v5');
    expect(rendered).toContain(`Model boundary coverage through: ${date}`);
  });
  it('never substitutes nearby dates for absent baselines and preserves an empty history', async () => {
    api = (url) =>
      envelope(url, [
        row(cve(0), { 'time-series': [{ date: '2026-10-12', epss: 0.9, percentile: 0.9 }] }),
        row(cve(1)),
      ]);
    const result = await runToolContract(epssGetTimeseries, { cves: ids(2) });
    const value = success(result, epssGetTimeseries.output);
    for (const item of value.items) {
      expect(item.delta7d).toBeUndefined();
      expect(item.delta30d).toBeUndefined();
      expect(item.unavailableDeltas).toEqual([7, 30]);
      expect(item.deltaComparisons).toEqual([]);
      expect(item.modelBoundariesCrossed).toEqual([]);
    }
    expect(value.items[0]?.peak).toEqual({ epss: 0.9, dates: ['2026-10-12'] });
    expect(value.items[1]?.series).toEqual([]);
    expect(value.items[1]?.observedWindow).toBeUndefined();
    expect(value.items[1]?.missingDates).toHaveLength(30);
    expect(text(result)).toContain('Observed window: unavailable');
    expect(text(result)).toContain(
      'delta7d: unavailable; delta30d: unavailable; unavailable deltas (days): 7, 30',
    );
  });
  it('does not mark a baseline equal to a transition as crossing it', async () => {
    api = (url) =>
      envelope(url, [
        row(cve(0), {
          date: '2026-06-22',
          'time-series': [{ date: '2026-06-15', epss: 0.1, percentile: 0.9 }],
        }),
      ]);
    const result = await runToolContract(epssGetTimeseries, { cves: [cve(0)], date: '2026-06-22' });
    const value = success(result, epssGetTimeseries.output);
    expect(value.items[0]?.deltaComparisons).toEqual([
      {
        days: 7,
        baselineDate: '2026-06-15',
        endpointDate: '2026-06-22',
        crossesModelBoundary: false,
      },
    ]);
    expect(value.items[0]?.modelBoundariesCrossed).toEqual([]);
    expect(text(result)).toContain('crosses model boundary: false');
  });
  it('orders history anchors by EPSS then CVE while preserving explicit missing items', async () => {
    api = (url) => envelope(url, [row(cve(2)), row(cve(1), { epss: 0.8 }), row(cve(0))]);
    const result = await runToolContract(epssGetTimeseries, { cves: [...ids(4), 'bad'] });
    const value = success(result, epssGetTimeseries.output);
    expect(value.items.map((item) => item.current.cve)).toEqual([cve(1), cve(0), cve(2)]);
    expect(value.unscoredCves).toMatchObject([
      { cve: cve(3), reason: 'not_returned' },
      { cve: 'BAD', reason: 'invalid_format' },
    ]);
    for (const missing of value.unscoredCves) {
      expect(text(result)).toContain(`${missing.cve}: ${missing.reason}`);
      expect(text(result)).toContain(missing.guidance);
    }
  });
});

describe('discovery candidate pagination', () => {
  it('continues after a zero-retained page and pins the second page date', async () => {
    api = (url) =>
      envelope(
        url,
        Number(url.searchParams.get('offset')) === 0
          ? [row('CVE-2025-1000'), row('CVE-2024-1000')]
          : [row('CVE-2021-1000')],
        3,
      );
    const first = await runToolContract(epssQueryThreshold, { year: 2021, limit: 2 });
    const one = success(first, epssQueryThreshold.output);
    expect(one.scores).toEqual([]);
    expect(one.pagination).toEqual({
      offset: 0,
      limit: 2,
      examinedCount: 2,
      returnedCount: 0,
      candidateTotal: 3,
      total: null,
      totalRelation: 'unknown',
      hasMore: true,
      nextOffset: 2,
    });
    expect(one.provenance.scoreDates).toEqual([date]);
    expect(text(first)).toContain(
      `Call epss_query_threshold with the same filters and limit, date=${date}, offset=2`,
    );
    expect(text(first)).toContain(
      'examinedCount: 2; returnedCount: 0; candidateTotal: 3; total: null; totalRelation: unknown; hasMore: true; nextOffset: 2',
    );
    expect(first.structuredContent).toHaveProperty('notice');
    expect(text(first)).toContain('No exact-year matches occurred');
    const second = await runToolContract(epssQueryThreshold, {
      year: 2021,
      limit: 2,
      offset: one.pagination.nextOffset,
      date: one.provenance.scoreDates[0],
    });
    const two = success(second, epssQueryThreshold.output);
    expect(two.pagination).toEqual({
      offset: 2,
      limit: 2,
      examinedCount: 1,
      returnedCount: 1,
      candidateTotal: 3,
      total: null,
      totalRelation: 'unknown',
      hasMore: false,
    });
    expect(calls[1]?.searchParams.get('date')).toBe(date);
    expect(calls[1]?.searchParams.get('offset')).toBe('2');
    scoreParity(two.scores[0]!, text(second));
    provenanceParity(two.provenance, text(second));
    expect(text(second)).toContain(
      `year: 2021; addedWithinDays: unset; date: ${date}; limit: 2; offset: 2`,
    );
  });
  it('renders exact totals and equal inclusive bounds with independent addition recency', async () => {
    api = (url) => envelope(url, [row()]);
    const result = await runToolContract(epssQueryThreshold, {
      minEpss: 0.1,
      maxEpss: 0.1,
      minPercentile: 0,
      maxPercentile: 1,
      addedWithinDays: 3,
      date,
      limit: 1,
    });
    const value = success(result, epssQueryThreshold.output);
    expect(value.pagination).toEqual({
      offset: 0,
      limit: 1,
      examinedCount: 1,
      returnedCount: 1,
      candidateTotal: 1,
      total: 1,
      totalRelation: 'exact',
      hasMore: false,
    });
    expect(Object.fromEntries(calls[0]!.searchParams)).toEqual({
      'epss-gt': '0.1',
      'epss-lt': '0.1',
      'percentile-gt': '0',
      'percentile-lt': '1',
      days: '3',
      date,
      order: '!epss',
      limit: '1',
      offset: '0',
    });
    expect(text(result)).toContain(
      'minEpss: 0.1; maxEpss: 0.1; minPercentile: 0; maxPercentile: 1',
    );
    expect(text(result)).toContain(
      `year: unset; addedWithinDays: 3; date: ${date}; limit: 1; offset: 0`,
    );
    scoreParity(value.scores[0]!, text(result));
  });
  it('accepts the maximum candidate limit and unit-interval endpoints', async () => {
    api = (url) => envelope(url, [row(cve(0), { epss: 1, percentile: 0 })]);
    const result = await runToolContract(epssQueryThreshold, {
      minEpss: 0,
      maxEpss: 1,
      minPercentile: 0,
      maxPercentile: 1,
      limit: 10000,
    });
    const value = success(result, epssQueryThreshold.output);
    expect(value.pagination.limit).toBe(10000);
    expect(value.scores[0]).toMatchObject({ epss: 1, percentile: 0 });
    scoreParity(value.scores[0]!, text(result));
    expect(text(result)).toContain('limit: 10000');
  });
  it.each([
    { total: 0, offset: 0 },
    { total: 2, offset: 9 },
  ])('keeps exhausted/empty discovery explicit: %j', async ({ total, offset }) => {
    api = (url) => envelope(url, [], total);
    const result = await runToolContract(epssQueryThreshold, { minEpss: 0, offset });
    const value = success(result, epssQueryThreshold.output);
    expect(value.scores).toEqual([]);
    expect(value.pagination).toEqual({
      offset,
      limit: 100,
      examinedCount: 0,
      returnedCount: 0,
      candidateTotal: total,
      total,
      totalRelation: 'exact',
      hasMore: false,
    });
    expect(value.provenance.scoreDates).toEqual([]);
    expect(text(result)).toContain('No scored records.');
    expect(text(result)).toContain(
      `candidateTotal: ${total}; total: ${total}; totalRelation: exact; hasMore: false; nextOffset: none`,
    );
    provenanceParity(value.provenance, text(result));
  });
  it.each([{}, { minEpss: 0.8, maxEpss: 0.2 }, { minPercentile: 0.9, maxPercentile: 0.1 }])(
    'returns actionable invalid filter reasons: %j',
    async (input) => {
      const result = await runToolContract(epssQueryThreshold, input);
      errorParity(
        result,
        JsonRpcErrorCode.ValidationError,
        'invalid_filter_combination',
        epssQueryThreshold.errors![0]!.recovery,
      );
      expect(calls).toEqual([]);
    },
  );
});

describe('reference and failure consumption paths', () => {
  it('keeps invalid filters distinct from upstream shape and transport errors on both surfaces', async () => {
    const result = await runToolContract(epssQueryThreshold, { limit: 5 });
    expect(result.structuredContent).toMatchObject({
      error: {
        message: 'Supply a qualifying filter and ordered inclusive bounds.',
        data: { retryable: false, reason: 'invalid_filter_combination' },
      },
    });
    expect(text(result)).toContain('Supply a qualifying filter and ordered inclusive bounds.');
    expect(calls).toEqual([]);
  });
  it.each([epssGetScores, epssGetTimeseries])(
    '$name omits irrelevant CVSS clauses for unscored CVEs',
    async (tool) => {
      api = (url) => envelope(url, []);
      const result = await runToolContract(tool, { cves: [cve(0)] });
      expect(text(result)).toContain('not_returned');
      expect(text(result)).not.toContain('CVSS');
    },
  );
  it('accepts the new current UTC year after a process crosses rollover', async () => {
    vi.setSystemTime(new Date('2027-01-01T00:00:00Z'));
    api = (url) => envelope(url, []);
    const result = await runToolContract(epssQueryThreshold, { year: 2027 });
    success(result, epssQueryThreshold.output);
    expect(calls[0]?.searchParams.get('q')).toBe('2027');
    const future = await runToolContract(epssQueryThreshold, { year: 2028 });
    expect(future.isError).toBe(true);
    expect(text(future)).toContain('current UTC year');
    expect(calls).toHaveLength(1);
  });
  it.each([epssGetScores, epssGetTimeseries, epssQueryThreshold])(
    '$name explains unavailable snapshots without exposing upstream text',
    async (tool) => {
      api = () =>
        Response.json(
          {
            'status-code': 422,
            message: ['listNoResults'],
            data: { error: ['listNoResults'] },
            private: 'never expose',
          },
          { status: 422 },
        );
      const result = await runToolContract(tool, {
        ...(tool.name === 'epss_query_threshold' ? { minEpss: 0 } : { cves: [cve(0)] }),
        date: '2026-10-17',
      });
      expect(result.structuredContent).toMatchObject({
        error: { data: { reason: 'snapshot_unavailable', retryable: false } },
      });
      expect(text(result)).toContain('2026-10-17');
      expect(text(result)).toContain('another date');
      expect(JSON.stringify(result)).not.toContain('never expose');
    },
  );
  it('keeps unrelated 422 responses as HTTP failures', async () => {
    api = () => Response.json({ message: ['other'], private: 'never expose' }, { status: 422 });
    const result = await runToolContract(epssGetScores, { cves: [cve(0)], date });
    expect(result.structuredContent).not.toHaveProperty('error.data.reason');
    expect(text(result)).toContain('HTTP 422');
    expect(JSON.stringify(result)).not.toContain('never expose');
  });
  it.each(['all', 'interpretation', 'models', 'coverage', 'prioritization'] as const)(
    'renders every nested fact and source for %s',
    async (topic) => {
      const result = await runToolContract(epssListReference, { topic });
      const value = success(result, epssListReference.output);
      expect(value.verifiedAt).toBe(date);
      expect(value.topics.map((item) => item.topic)).toEqual(
        topic === 'all' ? ['interpretation', 'models', 'coverage', 'prioritization'] : [topic],
      );
      expect(text(result)).toContain(`Verified at: ${date}`);
      for (const item of value.topics) {
        expect(item.facts.length).toBeGreaterThan(3);
        expect(item.sources.length).toBeGreaterThan(0);
        expect(text(result)).toContain(`## ${item.topic}`);
        for (const detail of [item.guidance, ...item.facts, ...item.sources])
          expect(text(result)).toContain(detail);
      }
      expect(calls).toEqual([]);
    },
  );
  it('defaults reference to all topics', async () => {
    const result = await runToolContract(epssListReference, {});
    expect(success(result, epssListReference.output).topics).toHaveLength(4);
    expect(text(result)).toContain('## prioritization');
  });
  it.each([epssGetScores, epssGetTimeseries, epssPrioritizeCves, epssQueryThreshold])(
    '$name preserves declared shape errors and recovery on both paths',
    async (tool) => {
      api = () => Response.json({ status: 'OK', data: 'invalid' });
      const input =
        tool.name === 'epss_query_threshold'
          ? { minEpss: 0 }
          : tool.name === 'epss_prioritize_cves'
            ? { cves: [{ cve: cve(0) }] }
            : { cves: [cve(0)] };
      const result = await runToolContract(tool, input);
      const contract = tool.errors!.find((error) => error.reason === 'upstream_shape')!;
      errorParity(result, JsonRpcErrorCode.SerializationError, 'upstream_shape', contract.recovery);
      expect(text(result)).not.toContain('node_modules');
    },
  );
  it.each([
    { tool: epssGetScores, input: { cves: { nested: 4 } } },
    { tool: epssGetScores, input: { cves: [' '] } },
    { tool: epssGetScores, input: { cves: ids(5001) } },
    { tool: epssGetScores, input: { cves: [cve(0)], date: '2026-02-30' } },
    { tool: epssGetTimeseries, input: { cves: [], date: date } },
    { tool: epssGetTimeseries, input: { cves: [cve(0)], date: '2021-04-13' } },
    { tool: epssGetTimeseries, input: { cves: [cve(0)], date: '2026-10-19' } },
    { tool: epssPrioritizeCves, input: { cves: [{ cve: cve(0), cvssBaseScore: 'seven' }] } },
    { tool: epssPrioritizeCves, input: { cves: [{ cve: cve(0), cvssBaseScore: 11 }] } },
    {
      tool: epssPrioritizeCves,
      input: { cves: [{ cve: cve(0) }], likelihood: { metric: 'epss', threshold: 1.1 } },
    },
    {
      tool: epssPrioritizeCves,
      input: { cves: [{ cve: cve(0) }], likelihood: { metric: 'both', threshold: 0.1 } },
    },
    { tool: epssQueryThreshold, input: { minEpss: 'not numeric' } },
    { tool: epssQueryThreshold, input: { minEpss: 0, limit: 10001 } },
    { tool: epssQueryThreshold, input: { minEpss: 0, offset: -1 } },
    { tool: epssListReference, input: { topic: 'unknown' } },
  ])('rejects malformed caller input before network %#', async ({ tool, input }) => {
    const result = await runToolContract(tool, input);
    errorParity(result, JsonRpcErrorCode.InvalidParams);
    expect(text(result)).toContain(tool.name);
    expect(calls).toEqual([]);
  });
});
