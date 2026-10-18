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
    expect(rendered).not.toContain('2026-09-17');
    expect(rendered).toContain('Missing dates: 2026-09-28, 2026-10-17');
    expect(rendered).toContain('observation count: 28');
    expect(rendered).toContain(`delta7d: ${item.delta7d}; delta30d: ${item.delta30d}`);
    provenanceParity(value.provenance, rendered);
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
      });
      for (const id of ids(cap + 2).slice(cap)) {
        expect(text(result).split(id)).toHaveLength(2);
        expect(calls.some((url) => url.searchParams.get('cve')?.split(',').includes(id))).toBe(
          false,
        );
      }
      expect(text(result)).toContain(`Call ${tool.name} with these deferred CVEs`);
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
    expect(value.tiers.monitor).toHaveLength(500);
    expect(text(result).split(cve(500))).toHaveLength(2);
    expect(text(result)).toContain('Call epss_prioritize_cves with these deferred CVEs');
  });
});

describe('exact-date history policy', () => {
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
    expect(item.delta30d).toBe(0.8 - 0.2);
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
