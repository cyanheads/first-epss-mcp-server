/**
 * @fileoverview Network-boundary contracts for the real FIRST EPSS service.
 * @module tests/services/epss/epss-service.test
 */

import { gzipSync } from 'node:zlib';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const dns = vi.hoisted(() => ({
  lookup: vi.fn(async () => [{ address: '93.184.216.34', family: 4 }]),
  resolve4: vi.fn(async () => ['93.184.216.34']),
  resolve6: vi.fn(async () => []),
}));
vi.mock('node:dns/promises', () => dns);

const date = '2026-10-18';
const realNow = Date.now.bind(Date);
let clockOffset = 0;
const header = `#model_version:v2026.06.15,score_date:${date}T12:03:10Z\ncve,epss,percentile\n`;
const ids = (count: number) => Array.from({ length: count }, (_, i) => `CVE-2026-${1000 + i}`);
const row = (cve = 'CVE-2026-1000', extra: Record<string, unknown> = {}) => ({
  cve,
  epss: '0.1',
  percentile: '0.9',
  date,
  ...extra,
});
type Domain = typeof import('@/services/epss/index.js');
let domain: Domain;
let calls: URL[];
let headerCalls: number;
let api: (url: URL, init?: RequestInit) => Response | Promise<Response>;
let metadata: (init?: RequestInit) => Response | Promise<Response>;
function envelope(url: URL, data: unknown[], total = data.length): Response {
  return Response.json({
    status: 'OK',
    'status-code': 200,
    total,
    limit: Number(url.searchParams.get('limit')),
    offset: Number(url.searchParams.get('offset') ?? 0),
    data,
  });
}
beforeEach(async () => {
  vi.resetModules();
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(new Date(`${date}T15:00:00Z`));
  clockOffset = 0;
  vi.spyOn(Date, 'now').mockImplementation(() => realNow() + clockOffset);
  calls = [];
  headerCalls = 0;
  api = (url) =>
    envelope(
      url,
      (url.searchParams.get('cve') ?? '')
        .split(',')
        .filter(Boolean)
        .map((cve) => row(cve)),
    );
  metadata = () => new Response(header);
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | Request | URL, init?: RequestInit) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.origin === 'https://api.first.org' && url.pathname === '/data/v1/epss') {
        calls.push(url);
        return api(url, init);
      }
      if (url.href === 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz') {
        headerCalls++;
        return metadata(init);
      }
      throw new Error(`Unexpected URL: ${url.href}`);
    }),
  );
  domain = await import('@/services/epss/index.js');
});
afterEach(() => {
  domain?.disposeEpssService();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('batch accounting and snapshot contracts', () => {
  it('deduplicates canonical IDs and preserves zero versus absent scores', async () => {
    api = (url) => envelope(url, [row(undefined, { epss: '0', percentile: 0 })]);
    const result = await new domain.EpssService().getScores(
      { cves: [' cve-2026-1000 ', 'CVE-2026-1000', 'bad', 'CVE-2026-1001'] },
      createMockContext(),
    );
    expect(result).toMatchObject({
      requestedCount: 3,
      processedCount: 3,
      duplicateCount: 1,
      scores: [{ epss: 0, percentile: 0, modelVersionSource: 'csv_header' }],
      unscoredCves: [
        { cve: 'BAD', reason: 'invalid_format' },
        { cve: 'CVE-2026-1001', reason: 'not_returned' },
      ],
    });
    expect(calls[0]?.searchParams.get('cve')).toBe('CVE-2026-1000,CVE-2026-1001');
    expect(headerCalls).toBe(1);
  });
  it('raises the upstream limit beyond the default 100', async () => {
    const result = await new domain.EpssService().getScores(
      { cves: ids(130) },
      createMockContext(),
    );
    expect(result.scores).toHaveLength(130);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.searchParams.get('limit')).toBe('130');
  });
  it.each([1999, 2000, 2001])(
    'splits a joined CVE value of length %i strictly below 2000',
    async (length) => {
      const cves = [
        ...Array.from({ length: 15 }, (_, i) => `CVE-2026-${String(i).padStart(119, '0')}`),
        `CVE-2026-${'9'.repeat(length - 1944)}`,
      ];
      expect(cves.join(',')).toHaveLength(length);
      expect(
        (await new domain.EpssService().getScores({ cves }, createMockContext())).scores,
      ).toHaveLength(16);
      expect(calls).toHaveLength(length === 1999 ? 1 : 2);
      for (const url of calls) expect(url.searchParams.get('cve')?.length).toBeLessThan(2000);
    },
  );
  it('caps at 500 and pins subsequent chunks to the first score date', async () => {
    const result = await new domain.EpssService().getScores(
      { cves: [...ids(502), 'cve-2026-1000'] },
      createMockContext(),
    );
    expect(result).toMatchObject({
      requestedCount: 502,
      processedCount: 500,
      duplicateCount: 1,
      deferredCves: ids(502).slice(500),
    });
    expect(result.scores).toHaveLength(500);
    expect(calls[0]?.searchParams.has('date')).toBe(false);
    expect(calls.slice(1).every((url) => url.searchParams.get('date') === date)).toBe(true);
    expect(result.provenance.scoreDates).toEqual([date]);
  });
  it('caps history at 50 without issuing individual lookups', async () => {
    const result = await new domain.EpssService().getTimeseries(
      { cves: ids(52) },
      createMockContext(),
    );
    expect(result.items).toHaveLength(50);
    expect(result.deferredCves).toEqual(ids(52).slice(50));
    expect(result.items.every((item) => item.series.length === 0)).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.searchParams.get('scope')).toBe('time-series');
  });
  it('rejects daily snapshot drift between chunks', async () => {
    api = (url) =>
      envelope(
        url,
        (url.searchParams.get('cve') ?? '')
          .split(',')
          .map((cve) => row(cve, { date: calls.length === 1 ? date : '2026-10-17' })),
      );
    await expect(
      new domain.EpssService().getScores({ cves: ids(160) }, createMockContext()),
    ).rejects.toMatchObject({ data: { reason: 'upstream_shape' } });
    expect(headerCalls).toBe(0);
  });
  it('returns invalid-only inputs with a coverage notice and no network traffic', async () => {
    const result = await new domain.EpssService().getScores({ cves: ['bad'] }, createMockContext());
    expect(result.scores).toEqual([]);
    expect(result.unscoredCves[0]?.reason).toBe('invalid_format');
    expect(result.notices.join(' ')).toContain('No requested CVEs');
    expect(calls).toEqual([]);
    expect(headerCalls).toBe(0);
  });
  it.each([[], [''], ['x'.repeat(129)], ids(5001)].map((cves) => ({ cves })))(
    'rejects invalid input bounds %#',
    async ({ cves }) => {
      await expect(
        new domain.EpssService().getScores({ cves }, createMockContext()),
      ).rejects.toMatchObject({ code: JsonRpcErrorCode.ValidationError });
      expect(calls).toEqual([]);
    },
  );
});

describe('strict upstream parsing', () => {
  it('rejects a history observation naming a different CVE', async () => {
    api = (url) =>
      envelope(url, [
        row(undefined, {
          'time-series': [{ cve: 'CVE-2026-9999', date: '2026-10-17', epss: 0.2, percentile: 0.3 }],
        }),
      ]);
    await expect(
      new domain.EpssService().getTimeseries({ cves: ids(1) }, createMockContext()),
    ).rejects.toMatchObject({ data: { reason: 'upstream_shape' } });
  });
  it('retains sparse early history without inventing observations', async () => {
    api = (url) =>
      envelope(url, [
        row(undefined, {
          date: '2021-04-15',
          'time-series': [{ date: '2021-04-14', epss: '1e-3', percentile: '.2' }],
        }),
      ]);
    const result = await new domain.EpssService().getTimeseries(
      { cves: ids(1), date: '2021-04-15' },
      createMockContext(),
    );
    expect(result.items[0]?.series).toMatchObject([
      { date: '2021-04-14', epss: 0.001, percentile: 0.2 },
    ]);
    expect(result.items[0]?.series).toHaveLength(1);
  });
  it.each(['', ' ', 'NaN', 'Infinity', '0x1', null, undefined, false, -0.1, 1.1])(
    'rejects invalid required probability %j without retry',
    async (epss) => {
      api = (url) => envelope(url, [row(undefined, { epss })]);
      await expect(
        new domain.EpssService().getScores({ cves: ids(1) }, createMockContext()),
      ).rejects.toMatchObject({
        code: JsonRpcErrorCode.SerializationError,
        data: { reason: 'upstream_shape' },
      });
      expect(calls).toHaveLength(1);
    },
  );
  it.each([
    { percentile: undefined },
    { date: '2026-02-30' },
    { date: '2026-10-19' },
    { cve: 'CVE-2026-9999' },
  ])('rejects invalid or unexpected score fields %j', async (extra) => {
    api = (url) => envelope(url, [row(undefined, extra)]);
    await expect(
      new domain.EpssService().getScores({ cves: ids(1) }, createMockContext()),
    ).rejects.toMatchObject({ data: { reason: 'upstream_shape' } });
    expect(calls).toHaveLength(1);
  });
  it.each([
    'duplicate',
    'truncated',
    'empty_before_total',
    'wrong_offset',
    'wrong_limit',
    'bad_status',
  ])('rejects envelope inconsistency %s', async (kind) => {
    api = (url) => {
      if (kind === 'duplicate') return envelope(url, [row(), row()]);
      if (kind === 'truncated') return envelope(url, [row()], 2);
      if (kind === 'empty_before_total') return envelope(url, [], 1);
      return Response.json({
        status: kind === 'bad_status' ? 'ERROR' : 'OK',
        'status-code': 200,
        data: [row()],
        total: 1,
        offset: kind === 'wrong_offset' ? 1 : 0,
        limit: kind === 'wrong_limit' ? 99 : 2,
      });
    };
    await expect(
      new domain.EpssService().getScores({ cves: ids(2) }, createMockContext()),
    ).rejects.toMatchObject({ data: { reason: 'upstream_shape' } });
    expect(calls).toHaveLength(1);
  });
  it('normalizes all 30 preceding observations and sorts shuffled dates', async () => {
    const series = Array.from({ length: 30 }, (_, i) => ({
      date: domain.shiftDate(date, -i - 1),
      epss: String(i / 100),
      percentile: '0.2',
    }));
    api = (url) => envelope(url, [row(undefined, { 'time-series': series })]);
    const result = await new domain.EpssService().getTimeseries(
      { cves: ids(1) },
      createMockContext(),
    );
    expect(result.items[0]?.series).toHaveLength(30);
    expect(result.items[0]?.series[0]).toMatchObject({
      cve: ids(1)[0],
      date: '2026-09-18',
      epss: 0.29,
    });
    expect(result.items[0]?.series.at(-1)?.date).toBe('2026-10-17');
  });
  it.each([
    null,
    [{ date, epss: 0.2, percentile: 0.3 }],
    [{ date: '2026-09-17', epss: 0.2, percentile: 0.3 }],
    [
      { date: '2026-10-17', epss: 0.2, percentile: 0.3 },
      { date: '2026-10-17', epss: 0.4, percentile: 0.3 },
    ],
    [{ date: '2026-10-17', epss: '', percentile: 0.3 }],
  ])('rejects contradictory history %#', async (series) => {
    api = (url) => envelope(url, [row(undefined, { 'time-series': series })]);
    await expect(
      new domain.EpssService().getTimeseries({ cves: ids(1) }, createMockContext()),
    ).rejects.toMatchObject({ data: { reason: 'upstream_shape' } });
    expect(calls).toHaveLength(1);
  });
});

describe('candidate paging', () => {
  it('continues in candidate space through an empty exact-year page', async () => {
    api = (url) =>
      envelope(
        url,
        Number(url.searchParams.get('offset')) === 0
          ? [row('CVE-2025-2021'), row('CVE-2024-2021')]
          : [row('CVE-2021-1000')],
        3,
      );
    const service = new domain.EpssService();
    const first = await service.queryThreshold({ year: 2021, limit: 2 }, createMockContext());
    expect(first.scores).toEqual([]);
    expect(first.pagination).toMatchObject({
      examinedCount: 2,
      returnedCount: 0,
      total: null,
      totalRelation: 'unknown',
      candidateTotal: 3,
      nextOffset: 2,
      hasMore: true,
    });
    expect(first.provenance.scoreDates).toEqual([date]);
    const second = await service.queryThreshold(
      {
        year: 2021,
        limit: 2,
        offset: first.pagination.nextOffset!,
        date: first.provenance.scoreDates[0]!,
      },
      createMockContext(),
    );
    expect(second.scores[0]?.cve).toBe('CVE-2021-1000');
    expect(second.pagination).toMatchObject({
      total: null,
      totalRelation: 'unknown',
      hasMore: false,
    });
    expect(calls[1]?.searchParams.get('date')).toBe(date);
    expect(calls[1]?.searchParams.get('offset')).toBe('2');
  });
  it('maps inclusive bounds and dataset days independently of historical date', async () => {
    api = (url) => envelope(url, [row(undefined, { date: '2025-01-01' })]);
    const result = await new domain.EpssService().queryThreshold(
      {
        minEpss: 0.1,
        maxEpss: 0.1,
        minPercentile: 0,
        maxPercentile: 1,
        addedWithinDays: 3,
        date: '2025-01-01',
        limit: 1,
      },
      createMockContext(),
    );
    expect(Object.fromEntries(calls[0]?.searchParams ?? [])).toEqual({
      'epss-gt': '0.1',
      'epss-lt': '0.1',
      'percentile-gt': '0',
      'percentile-lt': '1',
      days: '3',
      date: '2025-01-01',
      order: '!epss',
      limit: '1',
      offset: '0',
    });
    expect(result.pagination).toMatchObject({ total: 1, totalRelation: 'exact', hasMore: false });
    expect(result.provenance.modelMetadata.status).toBe('inferred');
  });
  it.each([{}, { minEpss: 0.8, maxEpss: 0.2 }, { minPercentile: 0.8, maxPercentile: 0.2 }])(
    'rejects invalid combinations %j',
    async (input) => {
      await expect(
        new domain.EpssService().queryThreshold(input, createMockContext()),
      ).rejects.toMatchObject({
        code: JsonRpcErrorCode.ValidationError,
        data: {
          reason: 'invalid_filter_combination',
          recovery: {
            hint: "Call epss_list_reference with topic='coverage', then call epss_query_threshold with ordered bounds or a year/addition filter.",
          },
        },
      });
      expect(calls).toEqual([]);
    },
  );
  it('returns exhausted offsets without invented dates or continuation', async () => {
    api = (url) => envelope(url, [], 2);
    const result = await new domain.EpssService().queryThreshold(
      { minEpss: 0, offset: 9 },
      createMockContext(),
    );
    expect(result.pagination).toMatchObject({
      offset: 9,
      examinedCount: 0,
      hasMore: false,
      total: 2,
    });
    expect(result.pagination.nextOffset).toBeUndefined();
    expect(result.provenance.scoreDates).toEqual([]);
    expect(headerCalls).toBe(0);
  });
});

describe('transport failures and cancellation', () => {
  it('stops a slow multi-chunk workload at the whole-call deadline', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(`${date}T15:00:00Z`));
    api = (url, init) =>
      new Promise<Response>((resolve, reject) => {
        const timer = setTimeout(
          () =>
            resolve(
              envelope(
                url,
                (url.searchParams.get('cve') ?? '').split(',').map((cve) => row(cve)),
              ),
            ),
          9000,
        );
        init?.signal?.addEventListener(
          'abort',
          () => {
            clearTimeout(timer);
            reject(init.signal?.reason);
          },
          { once: true },
        );
      });
    const cves = Array.from({ length: 500 }, (_, i) => `CVE-2026-${String(i).padStart(60, '0')}`);
    const operation = new domain.EpssService().getScores({ cves }, createMockContext());
    const rejected = expect(operation).rejects.toMatchObject({
      code: JsonRpcErrorCode.Timeout,
      data: { retryable: false },
    });
    await vi.advanceTimersByTimeAsync(45000);
    await rejected;
    const attempts = calls.length;
    await vi.advanceTimersByTimeAsync(20000);
    expect(calls).toHaveLength(attempts);
    expect(attempts).toBe(5);
    expect(headerCalls).toBe(0);
  });

  it('times out a hanging attempt and never proceeds to later chunks', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(`${date}T15:00:00Z`));
    api = (_url, init) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(init.signal?.reason), { once: true });
      });
    const operation = new domain.EpssService().getScores({ cves: ids(160) }, createMockContext());
    const rejected = expect(operation).rejects.toMatchObject({ code: JsonRpcErrorCode.Timeout });
    await vi.advanceTimersByTimeAsync(45000);
    await rejected;
    expect(calls.length).toBeLessThanOrEqual(3);
    expect(
      calls.every((url) => url.searchParams.get('cve') === calls[0]?.searchParams.get('cve')),
    ).toBe(true);
    expect(headerCalls).toBe(0);
  });
  it('does not retry ordinary HTTP errors or leak upstream bodies/headers', async () => {
    api = () =>
      new Response('<html>SECRET_BODY</html>', {
        status: 422,
        headers: { 'x-secret': 'SECRET_HEADER' },
      });
    const error = await new domain.EpssService()
      .getScores({ cves: ids(1) }, createMockContext())
      .catch((error: unknown) => error);
    expect(error).toMatchObject({ data: { status: 422, endpoint: 'scores' } });
    expect(JSON.stringify(error)).not.toContain('SECRET');
    expect(calls).toHaveLength(1);
  });
  it.each([429, 503, 'html'] as const)(
    'retries transient %s without inventing missing scores',
    async (status) => {
      api = (url) =>
        calls.length === 1
          ? new Response('<html>unavailable</html>', {
              status: status === 'html' ? 200 : status,
              headers: { 'retry-after': '0' },
            })
          : envelope(url, [row()]);
      const result = await new domain.EpssService().getScores(
        { cves: ids(1) },
        createMockContext(),
      );
      expect(calls).toHaveLength(2);
      expect(result.scores).toHaveLength(1);
      expect(result.unscoredCves).toEqual([]);
    },
  );
  it('does not fetch on prior cancellation or expose caller abort text', async () => {
    const controller = new AbortController();
    controller.abort('SECRET_REASON');
    const error = await new domain.EpssService()
      .getScores({ cves: ids(160) }, createMockContext({ signal: controller.signal }))
      .catch((error: unknown) => error);
    expect(error).toMatchObject({ code: JsonRpcErrorCode.RequestCancelled });
    expect(JSON.stringify(error)).not.toContain('SECRET_REASON');
    expect(calls).toEqual([]);
  });
  it('does not continue pending chunks after caller cancellation', async () => {
    const controller = new AbortController();
    api = (url) => {
      controller.abort();
      return envelope(url, [row()]);
    };
    await expect(
      new domain.EpssService().getScores(
        { cves: ids(160) },
        createMockContext({ signal: controller.signal }),
      ),
    ).rejects.toMatchObject({ code: JsonRpcErrorCode.RequestCancelled });
    expect(calls).toHaveLength(1);
    expect(headerCalls).toBe(0);
  });
});

describe('bounded model metadata', () => {
  it('rejects a private DNS answer even when another resolver returns a public address', async () => {
    dns.lookup.mockResolvedValueOnce([{ address: '127.0.0.1', family: 4 }]);
    dns.resolve4.mockResolvedValueOnce(['93.184.216.34']);
    await expect(
      new domain.ModelHeaderCache().get(createMockContext(), new AbortController().signal),
    ).rejects.toThrow(/not public/);
    expect(headerCalls).toBe(0);
  });
  it('does not attribute a stale header to a latest score', async () => {
    metadata = () => new Response(header.replace(date, '2026-10-17'));
    const result = await new domain.EpssService().getScores({ cves: ids(1) }, createMockContext());
    expect(result.scores[0]?.modelVersionSource).toBe('unavailable');
    expect(result.provenance.modelMetadata.status).toBe('unavailable');
    expect(result.notices.join(' ')).toContain('does not verify');
  });
  it('follows a same-allowlist redirect through real status handling', async () => {
    metadata = () =>
      headerCalls === 1
        ? new Response(null, { status: 302, headers: { location: '/epss_scores-current.csv.gz' } })
        : new Response(header);
    await expect(
      new domain.ModelHeaderCache().get(createMockContext(), new AbortController().signal),
    ).resolves.toMatchObject({ scoreDate: date });
    expect(headerCalls).toBe(2);
  });
  it('rejects an external redirect before another fetch', async () => {
    metadata = () =>
      new Response(null, { status: 302, headers: { location: 'https://example.com/private' } });
    await expect(
      new domain.ModelHeaderCache().get(createMockContext(), new AbortController().signal),
    ).rejects.toThrow(/redirect/);
    expect(headerCalls).toBe(1);
  });
  it('cancels malformed gzip sources when decoding fails', async () => {
    const cancel = vi.fn();
    metadata = () =>
      new Response(
        new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new Uint8Array([31, 139, 0, 0, 0, 0, 0, 0, 0, 0]));
          },
          cancel,
        }),
      );
    await expect(
      new domain.ModelHeaderCache().get(createMockContext(), new AbortController().signal),
    ).rejects.toThrow();
    expect(cancel).toHaveBeenCalled();
  });
  it('degrades only the five-second metadata budget while preserving scores', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(`${date}T15:00:00Z`));
    metadata = (init) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(init.signal?.reason), { once: true });
      });
    const operation = new domain.EpssService().getScores({ cves: ids(1) }, createMockContext());
    await vi.advanceTimersByTimeAsync(5100);
    const result = await operation;
    expect(result.scores).toHaveLength(1);
    expect(result.provenance.modelMetadata.status).toBe('unavailable');
    expect(result.notices.join(' ')).toContain('could not be verified');
  });
  it('fails caller cancellation during metadata instead of degrading to success', async () => {
    const controller = new AbortController();
    metadata = (init) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(init.signal?.reason), { once: true });
        controller.abort();
      });
    await expect(
      new domain.EpssService().getScores(
        { cves: ids(1) },
        createMockContext({ signal: controller.signal }),
      ),
    ).rejects.toMatchObject({ code: JsonRpcErrorCode.RequestCancelled });
  });
  it('reads gzip and timestamp dates, coalesces and expires the 15-minute cache', async () => {
    metadata = () => new Response(gzipSync(header));
    const cache = new domain.ModelHeaderCache();
    const ctx = createMockContext();
    const signal = new AbortController().signal;
    const expected = { scoreDate: date, modelVersion: 'v2026.06.15' };
    await expect(Promise.all([cache.get(ctx, signal), cache.get(ctx, signal)])).resolves.toEqual([
      expected,
      expected,
    ]);
    await expect(cache.get(ctx, signal)).resolves.toEqual(expected);
    expect(headerCalls).toBe(1);
    clockOffset = 900000;
    await expect(cache.get(ctx, signal)).resolves.toEqual(expected);
    expect(headerCalls).toBe(2);
  });
  it.each([
    '#model_version:v2026.06.15,score_date:2026-02-30\n',
    '#score_date:2026-10-18\n',
    '#model_version:unknown,score_date:2026-10-18\n',
    '#model_version:v2026.06.15,score_date:2026-10-18',
  ])('rejects malformed/incomplete metadata %#', async (text) => {
    metadata = () => new Response(text);
    await expect(
      new domain.ModelHeaderCache().get(createMockContext(), new AbortController().signal),
    ).rejects.toThrow();
  });
  it.each(['compressed', 'decompressed'] as const)(
    'bounds %s bytes and cancels the source',
    async (kind) => {
      const cancel = vi.fn();
      const bytes = kind === 'compressed' ? new Uint8Array(65537) : gzipSync('x'.repeat(16385));
      metadata = () =>
        new Response(
          new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(bytes);
            },
            cancel,
          }),
        );
      await expect(
        new domain.ModelHeaderCache().get(createMockContext(), new AbortController().signal),
      ).rejects.toThrow(/budget exceeded/);
      expect(cancel).toHaveBeenCalled();
    },
  );
  it('cancels after the header without consuming the dataset', async () => {
    const cancel = vi.fn();
    metadata = () =>
      new Response(
        new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new TextEncoder().encode(header));
          },
          cancel,
        }),
      );
    await expect(
      new domain.ModelHeaderCache().get(createMockContext(), new AbortController().signal),
    ).resolves.toMatchObject({ scoreDate: date });
    expect(cancel).toHaveBeenCalled();
  });
  it('isolates cancellation of one shared-cache waiter', async () => {
    let complete: (value: Response) => void = () => {};
    metadata = () =>
      new Promise<Response>((resolve) => {
        complete = resolve;
      });
    const cache = new domain.ModelHeaderCache();
    const controller = new AbortController();
    const first = cache.get(createMockContext(), controller.signal);
    const second = cache.get(createMockContext(), new AbortController().signal);
    const rejected = expect(first).rejects.toMatchObject({
      code: JsonRpcErrorCode.RequestCancelled,
    });
    await vi.waitFor(() => expect(headerCalls).toBe(1));
    controller.abort();
    await rejected;
    complete(new Response(header));
    await expect(second).resolves.toMatchObject({ scoreDate: date });
    expect(headerCalls).toBe(1);
  });
  it('degrades header failure to an explicit metadata notice', async () => {
    metadata = () => new Response('unavailable', { status: 503 });
    const result = await new domain.EpssService().getScores({ cves: ids(1) }, createMockContext());
    expect(result.scores).toHaveLength(1);
    expect(result.scores[0]?.modelVersionSource).toBe('unavailable');
    expect(result.provenance.modelMetadata.status).toBe('unavailable');
    expect(result.notices.join(' ')).toContain('could not be verified');
  });
  it('does not invent a version string for inferred EPSS v1', async () => {
    api = (url) => envelope(url, [row(undefined, { date: '2021-04-14' })]);
    const result = await new domain.EpssService().getScores(
      { cves: ids(1), date: '2021-04-14' },
      createMockContext(),
    );
    expect(result.provenance.modelMetadata).toMatchObject({
      status: 'inferred',
      scoreDate: '2021-04-14',
    });
    expect(result.scores[0]?.modelVersionSource).toBe('published_schedule');
    expect(result.scores[0]?.modelVersion).toBeUndefined();
    expect(result.provenance.modelMetadata.modelVersion).toBeUndefined();
  });
});
