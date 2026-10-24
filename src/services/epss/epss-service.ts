/**
 * @fileoverview Bounded FIRST EPSS lookup transport and normalized domain service.
 * @module services/epss/epss-service
 */
import type { Context } from '@cyanheads/mcp-ts-core';
import { serviceUnavailable } from '@cyanheads/mcp-ts-core/errors';
import { createPacer, withRetry } from '@cyanheads/mcp-ts-core/utils';
import { requestApi } from './api-request.js';
import { checkSignal, safeError, localValidationError as validationError } from './errors.js';
import { HEADER_URL, ModelHeaderCache } from './model-header.js';
import {
  chunkCves,
  compareScores,
  MODEL_SCHEDULE_VERIFIED_AT,
  MODEL_TRANSITIONS,
  normalizeBatch,
  normalizeDate,
  normalizeScore,
  record,
  shiftDate,
  upstreamShape,
} from './normalization.js';
import type {
  BatchInput,
  HeaderMetadata,
  ModelMetadata,
  Provenance,
  RawTimeseriesItem,
  Score,
  ScoresResult,
  ThresholdInput,
  ThresholdResult,
  TimeseriesResult,
} from './types.js';

/** Fixed keyless FIRST API endpoint. */
export const API_URL = 'https://api.first.org/data/v1/epss';
/** Published model schedule source. */
export const MODEL_SCHEDULE_URL = 'https://www.first.org/epss/data';
const missingGuidance =
  "Call epss_list_reference with topic='coverage' to interpret missing scores; retry epss_get_scores for a later score date.";
const coverageNotice =
  "No requested CVEs were returned by EPSS. Call epss_list_reference with topic='coverage' before interpreting the missing scores.";
const metadataRecovery =
  "Call epss_list_reference with topic='models' for documented model publishing dates; retry epss_get_scores later for verified current metadata.";
const pacer = createPacer({
  name: 'first_epss',
  minStartGapMs: 100,
  maxConcurrent: 1,
  maxQueueDepth: 100,
  cooldown: { baseMs: 1000, maxMs: 10000 },
});
const headers = new ModelHeaderCache();

interface Envelope {
  data: unknown[];
  limit: number;
  offset: number;
  total: number;
}

function integer(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) upstreamShape();
  return value;
}

function parseEnvelope(value: unknown, offset: number, limit: number): Envelope {
  const raw = record(value);
  if (raw.status !== 'OK' || raw['status-code'] !== 200 || !Array.isArray(raw.data))
    upstreamShape();
  const total = integer(raw.total);
  const returnedOffset = integer(raw.offset);
  const returnedLimit = integer(raw.limit);
  if (
    returnedOffset !== offset ||
    returnedLimit !== limit ||
    raw.data.length > limit ||
    (raw.data.length > 0 && offset + raw.data.length > total) ||
    (!raw.data.length && offset < total)
  )
    upstreamShape();
  return { total, offset, limit, data: raw.data };
}

/** Real transport seam: tests replace global fetch beneath framework timeout/status handling. */
export class EpssService {
  /** Retrieve up to 500 canonical identifiers with explicit omissions and deferrals. */
  getScores(input: BatchInput, ctx: Context): Promise<ScoresResult> {
    return this.call(ctx, async (signal) => {
      const result = await this.batch(input, false, ctx, signal);
      return {
        ...result.accounting,
        scores: result.items.map((item) => item.current).sort(compareScores),
        provenance: result.provenance,
        notices: result.notices,
      };
    });
  }

  /** Retrieve up to 50 anchors with normalized preceding observations. */
  getTimeseries(input: BatchInput, ctx: Context): Promise<TimeseriesResult> {
    return this.call(ctx, async (signal) => {
      const result = await this.batch(input, true, ctx, signal);
      return {
        ...result.accounting,
        items: result.items.sort((a, b) => compareScores(a.current, b.current)),
        provenance: result.provenance,
        notices: result.notices,
      };
    });
  }

  /** Retrieve exactly one upstream candidate page and apply an exact local year filter. */
  queryThreshold(input: ThresholdInput, ctx: Context): Promise<ThresholdResult> {
    return this.call(ctx, async (signal) => {
      const date = normalizeDate(input.date);
      const limit = input.limit ?? 100;
      const offset = input.offset ?? 0;
      const filters: ThresholdInput = { ...input, ...(date ? { date } : {}) };
      if (!date) delete filters.date;
      const bounds = [
        ['minEpss', 'epss-gt'],
        ['maxEpss', 'epss-lt'],
        ['minPercentile', 'percentile-gt'],
        ['maxPercentile', 'percentile-lt'],
      ] as const;
      const params = new URLSearchParams({
        order: '!epss',
        limit: String(limit),
        offset: String(offset),
      });
      let qualifies = false;
      for (const [key, parameter] of bounds) {
        const value = input[key];
        if (value !== undefined) {
          if (!Number.isFinite(value) || value < 0 || value > 1)
            throw validationError('Score bounds must be finite numbers between zero and one.');
          params.set(parameter, String(value));
          qualifies = true;
        }
      }
      if (input.year !== undefined) {
        if (
          !Number.isInteger(input.year) ||
          input.year < 1999 ||
          input.year > new Date().getUTCFullYear()
        )
          throw validationError('Year must be from 1999 through the current UTC year.');
        params.set('q', String(input.year));
        qualifies = true;
      }
      if (input.addedWithinDays !== undefined) {
        if (
          !Number.isInteger(input.addedWithinDays) ||
          input.addedWithinDays < 1 ||
          input.addedWithinDays > 100000
        )
          throw validationError('addedWithinDays must be an integer from 1 through 100000.');
        params.set('days', String(input.addedWithinDays));
        qualifies = true;
      }
      if (
        !qualifies ||
        (input.minEpss !== undefined &&
          input.maxEpss !== undefined &&
          input.minEpss > input.maxEpss) ||
        (input.minPercentile !== undefined &&
          input.maxPercentile !== undefined &&
          input.minPercentile > input.maxPercentile)
      )
        throw validationError('Supply a qualifying filter and ordered inclusive bounds.', {
          reason: 'invalid_filter_combination',
          recovery: {
            hint: "Call epss_list_reference with topic='coverage', then call epss_query_threshold with ordered bounds or a year/addition filter.",
          },
        });
      if (
        !Number.isInteger(limit) ||
        limit < 1 ||
        limit > 10000 ||
        !Number.isSafeInteger(offset) ||
        offset < 0
      )
        throw validationError('Use limit 1 through 10000 and a nonnegative integer offset.');
      if (date) params.set('date', date);
      const envelope = await this.request(params, offset, limit, ctx, signal);
      const candidates = envelope.data.map((value) => normalizeScore(value));
      this.validateDates(candidates, date);
      if (new Set(candidates.map((score) => score.cve)).size !== candidates.length) upstreamShape();
      const { provenance, notices } = await this.attribute(candidates, date, ctx, signal);
      const matchOffsets: number[] = [];
      const scores = candidates.filter((score, index) => {
        const matches = input.year === undefined || score.cve.startsWith(`CVE-${input.year}-`);
        if (matches) matchOffsets.push(offset + index);
        return matches;
      });
      const nextOffset = offset + candidates.length;
      const hasMore = nextOffset < envelope.total;
      if (!scores.length) {
        if (input.year !== undefined)
          notices.push(
            hasMore
              ? 'No exact-year matches occurred in this candidate page. Call epss_query_threshold with the same filters, returned score date, and nextOffset.'
              : `No exact-year matches occurred in this candidate page. Candidate pagination complete. The exact-year total remains unknown.${offset > 0 ? ' Use an earlier offset to inspect previous candidates.' : ''}`,
          );
        else if (envelope.total > 0)
          notices.push(
            'Candidate pagination complete. The offset is at or beyond the candidate total; use an earlier offset to inspect previous candidates.',
          );
        else
          notices.push(
            "No CVEs matched these filters. Call epss_query_threshold with broader bounds or epss_list_reference with topic='coverage'.",
          );
      }
      return {
        matchOffsets,
        scores,
        filters,
        pagination: {
          offset,
          limit,
          examinedCount: candidates.length,
          returnedCount: scores.length,
          candidateTotal: envelope.total,
          total: input.year === undefined ? envelope.total : null,
          totalRelation: input.year === undefined ? 'exact' : 'unknown',
          hasMore,
          ...(hasMore ? { nextOffset } : {}),
        },
        provenance,
        notices,
      };
    });
  }

  private async call<T>(ctx: Context, run: (signal: AbortSignal) => Promise<T>): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(new DOMException('Whole-call deadline.', 'TimeoutError')),
      45000,
    );
    const signal = ctx.signal
      ? AbortSignal.any([controller.signal, ctx.signal])
      : controller.signal;
    try {
      checkSignal(signal);
      const result = await run(signal);
      checkSignal(signal);
      return result;
    } catch (error) {
      checkSignal(signal);
      throw safeError(error, 'scores');
    } finally {
      clearTimeout(timer);
    }
  }

  private request(
    params: URLSearchParams,
    offset: number,
    limit: number,
    ctx: Context,
    signal: AbortSignal,
  ): Promise<Envelope> {
    return withRetry(
      async ({ signal: attemptSignal }) => {
        try {
          return await pacer.run(
            async () => {
              checkSignal(attemptSignal);
              const text = await requestApi(
                `${API_URL}?${params}`,
                attemptSignal,
                params.get('date') ?? undefined,
              );
              if (/^\s*<(?:!doctype\s+html|html[\s>])/i.test(text))
                throw serviceUnavailable('FIRST EPSS returned an HTML availability page.');
              let value: unknown;
              try {
                value = JSON.parse(text);
              } catch {
                upstreamShape();
              }
              return parseEnvelope(value, offset, limit);
            },
            { signal: attemptSignal },
          );
        } catch (error) {
          checkSignal(attemptSignal);
          throw safeError(error, 'scores');
        }
      },
      {
        maxRetries: 2,
        baseDelayMs: 1000,
        jitter: 0.25,
        maxDelayMs: 10000,
        signal,
        operation: 'FIRST EPSS lookup',
        context: ctx,
      },
    );
  }

  private validateDates(scores: Score[], requestedDate?: string): void {
    const dates = new Set(scores.map((score) => score.date));
    if (dates.size > 1 || (requestedDate && scores.some((score) => score.date !== requestedDate)))
      upstreamShape();
  }

  private async batch(input: BatchInput, history: boolean, ctx: Context, signal: AbortSignal) {
    const date = normalizeDate(input.date);
    const batch = normalizeBatch(input.cves, history ? 50 : 500, input.batchOffset);
    const items: RawTimeseriesItem[] = [];
    let pinnedDate = date;
    for (const chunk of chunkCves(batch.validCves)) {
      checkSignal(signal);
      const params = new URLSearchParams({ cve: chunk.join(','), limit: String(chunk.length) });
      if (pinnedDate) params.set('date', pinnedDate);
      if (history) params.set('scope', 'time-series');
      const envelope = await this.request(params, 0, chunk.length, ctx, signal);
      if (envelope.total !== envelope.data.length) upstreamShape();
      const seen = new Set<string>();
      for (const value of envelope.data) {
        const raw = record(value);
        const current = normalizeScore(raw);
        if (!chunk.includes(current.cve) || seen.has(current.cve)) upstreamShape();
        seen.add(current.cve);
        if (pinnedDate && current.date !== pinnedDate) upstreamShape();
        pinnedDate ??= current.date;
        const series: Score[] = [];
        if (history && raw['time-series'] !== undefined) {
          if (!Array.isArray(raw['time-series'])) upstreamShape();
          const dates = new Set<string>();
          for (const sample of raw['time-series']) {
            const observation = normalizeScore(sample, current.cve);
            if (observation.date >= current.date || dates.has(observation.date)) upstreamShape();
            dates.add(observation.date);
            if (observation.date >= shiftDate(current.date, -30)) series.push(observation);
          }
          series.sort((a, b) => a.date.localeCompare(b.date));
        }
        items.push({ current, series });
      }
    }
    const returned = new Set(items.map((item) => item.current.cve));
    const invalid = new Map(batch.unscoredCves.map((item) => [item.cve, item]));
    const accounting = {
      requestedCount: batch.requestedCount,
      processedCount: batch.processedCount,
      duplicateCount: batch.duplicateCount,
      deferredCves: batch.deferredCves,
      unscoredCves: batch.processedCves
        .filter((cve) => !returned.has(cve))
        .map((cve) => {
          const entry = invalid.get(cve) ?? {
            cve,
            reason: 'not_returned' as const,
            guidance: missingGuidance,
          };
          return {
            ...entry,
            guidance: entry.guidance.replaceAll(
              'epss_get_scores',
              history ? 'epss_get_timeseries' : 'epss_get_scores',
            ),
          };
        }),
    };
    const { provenance, notices } = await this.attribute(
      items.flatMap((item) => [item.current, ...item.series]),
      date,
      ctx,
      signal,
      items.map((item) => item.current.date),
    );
    if (batch.processedCount === 0)
      notices.push(
        'Batch complete. The batchOffset is at or beyond the normalized unique input count; use an earlier batchOffset to inspect previous entries.',
      );
    else if (!items.length) notices.push(coverageNotice);
    if (batch.deferredCves.length)
      notices.push(
        'Some CVEs were deferred by the per-call workload limit; resume with nextBatchOffset as batchOffset, the original cves and returned score date.',
      );
    return { items, accounting, provenance, notices };
  }

  private async attribute(
    scores: Score[],
    requestedDate: string | undefined,
    ctx: Context,
    signal: AbortSignal,
    anchorDates?: string[],
  ): Promise<{ provenance: Provenance; notices: string[] }> {
    const scoreDates = [...new Set(anchorDates ?? scores.map((score) => score.date))].sort();
    const notices: string[] = [];
    let header: HeaderMetadata | undefined;
    let headerFailed = false;
    if (scores.length) {
      try {
        header = await headers.get(ctx, signal);
      } catch {
        checkSignal(signal);
        headerFailed = true;
        notices.push(`Current model-header metadata could not be verified. ${metadataRecovery}`);
      }
    }
    for (const score of scores) {
      if (header?.scoreDate === score.date) {
        score.modelVersion = header.modelVersion;
        score.modelVersionSource = 'csv_header';
      } else if (
        (requestedDate || (anchorDates && !anchorDates.includes(score.date))) &&
        score.date <= MODEL_SCHEDULE_VERIFIED_AT
      ) {
        const model = MODEL_TRANSITIONS.findLast((model) => model.date <= score.date);
        if (model) {
          score.modelVersionSource = 'published_schedule';
          if ('version' in model) score.modelVersion = model.version;
        }
      }
    }
    const anchorDate = scoreDates[0];
    const matching = anchorDate ? scores.find((score) => score.date === anchorDate) : undefined;
    let modelMetadata: ModelMetadata = {
      status: 'unavailable',
      explanation: scores.length
        ? 'No matching verified current CSV header or eligible historical schedule attribution.'
        : 'No returned score dates to attribute.',
    };
    if (matching?.modelVersionSource === 'csv_header')
      modelMetadata = {
        status: 'verified',
        sourceUrl: HEADER_URL,
        scoreDate: matching.date,
        ...(matching.modelVersion ? { modelVersion: matching.modelVersion } : {}),
      };
    else if (matching?.modelVersionSource === 'published_schedule')
      modelMetadata = {
        status: 'inferred',
        sourceUrl: MODEL_SCHEDULE_URL,
        scoreDate: matching.date,
        ...(matching.modelVersion ? { modelVersion: matching.modelVersion } : {}),
        explanation: `Inferred from the published schedule verified ${MODEL_SCHEDULE_VERIFIED_AT}; EPSS v1 has no claimed version string.${headerFailed ? ' Current CSV-header verification failed.' : ''}`,
      };
    else if (scores.length && !headerFailed)
      notices.push(
        `The current CSV header does not verify the returned score date. ${metadataRecovery}`,
      );
    return {
      provenance: {
        source: 'FIRST EPSS',
        apiUrl: API_URL,
        retrievedAt: new Date().toISOString(),
        ...(requestedDate ? { requestedDate } : {}),
        scoreDates,
        modelMetadata,
      },
      notices,
    };
  }
}

let service: EpssService | undefined;
/** Initialize the process-local public lookup service without user-data storage. */
export function initEpssService(): void {
  service = new EpssService();
}
/** Access the initialized service. */
export function getEpssService(): EpssService {
  if (!service) throw new Error('EpssService not initialized; call initEpssService in setup.');
  return service;
}
/** Release the shared API request queue on application shutdown. */
export function disposeEpssService(): void {
  pacer.dispose();
  service = undefined;
}
