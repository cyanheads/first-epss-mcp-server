/**
 * @fileoverview Exact caller-surface byte budgeting and lossless batch continuation.
 * @module mcp-server/tools/response-budget
 */
import type { ContentBlock } from '@cyanheads/mcp-ts-core';
import { serializationError } from '@cyanheads/mcp-ts-core/errors';
import type { AnyToolDefinition } from '@cyanheads/mcp-ts-core/tools';
import { escapeMarkdownInline } from '@cyanheads/mcp-ts-core/utils';
import { normalizeCve } from '../../services/epss/index.js';

/** Maximum UTF-8 bytes for each JSON-serialized caller surface. */
export const RESPONSE_BUDGET_IN_BYTES = 65536;
const encoder = new TextEncoder();

/** Measure JSON escaping and UTF-8 encoding, including outer array/object syntax. */
export function serializedBytes(value: unknown): number {
  return encoder.encode(JSON.stringify(value)).byteLength;
}

/** Mirror the framework's generic notice enrichment trailer for ctx.enrich({notice}). */
export function measuredSurfaces(
  domain: Record<string, unknown>,
  content: ContentBlock[],
  notice?: string,
) {
  return {
    content: notice
      ? [...content, { type: 'text', text: `\n\n**notice:** ${escapeMarkdownInline(notice)}` }]
      : content,
    structuredContent: notice ? { ...domain, notice } : domain,
  };
}

/** Find the largest fitting prefix with logarithmically bounded full measurements. */
export function fittingPrefix(length: number, fits: (count: number) => boolean): number {
  let low = 0;
  let high = length;
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    if (fits(middle)) low = middle;
    else high = middle - 1;
  }
  return low;
}

/** Apply the batch budget after domain derivation and before framework enrichment. */
export function withBatchBudget<T extends AnyToolDefinition>(definition: T): T {
  const handler = definition.handler;
  const format = definition.format;
  if (!format) throw serializationError('Batch response budgeting requires a formatter.');
  return {
    ...definition,
    async handler(input, ctx) {
      const raw = await handler(input, ctx);
      // AnyToolDefinition erases the concrete handler types at this shared seam.
      const notices = raw.notices as string[];
      const domain: Record<string, unknown> = { ...raw };
      delete domain.notices;
      const submitted = input.cves as (string | { cve: string })[];
      const original = [
        ...new Set(
          submitted.map((entry) => normalizeCve(typeof entry === 'string' ? entry : entry.cve)),
        ),
      ];
      const offset = input.batchOffset as number;
      const processed = domain.processedCount as number;
      const processedCves = original.slice(offset, offset + processed);
      const deferred = original.slice(offset + processed);
      const baseNotice = notices.join('\n');
      const budgetNotice =
        'Response byte budget reached. Resume with nextBatchOffset as batchOffset, the original cves, the returned score date (or requested date when no scores were returned), and the original severity inputs and policy. Withheld entries were already processed; deferred entries were not queried.';

      const assemble = (count: number, previews: number) => {
        const retained = new Set(processedCves.slice(0, count));
        const withheld = processedCves.slice(count);
        const deferredPreview = deferred.slice(0, previews);
        const withheldPreview = withheld.slice(0, Math.max(0, previews - deferred.length));
        const limited = count < processed || previews < withheld.length + deferred.length;
        const next = offset + count;
        const value: Record<string, unknown> = {
          ...domain,
          batchOffset: offset,
          returnedCount: count,
          withheldCount: withheld.length,
          withheldCves: withheldPreview,
          withheldCvesComplete: withheldPreview.length === withheld.length,
          deferredCount: deferred.length,
          deferredCves: deferredPreview,
          deferredCvesComplete: deferredPreview.length === deferred.length,
          budgetLimited: limited,
          ...(next < original.length ? { nextBatchOffset: next } : {}),
          unscoredCves: (domain.unscoredCves as { cve: string }[]).filter((entry) =>
            retained.has(entry.cve),
          ),
        };
        if (Array.isArray(domain.scores))
          value.scores = domain.scores.filter((entry: { cve: string }) => retained.has(entry.cve));
        if (Array.isArray(domain.items))
          value.items = domain.items.filter((entry: { current: { cve: string } }) =>
            retained.has(entry.current.cve),
          );
        if (Array.isArray(domain.epssOnly))
          value.epssOnly = domain.epssOnly.filter((entry: { cve: string }) =>
            retained.has(entry.cve),
          );
        if (domain.tiers)
          value.tiers = Object.fromEntries(
            Object.entries(domain.tiers as Record<string, { cve: string }[]>).map(([key, rows]) => [
              key,
              rows.filter((entry) => retained.has(entry.cve)),
            ]),
          );
        const notice = [baseNotice, ...(limited ? [budgetNotice] : [])].filter(Boolean).join('\n');
        const surfaces = measuredSurfaces(value, format(value), notice);
        return {
          value,
          notice,
          fits:
            serializedBytes(surfaces.content) <= RESPONSE_BUDGET_IN_BYTES &&
            serializedBytes(surfaces.structuredContent) <= RESPONSE_BUDGET_IN_BYTES,
        };
      };

      // Probe the complete response first; most one-item calls need one measurement.
      let fitted = assemble(processed, deferred.length);
      if (!fitted.fits) {
        // Keep a complete deferred list whenever it fits alongside progress.
        const reserved = assemble(Math.min(1, processed), deferred.length).fits
          ? deferred.length
          : 0;
        const count = fittingPrefix(processed, (n) => assemble(n, reserved).fits);
        const previews = fittingPrefix(
          processed - count + deferred.length,
          (n) => assemble(count, n).fits,
        );
        fitted = assemble(count, previews);
        if (!fitted.fits || (processed > 0 && count === 0))
          throw serializationError(
            'A single complete EPSS entry exceeds the response byte budget.',
          );
      }
      if (fitted.notice) ctx.enrich({ notice: fitted.notice });
      return fitted.value;
    },
  };
}
