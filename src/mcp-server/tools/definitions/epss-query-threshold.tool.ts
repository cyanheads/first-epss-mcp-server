/**
 * @fileoverview Inclusive FIRST EPSS discovery with candidate pagination.
 * @module mcp-server/tools/definitions/epss-query-threshold.tool
 */
import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getEpssService } from '../../../services/epss/index.js';
import { provenanceText, scoresText } from '../format.js';
import {
  dateSchema,
  noticeEnrichment,
  probabilitySchema,
  provenanceSchema,
  scoreSchema,
} from '../schemas.js';

const filterShape = {
  minEpss: probabilitySchema.optional().describe('Inclusive minimum EPSS probability.'),
  maxEpss: probabilitySchema.optional().describe('Inclusive maximum EPSS probability.'),
  minPercentile: probabilitySchema
    .optional()
    .describe('Inclusive minimum population percentile rank.'),
  maxPercentile: probabilitySchema
    .optional()
    .describe('Inclusive maximum population percentile rank.'),
  year: z
    .number()
    .int()
    .min(1999)
    .max(new Date().getUTCFullYear())
    .optional()
    .describe('Exact year in the CVE identifier; candidate pages may contain no matches.'),
  addedWithinDays: z
    .number()
    .int()
    .min(1)
    .max(100000)
    .optional()
    .describe(
      'Dataset-addition recency relative to upstream present, independent of historical date.',
    ),
  date: dateSchema,
};

/** Discover one candidate page; exact-year totals remain unknown. */
export const epssQueryThreshold = tool('epss_query_threshold', {
  description:
    'Discover CVEs using inclusive EPSS or percentile bounds, CVE year or dataset-addition recency; filters intersect and at least one is required. Examine one candidate page ordered by EPSS descending. Year filtering can return an empty page with nextOffset; candidateTotal is a broad-query total, not an exact-year total. Continue with the same filters, limit, returned score date and nextOffset.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
  input: z.object({
    ...filterShape,
    limit: z
      .number()
      .int()
      .min(1)
      .max(10000)
      .default(100)
      .describe('Maximum candidates examined per page, before exact-year filtering.'),
    offset: z
      .number()
      .int()
      .min(0)
      .default(0)
      .describe('Candidate-space offset; use returned nextOffset for continuation.'),
  }),
  output: z.object({
    scores: z.array(scoreSchema).describe('Retained records from this candidate page.'),
    filters: z
      .object({
        ...filterShape,
        limit: z.number().optional().describe('Applied candidate page limit.'),
        offset: z.number().optional().describe('Applied candidate offset.'),
      })
      .describe('Applied filters; combine with provenance scoreDates to pin continuation.'),
    pagination: z
      .object({
        offset: z.number().int().describe('Candidate offset examined.'),
        limit: z.number().int().describe('Candidate page limit.'),
        examinedCount: z.number().int().describe('Candidates examined before year filtering.'),
        returnedCount: z.number().int().describe('Records retained after filtering.'),
        candidateTotal: z.number().int().describe('Exact broad-query candidate count.'),
        total: z
          .number()
          .int()
          .nullable()
          .describe('Exact total without a year filter; null with year.'),
        totalRelation: z.enum(['exact', 'unknown']).describe('Whether total is exact or unknown.'),
        hasMore: z
          .boolean()
          .describe('More candidate pages exist; not a guarantee of more year matches.'),
        nextOffset: z.number().int().optional().describe('Candidate continuation offset.'),
      })
      .describe('Candidate pagination accounting.'),
    provenance: provenanceSchema.describe(
      'Snapshot source and model metadata, including dates from filtered-out candidates.',
    ),
  }),
  enrichment: noticeEnrichment,
  errors: [
    {
      reason: 'invalid_filter_combination',
      code: JsonRpcErrorCode.ValidationError,
      thrownBy: 'service',
      when: 'No qualifying filter is supplied or minimum exceeds maximum.',
      retryable: false,
      recovery:
        "Call epss_list_reference with topic='coverage', then call epss_query_threshold with ordered bounds or a year/addition filter.",
    },
    {
      reason: 'upstream_shape',
      code: JsonRpcErrorCode.SerializationError,
      thrownBy: 'service',
      when: 'The candidate envelope, scores, snapshot or pagination are inconsistent.',
      retryable: false,
      recovery:
        "Retry the same tool call once; if it persists, call epss_list_reference with topic='coverage' and do not interpret the response as missing scores.",
    },
  ],
  async handler(input, ctx) {
    const { notices, ...result } = await getEpssService().queryThreshold(
      {
        limit: input.limit,
        offset: input.offset,
        ...(input.minEpss === undefined ? {} : { minEpss: input.minEpss }),
        ...(input.maxEpss === undefined ? {} : { maxEpss: input.maxEpss }),
        ...(input.minPercentile === undefined ? {} : { minPercentile: input.minPercentile }),
        ...(input.maxPercentile === undefined ? {} : { maxPercentile: input.maxPercentile }),
        ...(input.year === undefined ? {} : { year: input.year }),
        ...(input.addedWithinDays === undefined ? {} : { addedWithinDays: input.addedWithinDays }),
        ...(input.date === undefined ? {} : { date: input.date }),
      },
      ctx,
    );
    if (notices.length) ctx.enrich({ notice: notices.join('\n') });
    return result;
  },
  format(result) {
    const p = result.pagination;
    const f = result.filters;
    return [
      {
        type: 'text',
        text: [
          scoresText(result.scores),
          '## Applied filters',
          `minEpss: ${f.minEpss ?? 'unset'}; maxEpss: ${f.maxEpss ?? 'unset'}; minPercentile: ${f.minPercentile ?? 'unset'}; maxPercentile: ${f.maxPercentile ?? 'unset'}`,
          `year: ${f.year ?? 'unset'}; addedWithinDays: ${f.addedWithinDays ?? 'unset'}; date: ${f.date ?? 'latest available'}; limit: ${f.limit ?? 100}; offset: ${f.offset ?? 0}`,
          '## Candidate pagination',
          `offset: ${p.offset}; limit: ${p.limit}; examinedCount: ${p.examinedCount}; returnedCount: ${p.returnedCount}; candidateTotal: ${p.candidateTotal}; total: ${p.total === null ? 'null' : p.total}; totalRelation: ${p.totalRelation}; hasMore: ${p.hasMore}; nextOffset: ${p.nextOffset ?? 'none'}`,
          ...(p.hasMore
            ? [
                `Call epss_query_threshold with the same filters and limit, date=${result.provenance.scoreDates[0]}, offset=${p.nextOffset}.`,
              ]
            : []),
          provenanceText(result.provenance),
        ].join('\n\n'),
      },
    ];
  },
});
