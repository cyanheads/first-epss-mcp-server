/**
 * @fileoverview Bounded daily FIRST EPSS score lookup.
 * @module mcp-server/tools/definitions/epss-get-scores.tool
 */
import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getEpssService } from '../../../services/epss/index.js';
import { accountingText, provenanceText, scoresText } from '../format.js';
import {
  accountingShape,
  cvesSchema,
  dateSchema,
  noticeEnrichment,
  scoreSchema,
} from '../schemas.js';

/** Retrieve current or historical scores with explicit omissions and deferrals. */
export const epssGetScores = tool('epss_get_scores', {
  description:
    'Retrieve latest available or historically dated FIRST EPSS probability and percentile for supplied CVEs. Batch identifiers in one call; the first 500 unique entries are processed and the remainder is returned as deferredCves. Missing scores remain unknown; use epss_list_reference for coverage and interpretation.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
  input: z.object({ cves: cvesSchema, date: dateSchema }),
  output: z.object({
    scores: z.array(scoreSchema).describe('Forecasts ordered by EPSS descending then CVE.'),
    ...accountingShape,
  }),
  enrichment: noticeEnrichment,
  errors: [
    {
      reason: 'upstream_shape',
      code: JsonRpcErrorCode.SerializationError,
      thrownBy: 'service',
      when: 'The upstream envelope, score data, batch completeness or snapshot consistency is invalid.',
      retryable: false,
      recovery:
        "Retry the same tool call once; if it persists, call epss_list_reference with topic='coverage' and do not interpret the response as missing scores.",
    },
  ],
  async handler(input, ctx) {
    const { notices, ...result } = await getEpssService().getScores(
      { cves: input.cves, ...(input.date === undefined ? {} : { date: input.date }) },
      ctx,
    );
    if (notices.length) ctx.enrich({ notice: notices.join('\n') });
    return result;
  },
  format(result) {
    return [
      {
        type: 'text',
        text: [
          scoresText(result.scores),
          accountingText(result, 'epss_get_scores'),
          provenanceText(result.provenance),
        ].join('\n\n'),
      },
    ];
  },
});
