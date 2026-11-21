/**
 * @fileoverview Prioritization severity validation and bounded caller diagnostics.
 * @module mcp-server/tools/prioritization-conflicts
 */
import type { HandlerContext } from '@cyanheads/mcp-ts-core';
import { isCve, normalizeCve } from '../../services/epss/index.js';
import { RESPONSE_BUDGET_IN_BYTES, serializedBytes } from './response-budget.js';

/** Recovery shared by the declared error and each diagnostic form. */
export const conflictRecovery =
  'Call epss_prioritize_cves again with one caller-supplied severity value per CVE.';

/** Index severity by normalized CVE or report conflicts across the complete submission. */
export function validateSeverities(
  entries: readonly { cve: string; cvssBaseScore?: number | undefined }[],
  ctx: Pick<HandlerContext<'conflicting_cvss'>, 'fail' | 'requestId'>,
): Map<string, number | undefined> {
  const severity = new Map<string, number | undefined>();
  const submittedValues = new Map<string, Map<number | null, number>>();
  for (const [row, entry] of entries.entries()) {
    const cve = normalizeCve(entry.cve);
    severity.set(cve, entry.cvssBaseScore);
    let values = submittedValues.get(cve);
    if (!values) {
      values = new Map();
      submittedValues.set(cve, values);
    }
    const value = entry.cvssBaseScore ?? null;
    if (!values.has(value)) values.set(value, row);
  }
  const conflictGroups = [...submittedValues].filter(([, values]) => values.size > 1);
  const conflictCount = conflictGroups.length;
  if (conflictCount === 0) return severity;

  const message = `Found ${conflictCount} conflicting CVE severity groups in the submission.`;
  const conflicts = conflictGroups.map(([cve, values]) => ({
    ...(isCve(cve) ? { cve } : { rows: [...values.values()] }),
    values: [...values.keys()],
  }));
  const literals = conflicts.flatMap((conflict) => ('cve' in conflict ? [conflict.cve] : []));
  const details = conflicts.map(
    (conflict) =>
      `${'cve' in conflict ? conflict.cve : `Rows ${conflict.rows.join(', ')}`}: ${conflict.values.map(String).join(', ')}`,
  );
  const namedFailure = ctx.fail(
    'conflicting_cvss',
    message,
    {
      conflictCount,
      conflicts,
      recovery: {
        hint: `${conflictRecovery} Null means a missing score. Row positions are zero-based.\n${details.join('\n')}`,
      },
    },
    { literals },
  );
  /** The structured envelope repeats the diagnostics and is larger than the text envelope. */
  const namedEnvelope = {
    error: {
      code: namedFailure.code,
      message: namedFailure.message,
      data: { ...namedFailure.data, requestId: ctx.requestId },
    },
  };
  if (serializedBytes(namedEnvelope) <= RESPONSE_BUDGET_IN_BYTES) throw namedFailure;

  const conflictRows = conflictGroups.map(([, values]) => [...values.values()]);
  throw ctx.fail('conflicting_cvss', message, {
    conflictCount,
    conflictRows,
    recovery: {
      hint: `${conflictRecovery} Each semicolon-separated group lists zero-based positions in the submitted cves array, one row per distinct severity. Rows: ${conflictRows.map((rows) => rows.join(',')).join(';')}`,
    },
  });
}
