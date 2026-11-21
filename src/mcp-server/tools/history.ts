/**
 * @fileoverview Exact-calendar history comparisons and model-boundary policy.
 * @module mcp-server/tools/history
 */
import {
  FIRST_SCORE_DATE,
  MODEL_SCHEDULE_VERIFIED_AT,
  MODEL_TRANSITIONS,
  type RawTimeseriesItem,
  shiftDate,
} from '../../services/epss/index.js';

/** Derive history without interpolating missing observations or attributing causality. */
export function deriveHistory(item: RawTimeseriesItem) {
  const { current, series } = item;
  const byDate = new Map(series.map((score) => [score.date, score]));
  const thirtyDate = shiftDate(current.date, -30);
  const expected = Array.from({ length: 30 }, (_, i) => shiftDate(thirtyDate, i));
  const observed = series.toSorted((a, b) => a.date.localeCompare(b.date));
  const first = observed[0];
  const last = observed.at(-1);
  const start = first?.date ?? current.date;
  const boundaries = MODEL_TRANSITIONS.flatMap<{
    date: string;
    fromModel: string;
    toModel: string;
  }>((model, i) => {
    const previous = MODEL_TRANSITIONS[i - 1];
    return previous && model.date > start && model.date <= current.date
      ? [{ date: model.date, fromModel: previous.label, toModel: model.label }]
      : [];
  });
  const verifiedEndpoints =
    first?.modelVersionSource === 'csv_header' &&
    current.modelVersionSource === 'csv_header' &&
    first.modelVersion &&
    current.modelVersion
      ? {
          earlierDate: first.date,
          earlierVersion: first.modelVersion,
          laterDate: current.date,
          laterVersion: current.modelVersion,
        }
      : undefined;
  const adjacent = shiftDate(start, 1) === current.date;
  const modelChange =
    verifiedEndpoints && verifiedEndpoints.earlierVersion !== verifiedEndpoints.laterVersion
      ? verifiedEndpoints
      : undefined;
  if (modelChange && adjacent && !boundaries.length)
    boundaries.push({
      date: modelChange.laterDate,
      fromModel: modelChange.earlierVersion,
      toModel: modelChange.laterVersion,
    });
  const coverageIncomplete =
    start < current.date &&
    current.date > MODEL_SCHEDULE_VERIFIED_AT &&
    !(verifiedEndpoints && adjacent);
  const sevenDate = shiftDate(current.date, -7);
  const previousAnchorDate = shiftDate(thirtyDate, -1);
  const seven = byDate.get(sevenDate);
  const thirty = byDate.get(thirtyDate);
  const baselines = [
    { days: 7, date: sevenDate, score: seven },
    { days: 30, date: thirtyDate, score: thirty },
  ];
  const deltaComparisons = baselines.flatMap(({ days, date, score }) =>
    score
      ? [
          {
            days,
            baselineDate: date,
            endpointDate: current.date,
            crossesModelBoundary:
              boundaries.some((boundary) => boundary.date > date) ||
              (modelChange !== undefined && date <= modelChange.earlierDate),
          },
        ]
      : [],
  );
  const peak = Math.max(current.epss, ...series.map((score) => score.epss));
  return {
    current,
    series: observed,
    requestedWindow: {
      startDate: thirtyDate,
      endDate: shiftDate(current.date, -1),
    },
    ...(previousAnchorDate >= FIRST_SCORE_DATE ? { previousAnchorDate } : {}),
    ...(first && last
      ? {
          observedWindow: {
            startDate: first.date,
            endDate: last.date,
            observationCount: observed.length,
          },
        }
      : {}),
    missingDates: expected.filter((date) => !byDate.has(date)),
    ...(seven ? { delta7d: Number((current.epss - seven.epss).toFixed(9)) } : {}),
    ...(thirty ? { delta30d: Number((current.epss - thirty.epss).toFixed(9)) } : {}),
    unavailableDeltas: baselines.filter(({ score }) => !score).map(({ days }) => days),
    deltaComparisons,
    peak: {
      epss: peak,
      dates: [...series, current]
        .filter((score) => score.epss === peak)
        .map((score) => score.date)
        .sort(),
    },
    modelBoundariesCrossed: boundaries,
    modelBoundaryCoverageThrough: MODEL_SCHEDULE_VERIFIED_AT,
    ...(coverageIncomplete ? { modelBoundaryCoverageIncomplete: true as const } : {}),
    ...(modelChange && !adjacent ? { modelBoundaryEvidence: modelChange } : {}),
  };
}
