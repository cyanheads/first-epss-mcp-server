/**
 * @fileoverview Exact-calendar history comparisons and model-boundary policy.
 * @module mcp-server/tools/history
 */
import {
  MODEL_SCHEDULE_VERIFIED_AT,
  MODEL_TRANSITIONS,
  type RawTimeseriesItem,
  shiftDate,
} from '../../services/epss/index.js';

/** Derive history without interpolating missing observations or attributing causality. */
export function deriveHistory(item: RawTimeseriesItem) {
  const { current, series } = item;
  const byDate = new Map(series.map((score) => [score.date, score]));
  const expected = Array.from({ length: 30 }, (_, i) => shiftDate(current.date, i - 30));
  const observed = [...series].sort((a, b) => a.date.localeCompare(b.date));
  const first = observed[0];
  const last = observed.at(-1);
  const start = first?.date ?? current.date;
  const boundaries = MODEL_TRANSITIONS.flatMap((model, i) => {
    const previous = MODEL_TRANSITIONS[i - 1];
    return previous && model.date > start && model.date <= current.date
      ? [{ date: model.date, fromModel: previous.label, toModel: model.label }]
      : [];
  });
  const deltaComparisons = [7, 30].flatMap((days) => {
    const date = shiftDate(current.date, -days);
    return byDate.has(date)
      ? [
          {
            days,
            baselineDate: date,
            endpointDate: current.date,
            crossesModelBoundary: MODEL_TRANSITIONS.some(
              (m, i) => i > 0 && m.date > date && m.date <= current.date,
            ),
          },
        ]
      : [];
  });
  const peak = Math.max(current.epss, ...series.map((score) => score.epss));
  const seven = byDate.get(shiftDate(current.date, -7));
  const thirty = byDate.get(shiftDate(current.date, -30));
  return {
    current,
    series: observed,
    requestedWindow: {
      startDate: shiftDate(current.date, -30),
      endDate: shiftDate(current.date, -1),
    },
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
    ...(seven ? { delta7d: current.epss - seven.epss } : {}),
    ...(thirty ? { delta30d: current.epss - thirty.epss } : {}),
    unavailableDeltas: [7, 30].filter((days) => !byDate.has(shiftDate(current.date, -days))),
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
  };
}
