/**
 * @fileoverview Public EPSS domain contracts.
 * @module services/epss/types
 */
/** Daily exploitation forecast, with explicitly attributed model metadata. */
export interface Score {
  cve: string;
  date: string;
  epss: number;
  modelVersion?: string;
  modelVersionSource: 'csv_header' | 'published_schedule' | 'unavailable';
  percentile: number;
}
/** Model attribution for a score snapshot. */
export interface ModelMetadata {
  explanation?: string;
  modelVersion?: string;
  scoreDate?: string;
  sourceUrl?: string;
  status: 'verified' | 'inferred' | 'unavailable';
}
/** Source and dates for returned forecasts. */
export interface Provenance {
  apiUrl: string;
  modelMetadata: ModelMetadata;
  requestedDate?: string;
  retrievedAt: string;
  scoreDates: string[];
  source: 'FIRST EPSS';
}
/** Identifier lacking a returned usable forecast. */
export interface UnscoredCve {
  cve: string;
  guidance: string;
  reason: 'invalid_format' | 'not_returned';
}
/** Bounded canonical batch accounting. */
export interface BatchAccounting {
  deferredCves: string[];
  duplicateCount: number;
  processedCount: number;
  requestedCount: number;
  unscoredCves: UnscoredCve[];
}
/** Score/history request. */
export interface BatchInput {
  cves: readonly string[];
  date?: string;
}
/** Anchor and preceding observations, before derived history policy. */
export interface RawTimeseriesItem {
  current: Score;
  series: Score[];
}
/** Score response. */
export interface ScoresResult extends BatchAccounting {
  notices: string[];
  provenance: Provenance;
  scores: Score[];
}
/** Raw normalized history response. */
export interface TimeseriesResult extends BatchAccounting {
  items: RawTimeseriesItem[];
  notices: string[];
  provenance: Provenance;
}
/** Inclusive discovery bounds and candidate paging. */
export interface ThresholdInput {
  addedWithinDays?: number;
  date?: string;
  limit?: number;
  maxEpss?: number;
  maxPercentile?: number;
  minEpss?: number;
  minPercentile?: number;
  offset?: number;
  year?: number;
}
/** One upstream candidate page. */
export interface ThresholdResult {
  filters: ThresholdInput;
  notices: string[];
  pagination: {
    offset: number;
    limit: number;
    examinedCount: number;
    returnedCount: number;
    candidateTotal: number;
    total: number | null;
    totalRelation: 'exact' | 'unknown';
    hasMore: boolean;
    nextOffset?: number;
  };
  provenance: Provenance;
  scores: Score[];
}
/** Successfully parsed CSV comment. */
export interface HeaderMetadata {
  modelVersion: string;
  scoreDate: string;
}
