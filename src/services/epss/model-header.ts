/**
 * @fileoverview Bounded first-line CSV metadata with isolated shared-read cancellation.
 * @module services/epss/model-header
 */
import { lookup, resolve4, resolve6 } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';
import { createGunzip } from 'node:zlib';
import type { Context } from '@cyanheads/mcp-ts-core';
import { McpError } from '@cyanheads/mcp-ts-core/errors';
import { fetchWithTimeout } from '@cyanheads/mcp-ts-core/utils';
import { checkSignal } from './errors.js';
import { isCalendarDate } from './normalization.js';
import type { HeaderMetadata } from './types.js';

/** FIRST's current public score-file header source. */
export const HEADER_URL = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz';
const maxCachedHeaders = 64;
const headerTtlMs = 900000;
const redirectStatuses = [301, 302, 303, 307, 308];

/** Public source for a validated score date, or the current file when omitted. */
export function modelHeaderUrl(scoreDate?: string): string {
  return scoreDate ? HEADER_URL.replace('current', scoreDate) : HEADER_URL;
}
const blocked = new BlockList();
for (const [address, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
] as const)
  blocked.addSubnet(address, prefix, 'ipv4');
for (const [address, prefix] of [
  ['::', 128],
  ['::1', 128],
  ['fc00::', 7],
  ['fe80::', 10],
  ['ff00::', 8],
] as const)
  blocked.addSubnet(address, prefix, 'ipv6');

/** The fixed download allowlist is checked alongside both DNS resolver paths. */
async function publicHeaderUrl(url: URL, signal: AbortSignal): Promise<void> {
  if (
    url.origin !== 'https://epss.empiricalsecurity.com' ||
    !/^\/epss_scores-(?:current|\d{4}-\d{2}-\d{2})\.csv\.gz$/.test(url.pathname) ||
    url.search ||
    url.username ||
    url.password
  )
    throw new Error('Unsupported model-header redirect.');
  const answers = await waitForSignal(
    Promise.allSettled([
      lookup(url.hostname, { all: true }),
      resolve4(url.hostname),
      resolve6(url.hostname),
    ]),
    signal,
  );
  checkSignal(signal);
  const addresses = answers.flatMap((answer) =>
    answer.status === 'fulfilled'
      ? answer.value.map((item) => (typeof item === 'string' ? item : item.address))
      : [],
  );
  if (
    !addresses.length ||
    addresses.some((address) => blocked.check(address, isIP(address) === 4 ? 'ipv4' : 'ipv6'))
  )
    throw new Error('Model-header address is not public.');
}

async function waitForSignal<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  checkSignal(signal);
  let abort: () => void = () => {};
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        abort = () => {
          try {
            checkSignal(signal);
          } catch (error) {
            reject(error);
          }
        };
        signal.addEventListener('abort', abort, { once: true });
      }),
    ]);
  } finally {
    signal.removeEventListener('abort', abort);
  }
}

async function readFirstLine(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  signal: AbortSignal,
): Promise<string> {
  async function* input(): AsyncGenerator<Uint8Array> {
    let remaining = 65536;
    while (true) {
      checkSignal(signal);
      const result = await waitForSignal(reader.read(), signal);
      if (result.done) return;
      for (let offset = 0; offset < result.value.length; ) {
        const size = Math.min(1024, result.value.length - offset, remaining);
        yield result.value.subarray(offset, offset + size);
        offset += size;
        remaining -= size;
        if (!remaining) throw new Error('Model-header compressed-byte budget exceeded.');
      }
    }
  }
  const chunks = input();
  let prefix = Buffer.alloc(0);
  while (prefix.length < 2) {
    const next = await chunks.next();
    if (next.done) break;
    prefix = Buffer.concat([prefix, next.value]);
  }
  if (!prefix.length) throw new Error('Empty model-header stream.');
  const parts: Uint8Array[] = [];
  let length = 0;
  let complete = false;
  let tooLong = false;
  const collect = (chunk: Uint8Array) => {
    if (complete || tooLong) return;
    const newline = chunk.indexOf(10);
    const line = newline >= 0 ? chunk.subarray(0, newline) : chunk;
    length += line.length;
    tooLong = length > 16384;
    if (tooLong) return;
    parts.push(line);
    complete = newline >= 0;
  };
  const gunzip =
    prefix[0] === 0x1f && prefix[1] === 0x8b ? createGunzip({ chunkSize: 1024 }) : undefined;
  gunzip?.on('data', collect);
  try {
    let chunk: Uint8Array = prefix;
    while (true) {
      checkSignal(signal);
      if (gunzip) {
        // Wait for this input's output before allowing the next bounded slice into zlib.
        await waitForSignal(
          new Promise<void>((resolve, reject) => {
            gunzip.once('error', reject);
            gunzip.write(chunk, (error) => {
              if (error) return; // The stream emits the error after the write callback.
              gunzip.removeListener('error', reject);
              resolve();
            });
          }),
          signal,
        );
      } else collect(chunk);
      if (tooLong) throw new Error('Model-header decompressed-byte budget exceeded.');
      if (complete) return Buffer.concat(parts).toString('utf8');
      const next = await chunks.next();
      if (next.done) throw new Error('Model-header first line is incomplete.');
      chunk = next.value;
    }
  } finally {
    gunzip?.destroy();
  }
}

async function downloadHeader(
  sourceUrl: string,
  ctx: Context,
  controller: AbortController,
): Promise<HeaderMetadata> {
  const signal = controller.signal;
  const deadline = Date.now() + 5000;
  const timer = setTimeout(
    () => controller.abort(new DOMException('Metadata deadline expired.', 'TimeoutError')),
    5000,
  );
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  try {
    let url = new URL(sourceUrl);
    let response: Response | undefined;
    for (let hop = 0; hop <= 5; hop++) {
      await publicHeaderUrl(url, signal);
      try {
        response = await fetchWithTimeout(url, Math.max(1, deadline - Date.now()), ctx, {
          signal,
          redirect: 'manual',
          errorBodyLimit: 0,
          errorHeaders: ['location'],
          expectedStatuses: redirectStatuses,
        });
        break;
      } catch (error) {
        checkSignal(signal);
        if (
          !(error instanceof McpError) ||
          !redirectStatuses.includes(Number(error.data?.status)) ||
          hop === 5
        )
          throw error;
        const headers = error.data?.headers;
        const location =
          headers && typeof headers === 'object' && 'location' in headers
            ? headers.location
            : undefined;
        if (typeof location !== 'string')
          throw new Error('Missing model-header redirect location.');
        url = new URL(location, url);
      }
    }
    if (!response?.body) throw new Error('Missing model-header stream.');
    reader = response.body.getReader();
    const header = await readFirstLine(reader, signal);
    const version = /(?:^|[#,\s])model_version\s*:\s*([^,\s]+)/.exec(header)?.[1];
    const timestamp = /(?:^|[#,\s])score_date\s*:\s*([^,\s]+)/.exec(header)?.[1];
    const date = timestamp?.slice(0, 10);
    if (
      !version ||
      !/^v\d{4}\.\d{2}\.\d{2}$/.test(version) ||
      !date ||
      !isCalendarDate(date) ||
      !timestamp ||
      !Number.isFinite(Date.parse(timestamp))
    )
      throw new Error('Invalid model-header comment.');
    return { scoreDate: date, modelVersion: version };
  } finally {
    clearTimeout(timer);
    controller.abort();
    if (reader) {
      void reader.cancel().catch(() => {});
      reader.releaseLock();
    }
  }
}

/** Bounded public metadata cache that coalesces downloads by requested date. */
export class ModelHeaderCache {
  private cached = new Map<string, { value: HeaderMetadata; expires: number }>();
  private pending = new Map<
    string,
    { controller: AbortController; promise: Promise<HeaderMetadata>; waiters: number }
  >();

  /** Resolve metadata without allowing one waiter to cancel another's download. */
  async get(ctx: Context, signal: AbortSignal, scoreDate?: string): Promise<HeaderMetadata> {
    checkSignal(signal);
    const url = modelHeaderUrl(scoreDate);
    const cached = this.cached.get(url);
    if (cached && cached.expires > Date.now()) return cached.value;
    this.cached.delete(url);
    let entry = this.pending.get(url);
    if (!entry) {
      const controller = new AbortController();
      const promise = downloadHeader(url, ctx, controller)
        .then((value) => {
          if (
            this.pending.get(url)?.controller === controller &&
            (!scoreDate || value.scoreDate === scoreDate)
          ) {
            this.cached.set(url, { value, expires: Date.now() + headerTtlMs });
            const oldest = this.cached.keys().next();
            if (this.cached.size > maxCachedHeaders && !oldest.done)
              this.cached.delete(oldest.value);
          }
          return value;
        })
        .finally(() => {
          if (this.pending.get(url)?.controller === controller) this.pending.delete(url);
        });
      entry = { controller, promise, waiters: 0 };
      this.pending.set(url, entry);
    }
    const download = entry;
    download.waiters++;
    return await waitForSignal(download.promise, signal).finally(() => {
      download.waiters--;
      if (!download.waiters && this.pending.get(url) === download) {
        this.pending.delete(url);
        download.controller.abort();
      }
    });
  }
}
