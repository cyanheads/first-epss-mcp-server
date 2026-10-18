/**
 * @fileoverview Bounded first-line CSV metadata with isolated shared-read cancellation.
 * @module services/epss/model-header
 */
import { lookup, resolve4, resolve6 } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';
import { Readable } from 'node:stream';
import { createGunzip } from 'node:zlib';
import type { Context } from '@cyanheads/mcp-ts-core';
import { McpError } from '@cyanheads/mcp-ts-core/errors';
import { fetchWithTimeout } from '@cyanheads/mcp-ts-core/utils';
import { checkSignal } from './errors.js';
import { isCalendarDate } from './normalization.js';
import type { HeaderMetadata } from './types.js';

/** FIRST's current public score-file header source. */
export const HEADER_URL = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz';
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
    url.pathname !== '/epss_scores-current.csv.gz' ||
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

async function downloadHeader(ctx: Context, controller: AbortController): Promise<HeaderMetadata> {
  const signal = controller.signal;
  const deadline = Date.now() + 5000;
  const timer = setTimeout(
    () => controller.abort(new DOMException('Metadata deadline expired.', 'TimeoutError')),
    5000,
  );
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  let source: Readable | undefined;
  let gunzip: ReturnType<typeof createGunzip> | undefined;
  try {
    let url = new URL(HEADER_URL);
    let response: Response | undefined;
    for (let hop = 0; hop <= 5; hop++) {
      await publicHeaderUrl(url, signal);
      try {
        response = await fetchWithTimeout(url, Math.max(1, deadline - Date.now()), ctx, {
          signal,
          redirect: 'manual',
          errorBodyLimit: 0,
          errorHeaders: ['location'],
          expectedStatuses: [301, 302, 303, 307, 308],
        });
        break;
      } catch (error) {
        checkSignal(signal);
        if (
          !(error instanceof McpError) ||
          ![301, 302, 303, 307, 308].includes(Number(error.data?.status)) ||
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
    const ownedReader = reader;
    let inputBytes = 0;
    async function* input(): AsyncGenerator<Uint8Array> {
      while (true) {
        checkSignal(signal);
        const result = await waitForSignal(ownedReader.read(), signal);
        if (result.done) return;
        inputBytes += result.value.byteLength;
        if (inputBytes > 65536) throw new Error('Model-header compressed-byte budget exceeded.');
        yield result.value;
      }
    }
    const iterator = input();
    const first = await iterator.next();
    if (first.done) throw new Error('Empty model-header stream.');
    let prefix = first.value;
    while (prefix.length < 2) {
      const next = await iterator.next();
      if (next.done) break;
      prefix = Buffer.concat([prefix, next.value]);
    }
    async function* prefixed(): AsyncGenerator<Uint8Array> {
      yield prefix;
      yield* iterator;
    }
    source = Readable.from(prefixed());
    let output: AsyncIterable<Uint8Array> = source;
    if (prefix[0] === 0x1f && prefix[1] === 0x8b) {
      gunzip = createGunzip({ chunkSize: 1024 });
      source.on('error', (error) => gunzip?.destroy(error));
      source.pipe(gunzip);
      output = gunzip;
    }
    const abort = () => {
      source?.destroy();
      gunzip?.destroy(new Error('Metadata read aborted.'));
      void ownedReader.cancel().catch(() => {});
    };
    signal.addEventListener('abort', abort, { once: true });
    try {
      const parts: Buffer[] = [];
      let outputBytes = 0;
      for await (const chunk of output) {
        checkSignal(signal);
        const bytes = Buffer.from(chunk);
        const newline = bytes.indexOf(10);
        const line = newline >= 0 ? bytes.subarray(0, newline) : bytes;
        outputBytes += line.length;
        if (outputBytes > 16384) throw new Error('Model-header decompressed-byte budget exceeded.');
        parts.push(line);
        if (newline >= 0) {
          const header = Buffer.concat(parts).toString('utf8');
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
        }
      }
      throw new Error('Model-header first line is incomplete.');
    } finally {
      signal.removeEventListener('abort', abort);
    }
  } finally {
    clearTimeout(timer);
    controller.abort();
    gunzip?.destroy();
    source?.destroy();
    if (reader) {
      void reader.cancel().catch(() => {});
      reader.releaseLock();
    }
  }
}

/** One public cache entry and one shared bounded download. */
export class ModelHeaderCache {
  private cached: { value: HeaderMetadata; expires: number } | undefined;
  private pending:
    | { controller: AbortController; promise: Promise<HeaderMetadata>; waiters: number }
    | undefined;

  /** Resolve metadata without allowing one waiter to cancel another's download. */
  async get(ctx: Context, signal: AbortSignal): Promise<HeaderMetadata> {
    checkSignal(signal);
    if (this.cached && this.cached.expires > Date.now()) return this.cached.value;
    if (!this.pending) {
      const controller = new AbortController();
      const entry = {
        controller,
        promise: Promise.resolve({ scoreDate: '', modelVersion: '' }),
        waiters: 0,
      };
      entry.promise = downloadHeader(ctx, controller)
        .then((value) => {
          this.cached = { value, expires: Date.now() + 900000 };
          return value;
        })
        .finally(() => {
          if (this.pending === entry) this.pending = undefined;
        });
      this.pending = entry;
    }
    const entry = this.pending;
    entry.waiters++;
    return await waitForSignal(entry.promise, signal).finally(() => {
      entry.waiters--;
      if (!entry.waiters && this.pending === entry) {
        this.pending = undefined;
        entry.controller.abort();
      }
    });
  }
}
