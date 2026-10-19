/**
 * @fileoverview Safe error projection contracts.
 * @module tests/services/epss/errors.test
 */
import { JsonRpcErrorCode, McpError, validationError } from '@cyanheads/mcp-ts-core/errors';
import { describe, expect, it } from 'vitest';
import { safeError } from '@/services/epss/errors.js';
import { upstreamShape } from '@/services/epss/normalization.js';

describe('safe error projection', () => {
  it('redacts arbitrary transport messages and body fields through repeated projection', () => {
    const error = safeError(
      new McpError(JsonRpcErrorCode.RateLimited, 'private upstream body', {
        status: 429,
        retryAfter: '10',
        retryAttempts: 2,
        body: 'private',
        retryable: true,
      }),
      'scores',
    );
    const again = safeError(error, 'scores');
    expect(again.code).toBe(JsonRpcErrorCode.RateLimited);
    expect(again.data).toMatchObject({
      status: 429,
      retryAfter: '10',
      retryAttempts: 2,
      retryable: true,
    });
    expect(JSON.stringify(again)).not.toContain('private');
  });
  it('preserves locally authored shape messages and nonretryable classification', () => {
    let error: unknown;
    try {
      upstreamShape();
    } catch (caught) {
      error = caught;
    }
    const projected = safeError(safeError(error, 'scores'), 'scores');
    expect(projected.message).toBe('FIRST EPSS returned inconsistent or invalid score data.');
    expect(projected.data).toMatchObject({ reason: 'upstream_shape', retryable: false });
  });
  it('does not trust arbitrary errors claiming a local reason', () => {
    const projected = safeError(validationError('private', { reason: 'upstream_shape' }), 'scores');
    expect(projected.message).not.toContain('private');
  });
  it('names HTTP status without upstream text', () => {
    expect(
      safeError(
        new McpError(JsonRpcErrorCode.ValidationError, 'private', { status: 422 }),
        'scores',
      ).message,
    ).toContain('HTTP 422');
  });
});
