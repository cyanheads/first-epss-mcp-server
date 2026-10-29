/**
 * @fileoverview Bundle agent-doc selection in the cleaner and the packaging check:
 * package-root agent trees are stripped, nested runtime `skills/` modules are kept.
 * @module tests/scripts/agent-doc-entry.test
 */
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';

interface CleanMcpb {
  AGENT_DOC_ENTRY: RegExp;
  filterAgentDocEntries(entries: string[]): string[];
}
interface LintPackaging {
  AGENT_DOC_ENTRY: RegExp;
  checkBundleEntries(entries: string[], bundleLabel: string): string[];
}

/**
 * Loaded by URL at run time so neither script joins the typecheck program:
 * `lint-packaging.ts` carries a repository-only fallback import that a consumer
 * `tsc` cannot resolve.
 */
async function loadScript<T>(name: string): Promise<T> {
  return (await import(pathToFileURL(resolve('scripts', name)).href)) as T;
}

const cleaner = await loadScript<CleanMcpb>('clean-mcpb.ts');
const packaging = await loadScript<LintPackaging>('lint-packaging.ts');

/** Runtime modules the MCP SDK imports at startup, plus nested and root-level lookalikes. */
const retained = [
  'node_modules/@modelcontextprotocol/server/dist/ext/skills/index.mjs',
  'node_modules/@modelcontextprotocol/server/dist/ext/skills/node.cjs',
  'node_modules/@modelcontextprotocol/core/dist/ext/skills/index.mjs',
  'node_modules/@modelcontextprotocol/core/dist/ext/skills/index.cjs',
  'node_modules/some-pkg/node_modules/@modelcontextprotocol/server/dist/ext/skills/index.mjs',
  'node_modules/plain-pkg/lib/skills/loader.js',
  'node_modules/@cyanheads/mcp-ts-core/dist/mcp-server/skills.js',
  'skills/epss-guide/SKILL.md',
  'dist/index.js',
];

/** Package-root agent trees, at the top level, under a scope, and below nested node_modules. */
const stripped = [
  'node_modules/@cyanheads/mcp-ts-core/framework-skills/add-tool/SKILL.md',
  'node_modules/@cyanheads/mcp-ts-core/framework-skills/api-utils/references/formatting.md',
  'node_modules/some-pkg/skills/guide/SKILL.md',
  'node_modules/some-pkg/skills/guide/references/notes.md',
  'node_modules/@scope/pkg/skills/guide/notes.md',
  'node_modules/some-pkg/.claude/settings.json',
  'node_modules/@scope/pkg/.agents/skills/guide/notes.md',
  'node_modules/outer/node_modules/@scope/inner/skills/guide/notes.md',
  'node_modules/outer/node_modules/inner/.claude/skills/guide/notes.md',
  'node_modules/some-pkg/docs/SKILL.md',
];

describe.each([
  ['clean-mcpb.ts', cleaner.AGENT_DOC_ENTRY],
  ['lint-packaging.ts', packaging.AGENT_DOC_ENTRY],
])('AGENT_DOC_ENTRY in %s', (_name, pattern) => {
  it.each(retained)('keeps %s', (entry) => {
    expect(pattern.test(entry)).toBe(false);
  });
  it.each(stripped)('strips %s', (entry) => {
    expect(pattern.test(entry)).toBe(true);
  });
});

describe('bundle agent-doc selection', () => {
  it('keeps the two scripts on one pattern', () => {
    expect(packaging.AGENT_DOC_ENTRY.source).toBe(cleaner.AGENT_DOC_ENTRY.source);
    expect(packaging.AGENT_DOC_ENTRY.flags).toBe(cleaner.AGENT_DOC_ENTRY.flags);
  });

  it('selects exactly the package-root agent docs for the strip', () => {
    expect(cleaner.filterAgentDocEntries([...retained, ...stripped])).toEqual(stripped);
  });

  it('accepts a bundle that keeps the SDK runtime skills modules', () => {
    expect(packaging.checkBundleEntries(retained, 'bundle.mcpb')).toEqual([]);
  });

  it('rejects a bundle that still holds package-root agent docs', () => {
    const errors = packaging.checkBundleEntries([...retained, ...stripped], 'bundle.mcpb');
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain(`contains ${stripped.length} node_modules agent-doc entries`);
  });
});
