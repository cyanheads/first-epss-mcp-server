# Developer Protocol

**Server:** first-epss-mcp-server

**Version:** 0.1.1

**Framework:** [@cyanheads/mcp-ts-core](https://www.npmjs.com/package/@cyanheads/mcp-ts-core) `^0.13.15`

**Engines:** Bun ≥1.4.0, Node ≥24.0.0

Read `node_modules/@cyanheads/mcp-ts-core/CLAUDE.md` first for framework APIs, builders, Context, errors, configuration, and exports. [docs/design.md](docs/design.md) records the server's domain contracts, decisions, and primary-source evidence.

## Scope

Five read-only tools expose FIRST EPSS scores, daily history, threshold discovery, prioritization with caller-supplied CVSS base severity, and static reference guidance. There are no resources, prompts, apps, or user-data stores. FIRST is keyless; no server-specific environment variables are required. Standard framework configuration selects stdio or Streamable HTTP and optional HTTP authentication.

Package/install identity is `@cyanheads/first-epss-mcp-server`; registry identity is `io.github.cyanheads/first-epss-mcp-server`. Display/machine identity is `first-epss-mcp-server`, including `createApp()` name/title, plugin names, Docker, and the `.mcpb` filename.

## Core Rules

- **Logic throws, framework catches.** Tool handlers throw on failure; no handler-level `try/catch`. Declare domain errors inline on each definition; service-origin entries use `thrownBy: 'service'`. Use framework error factories when classification matters.
- **Use `ctx.log`** for request-scoped, client-visible logging. Never log raw upstream bodies, secrets, or caller CVE lists.
- **Use `ctx.state`** for tenant-scoped storage if future work needs it. The current integration stores no user data.
- **Secrets in env vars only** — never hardcoded.
- **Cut noise.** No speculative abstractions, fallback facts, or guards for states already ruled out by validated schemas.
- **Preserve unknowns.** Missing EPSS is not zero risk; missing CVSS is not low severity. Probability and percentile are different metrics. Model changes alone do not establish new vulnerability evidence.
- **Preserve bounded work.** Scores/prioritization process 500 unique CVEs; history processes 50; the submission ceiling is 5,000 entries. Batch tools bound each serialized caller surface to 65,536 UTF-8 bytes, retaining whole entries and explicit full counts/preview completeness. Resume with the original submission, returned date, original severity/policy and `nextBatchOffset` as `batchOffset`; already-processed withheld entries differ from never-queried deferrals.
- **Close the loop on issues.** Follow the authorized workflow's issue-update and closure steps, describing the concrete change for future readers.
- **Candidate byte continuation.** All four dynamic tools bound each serialized caller surface to 65,536 UTF-8 bytes. Threshold discovery retains whole matches in upstream candidate order, discloses budget cuts with nested `budgetLimited`/`withheldCount`, and resumes at the first withheld match's exact upstream candidate position. Preserve the actual `examinedCount`; an empty year-filtered page advances across every inspected candidate. Candidate-position metadata stays internal.

## Patterns

Use the real definitions in `src/mcp-server/tools/definitions/` as examples:

| Definition | Pattern |
|:---|:---|
| `epss-get-scores.tool.ts` | Service call, inline error contract, notice enrichment, complete formatted accounting/provenance |
| `epss-get-timeseries.tool.ts` | Exact-date history, missing baselines, model-boundary caveats |
| `epss-query-threshold.tool.ts` | Candidate pagination and exact local CVE-year filtering |
| `epss-prioritize-cves.tool.ts` | Explicit likelihood/severity policy with unknown severity kept separate |
| `epss-list-reference.tool.ts` | Static source-linked reference without network access |

All definitions are exported through `definitions/index.ts` and registered in `src/index.ts`. Setup initializes `EpssService`; teardown disposes the shared request pacer.

## Context and errors

Handlers use `ctx.enrich({ notice })` for success caveats and `ctx.fail(reason)` for declared tool errors. The service threads `ctx.signal` through pacing, retries, body consumption, and model-header reads.

`upstream_shape` means invalid/inconsistent upstream data, never an ordinary missing CVE. `invalid_filter_combination` rejects absent/inverted query bounds; `conflicting_cvss` rejects duplicate CVEs with differing severity inputs. Preserve framework timeout, cancellation, rate-limit, and HTTP classifications while projecting only safe error fields. Never expose raw response bodies or causes.

The metadata cache holds public header data only. A failed metadata read can leave usable scores with a notice; caller cancellation and the whole-call deadline still fail the request.

## Structure

| Path | Purpose |
|:---|:---|
| `src/index.ts` | Register five tools; initialize/dispose the service |
| `src/mcp-server/tools/definitions/` | Tool definitions and public registration barrel |
| `src/mcp-server/tools/{format,history,schemas}.ts` | Text output, exact-date policy, described schemas |
| `src/services/epss/epss-service.ts` | FIRST requests, pacing, retries, chunking, attribution |
| `src/services/epss/model-header.ts` | Bounded CSV-header reader and public metadata cache |
| `src/services/epss/{normalization,errors,types,index}.ts` | IDs/dates/models, safe errors, service contracts/barrel |
| `tests/` | Tool, service, and integration tests |

## Naming and imports

Files use kebab-case with `.tool.ts` for definitions; tool names use `epss_` snake_case. Cross-module imports use public barrels. The framework re-exports `z`; import error factories from `@cyanheads/mcp-ts-core/errors` and utilities from `@cyanheads/mcp-ts-core/utils`. Service consumers import from `src/services/epss/index.ts`.

Exports and files carry concise JSDoc `@fileoverview` / `@module` documentation. Descriptions are single strings or template literals. Every public schema field has `.describe()` and is JSON-Schema-serializable.

## Skills

Run `bun run list-skills` for the current registry. Canonical development skills live in `framework-skills/`; agent copies live in `.claude/skills/` and `.agents/skills/`. They are contributor instructions, not installed plugin skills. After framework updates, follow `framework-skills/maintenance/SKILL.md` to sync them.

Read the matching skill before adding tools/services/tests, field-testing, reviewing definition language, simplifying code, auditing security, polishing metadata, or releasing. A scoped sub-agent follows its assigned phase; it does not start an orchestration workflow.

## Commands

Use `bun run <script>`. Tests use Vitest: `bun run test`, never bare `bun test`.

| Command | Purpose |
|:---|:---|
| `build` / `rebuild` / `clean` | Compile; clean and compile; remove build artifacts |
| `devcheck` | Raw lint, format, typecheck, packaging, security, and sync gates |
| `test` / `test:coverage` | Vitest suite; Istanbul coverage |
| `lint:mcp` / `lint:packaging` | Definition contracts; metadata and launch checks |
| `format` / `format:unsafe` | Biome safe fixes; unsafe fixes requiring diff review |
| `tree` / `list-skills` | Generate `docs/tree.md`; print skill registry |
| `start` / `start:stdio` / `start:http` | Built Node entrypoint; explicit transport variants |
| `changelog:build` / `changelog:check` | Generate/check changelog rollup |
| `bundle` | Build, pack, clean `dist/first-epss-mcp-server.mcpb` |
| `release:github` / `publish-mcp` | Release workflow helpers |
| `audit:fix` | Resolve vulnerable dependencies within current ranges |
| `audit:refresh` | Full lockfile re-resolution; not a routine audit remedy |

Do not change framework adoption, lower the release-age guard, add dependency overrides, or refresh the lockfile without the task's authorization.

## Testing and verification

Automated tests make no live upstream requests. Install strict global fetch fakes below the real native API exchange and framework metadata fetch helper; do not mock `EpssService` public methods. Exercise handlers with `createMockContext()` and check structured/text parity, sparse payloads, missing/deferred CVEs, calendar gaps, candidate continuation, cancellation, retries, and model attribution. API error bodies are inspected privately and never logged; preserve one attempt deadline across headers and body reads.

Run raw `bun run devcheck`, `bun run rebuild`, and `bun run test` before handback. Read warnings as well as exit codes. Verification runs locally. `.github/workflows/codeql.yml` is the only GitHub Actions workflow; do not add duplicate local-gate workflows.

## Bundling and metadata

`manifest.json` defines the Node stdio MCPB launch. `.mcpbignore` excludes source, tests, scripts, coverage, and private material. `scripts/clean-mcpb.ts` prunes dev dependencies and dependency-shipped agent docs/native bindings after packing.

Keep package, registry, MCPB, Claude/Codex plugins, Docker labels, and README consistent. A new user-supplied env variable must be wired through `server.json`, MCPB `user_config` / `mcp_config.env`, Claude `userConfig`, and Codex `env_vars`. An empty runtime env value replaces the user's value; it is not an optional-config hint.

## Changelog

Per-release sources live at `changelog/<major.minor>.x/<version>.md`, with concrete version/date and `summary` frontmatter. `changelog/template.md` stays pristine. `CHANGELOG.md` is generated by `bun run changelog:build`; never hand-edit it. Dependency entries name the package and old → new range.

## Publishing

**Every release goes through a straight-through release PR** — `git-wrapup`'s "Release PR mode", mode `straight-through`. Run `git-wrapup` then `release-and-publish` on `release/<version>`. Fast-forward `main` locally with `git merge --ff-only`; never merge through the GitHub UI or `gh pr merge`. Publish to npm, MCP Registry, GHCR, and a GitHub Release with the `first-epss-mcp-server.mcpb` asset.

## Checklist

- [ ] Domain changes preserve bounded requests, explicit unknowns, and FIRST/Empirical Security attribution.
- [ ] Schema fields are described and JSON-Schema-serializable.
- [ ] Inline error contracts and success notices give actionable next steps.
- [ ] Text output preserves every semantic structured-output field.
- [ ] Fetch-boundary integration tests cover sparse data and operational failures.
- [ ] Metadata/install identities and user-config wiring agree across manifests.
- [ ] README capabilities/configuration and `docs/design.md` match source.
- [ ] Raw devcheck, rebuild, and the full test script pass.
