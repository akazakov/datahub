# Research Prompt — Implement Search-Time Permission Filtering for DataHub

You are briefed below with what a prior investigation already established. Do **not** rediscover it. Spend your time on the open design questions and produce an implementation plan, not code.

## What is already verified

DataHub OSS ships scaffolding for "Search Access Controls" but the search-result filtering layer is inert. Specifically:

- `VIEW_AUTHORIZATION_ENABLED=true` (env var → `metadata-service/configuration/src/main/resources/application.yaml:96` → `authorization.view.enabled`) **does** work end-to-end, but only for entity-page reads. The gate is `datahub-graphql-core/src/main/java/com/linkedin/datahub/graphql/authorization/AuthorizationUtils.java:260` (`canView`), called from per-entity mappers e.g. `datahub-graphql-core/src/main/java/com/linkedin/datahub/graphql/types/dataset/mappers/DatasetMapper.java:217`. When the actor can't view the entity, `AuthorizationUtils.restrictEntity(...)` reflectively nulls non-required fields. Verified empirically: a no-policy user fetching a dataset gets URN/name/platform but `customProperties=[]`, `schemaMetadata=null`, descriptions blank.
- `metadata-io/src/main/java/com/linkedin/metadata/search/utils/ESAccessControlUtil.java:34-65` (`restrictSearchResult`) is called from `metadata-io/src/main/java/com/linkedin/metadata/search/elasticsearch/query/request/SearchRequestHandler.java:490`, but its inner loop only fires when `opContext.getSearchContext().isRestrictedSearch()` is true. That flag is driven by `searchFlags.includeRestricted` (see `metadata-operation-context/src/main/java/io/datahubproject/metadata/context/SearchContext.java:70-72`). No frontend code anywhere sets `includeRestricted: true` — only `datahub-web-react/src/types.generated.ts` references it. So the path is dead in the running UI.
- Even when `includeRestricted=true` *is* passed (verified via direct GraphQL), the path errors out: `ESAccessControlUtil` calls `RestrictedService.encryptRestrictedUrn` (`metadata-operation-context/src/main/java/io/datahubproject/metadata/services/RestrictedService.java:16-23`), which mints a URN with entity type `"restricted"`. The GraphQL EntityRegistry has no `restricted` entity definition, and the response fails with *"Failed to find entity with name restricted in EntityRegistry"*. Reproduced.
- `applyDefaultSearchFilters` (`metadata-io/src/main/java/com/linkedin/metadata/search/utils/ESUtils.java:1155-1209`) is the only default filter injection point. It only handles `removed` (soft-delete) and `lifecycleStage` (hide-in-search). No actor or policy clauses.
- `metadata-service/configuration/src/main/java/com/linkedin/datahub/graphql/featureflags/FeatureFlags.java` has no flag for search authorization filtering. `glossaryBasedPoliciesEnabled` is UI-only.
- The acryldata/datahub fork is byte-identical to upstream on every auth-related file (verified: `ESUtils.java`, `ESAccessControlUtil.java`, `AuthorizationUtils.java`, `FeatureFlags.java`). `application.yaml` differs only on OTel and MCP URL validation, neither auth-related. The closed-source DataHub Cloud product has its own implementation that does not ship in either OSS repo.

## What is missing

A user with no view privileges on an entity should not see it (or should see a `restricted` placeholder) in any of these listing surfaces:

- `searchAcrossEntities` and `searchAcrossLineage` (GraphQL + RestLi + OpenAPI v3)
- `browseV2`
- `autocomplete`
- Recommendation candidates (`MostPopularSource.java` already has a TODO comment about this at line 165 — note it)
- Lineage exploration (already partly gated at `LineageSearchService` — confirm and note)

Per DataHub's validation architecture guideline (see `AGENTS.md` → "Validation Architecture"), enforcement must live at the search-service layer or below, never in a per-resolver shim, so the fix covers GraphQL + OpenAPI + RestLi simultaneously.

## Existing primitives you should reuse

- `metadata-auth/auth-api/src/main/java/com/datahub/authorization/AuthUtil.java:100` — `VIEW_RESTRICTED_ENTITY_TYPES` (dataset, dashboard, chart, mlModel, mlFeature, mlModelGroup, …). Confirm completeness.
- `metadata-service/auth-impl/src/main/java/com/datahub/authorization/DataHubAuthorizer.java:163` — `getActorPolicies(actorUrn)` returns the policies that grant the actor anything.
- `metadata-service/auth-impl/src/main/java/com/datahub/authorization/PolicyEngine.java` — evaluates a single policy against an entity for an actor.
- `metadata-operation-context/src/main/java/io/datahubproject/metadata/context/OperationContextConfig.java` — already carries `ViewAuthorizationConfiguration` per request. Extend, don't duplicate.
- `RestrictedService.encryptRestrictedUrn / decryptRestrictedUrn` — already mints reversible placeholder URNs; just needs a real GraphQL type wired up to render them.

## Your deliverable

A written implementation plan in `perms_plan.md` (next to this file). 4–6 pages. No code. The structure below — answer every section. When the code doesn't tell you something, say "unknown — need product/maintainer decision: …" and move on; don't guess.

### 1. Filtering vs redaction
Pick one as the primary mode. Justify with the trade-offs:
- **Filter** (drop unauthorized hits): result counts are accurate from the user's perspective, pagination simple, but reveals via differential counting that hidden entities exist; existing dashboards may show fewer results overnight.
- **Redact** (rewrite URN to `urn:li:restricted:*`): preserves counts so admins and low-priv users see consistent totals, but requires a real `restricted` entity type in the registry, frontend rendering, and the redacted-URN-resolution roundtrip already broken today.

Identify which surfaces want filter vs which want redaction (the answer may differ for autocomplete vs full search vs lineage). Note that filter + redact aren't mutually exclusive — could be a config knob per surface.

### 2. Policy → ES query translation
Read `DataHubPolicyInfo` (PDL) and `PolicyEngine`. Categorise policy resource predicates into:
- **Translatable to ES `bool`/`terms` clauses**: typically `urn` lists, `owners`, `domains`, `tags`, `glossaryTerms`, `type`. Sketch the clause shape for each.
- **Not translatable** (custom plugin authorizers, structured-property predicates, anything dynamic): these need a post-filter hook.

Design how the two layers compose: pre-filter to narrow the candidate set cheaply, post-filter to refine. Reference how `LineageSearchService` already does something similar — pattern-match on its approach.

### 3. Configuration & feature gating
Where do the new flags go? Three plausible spots:
- Extend `authorization.view` block: e.g. `authorization.view.searchFiltering.enabled` + `.mode: filter|redact`.
- New top-level block `authorization.searchAccessControl` if the semantics drift far from view auth.
- A `FeatureFlags.java` runtime toggle if there's a UI angle.

Pick one, explain why. Document the env var naming, the migration story (default OFF — operators turn on; existing behaviour unchanged), and the risks operators need to know (most importantly: enabling this may make existing saved searches and dashboards show fewer results).

### 4. Code change inventory
For each file, give path + summary of change + outline of the test that proves the change works.

Minimum coverage I expect:
- `metadata-io/src/main/java/com/linkedin/metadata/search/utils/ESUtils.java` (`applyDefaultSearchFilters`) — add auth-filter injection, or add a peer method `applyAuthorizationFilter(opContext, queryBuilder)` called from all entry points.
- `metadata-io/src/main/java/com/linkedin/metadata/search/utils/ESAccessControlUtil.java` — add filter mode alongside the existing redact mode.
- `metadata-io/src/main/java/com/linkedin/metadata/search/elasticsearch/query/request/SearchRequestHandler.java`, `AutocompleteRequestHandler.java`, `ESBrowseDAO.java` — call the new filter at the right point in query construction or post-processing.
- `metadata-operation-context/src/main/java/io/datahubproject/metadata/context/SearchContext.java` — new flag, separate from `isRestrictedSearch()` because semantics differ (enforce-filter vs opt-in-redact).
- `metadata-auth/auth-api/src/main/java/com/datahub/authorization/config/ViewAuthorizationConfiguration.java` + `metadata-service/configuration/src/main/resources/application.yaml` — new sub-config + env var wiring through `ConfigurationProvider`.
- If redact is the chosen path: register a `restricted` entity type in `entity-registry.yml`, add the GraphQL type, wire `RestrictedType` resolver. Without this the existing `urn:li:restricted:*` path stays broken.
- `MostPopularSource.java` — connect the TODO at line 165 to the new layer.
- `metadata-io/.../LineageSearchService.java` — confirm or extend.
- Frontend: minimum is making `restricted` placeholders render as locked rows in search/browse cards if redact mode is chosen. Identify `SearchResultsList`, `BrowseResults`, `AutoComplete` components.

### 5. Performance budget
- ES `bool` clause ceiling. A user with many policies × many resource filters can balloon the query. Identify a hard limit (e.g. 1024 clauses) and the graceful degradation strategy (fall back to post-filter, or fail closed with an explicit error).
- Authorization cache (`DataHubAuthorizer` already caches policy → actor mappings). Confirm that the new search-path code reads it correctly and doesn't bypass it under load.
- p99 latency target for `searchAcrossEntities`. Locate an existing latency baseline (logs / metrics / monitoring/.../client-prometheus-config.yaml) and propose an acceptance threshold.

### 6. Test strategy
- Unit: policy → ES filter translator (this is the highest-risk component; cover edge cases — empty policy set, policies with deny clauses, malformed resource filters).
- Integration: under `smoke-test/` boot DataHub, create admin + low-priv users, ingest 2-3 sample entities, run searches as each, assert different results.
- Backwards-compat regression: with the new feature OFF, every existing search test must still pass byte-for-byte.
- Performance regression: a search with N=100 policies should add < some threshold ms to query time.

### 7. Sequencing / phases
Propose an order. A reasonable shape:
1. Land the `restricted` entity type and fix the broken redact path (small, valuable on its own).
2. Add the translatable-subset pre-filter, default OFF.
3. Add the post-filter for non-translatable policies.
4. Flip the default to ON for fresh installations (next major version).

Justify why each phase is independently shippable.

### 8. Open questions
List anything you genuinely could not resolve from the code:
- Does Acryl/DataHub Cloud already have a private implementation we should align with, or are we free to diverge?
- Pagination semantics under filter mode — do total counts reflect post-filter or pre-filter? Existing API contracts say what?
- Are there ingestion / lineage paths where `OperationContext` is currently the system actor for legitimate reasons (consumer-job, MCP processing) — would the new filter accidentally block them?

## Constraints

- Follow DataHub conventions (see `AGENTS.md` and `metadata-ingestion/CLAUDE.md`). Spotless + Lombok + TestNG for Java; ruff + pytest for Python; TypeScript strict for frontend.
- Tests mirror `src/` directory structure; never add prod-only code paths under `src/test/`.
- No per-API shims (per `AGENTS.md` "Validation Architecture") — enforce at the search-service layer or lower.
- Don't redesign DataHub's policy model. Reuse `DataHubPolicyInfo`, `PolicyEngine`, `AuthUtil`. This is plumbing, not new policy.

## What this is not

Not a code task. Not a PR. Produce a written plan I can review and decide whether to fund the work. If a section is genuinely unknown after reading the code, mark it unknown — do not invent.
