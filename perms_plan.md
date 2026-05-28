# Implementation Plan — Search-Time Permission Filtering for DataHub

This plan turns the briefing in `perms_prompt.md` into a concrete, reviewable proposal.
No code, no rediscovery. Where the source doesn't answer a question I have marked it
**unknown — needs decision** and moved on.

The shape of the fix in one line: inject an authorization clause into
`ESUtils.applyDefaultSearchFilters` (the single chokepoint already used by search,
autocomplete, and browse), and back it with a post-filter that re-uses the existing
`ESAccessControlUtil` primitives. Everything in the surrounding text below — modes,
config, sequencing — is in service of that line.

---

## 1. Filtering vs redaction

### Primary mode: **filter** (drop unauthorized hits before they leave ES)

Reasons:

- The redact path is **broken today** in OSS. `RestrictedService.encryptRestrictedUrn`
  mints `urn:li:restricted:<encrypted>` but `metadata-models/src/main/resources/entity-registry.yml`
  has no `restricted` entry (verified — `grep restricted` is empty), so the Java
  `EntityRegistry` throws on lookup. The GraphQL `Restricted` type
  (`datahub-graphql-core/src/main/resources/entity.graphql:14076`) and resolver
  (`datahub-graphql-core/src/main/java/com/linkedin/datahub/graphql/types/restricted/RestrictedType.java`)
  exist, but the frontend only renders `Restricted` for lineage nodes
  (`datahub-web-react/src/app/lineage/LineageEntityNode.tsx`,
  `LineageExplorer.tsx`); no `SearchResultsList`, `BrowseResults`, or autocomplete
  card knows what a restricted entity looks like. Shipping redact first means
  shipping a working entity-registry entry plus three frontend renderers plus
  the round-trip resolution that fails today. Filter mode ships none of that.
- Filter is what the user expects from a search box. "I search and see what I can
  use" is the dominant intuition. Filter cleanly carries through pagination,
  scroll IDs, and aggregations because the count `searchAcrossEntities` returns
  matches what the user sees.
- The differential-counting concern (admin sees 100, low-priv sees 90 → low-priv
  infers 10 hidden) is **already true today** in places like aggregation buckets
  and lineage degree counts. Hardening the count signal is a separate program of
  work, not a blocker for landing search-time filtering.

### Where redact is the right call

- **Lineage explorer.** Graph topology breaks if we drop nodes — a downstream
  table disappears and its dependents look orphaned. Redact preserves the shape
  of the graph while hiding the asset's metadata. `LineageSearchService`
  (`metadata-io/.../LineageSearchService.java:711`) already filters path URNs
  through `canViewEntity` — that path should switch to "redact node, keep
  path" rather than "drop path" when redact mode is on for lineage. **Note:**
  `LineageSearchService` is only one of two lineage paths. `ElasticSearchGraphService.getLineage`
  (in `metadata-io/.../graph/elastic/`) queries the graph index directly and does
  **not** call `canViewEntity` today. Any redact-mode lineage work must cover
  both call paths or document why graph-direct lineage is out of scope.
- **Optionally for full search**, behind a per-surface config knob, so operators
  who care more about consistent totals than information leakage can turn it on.

### Per-surface defaults (proposed)

| Surface                                            | Default mode      | Notes |
|----------------------------------------------------|-------------------|-------|
| `searchAcrossEntities` / scroll search             | filter            | redact opt-in via config |
| `autocomplete`                                     | filter            | already drops via `restrictUrn` (`AutocompleteRequestHandler.java:388`) |
| `browseV2`                                         | filter            | counts in browse tree match what user sees |
| `searchAcrossLineage` / lineage explorer           | redact            | preserve graph topology |
| Recommendations (`MostPopularSource`)              | filter            | nothing displays restricted cards today |

Filter and redact are **not mutually exclusive** — both are implemented; the
config selects which runs per surface.

### What is explicitly **not** in scope here

System actors (`opContext.isSystemAuth() == true`) bypass both paths, matching
the existing behavior in `ESAccessControlUtil.restrictSearchResult` lines 36–37
and the entity-page gate in `AuthorizationUtils.canView`. Ingestion, MCP
processing, MCL consumers, and other system-driven reads must not be filtered.

---

## 2. Policy → ES query translation

### What the policy model gives us

`DataHubPolicyInfo` carries `resources: DataHubResourceFilter` (verified —
`DataHubPolicyInfo.pdl:46` and `DataHubResourceFilter.pdl:33`), which holds a
`PolicyMatchFilter`. That filter is `list[PolicyMatchCriterion]`, where each
criterion is `{ field: string, values: array[string], condition: PolicyMatchCondition }`
(verified — `PolicyMatchCriterion.pdl:11/16/21`). `PolicyMatchCondition` is the
enum `EQUALS | STARTS_WITH | NOT_EQUALS` (verified — `PolicyMatchCondition.pdl`).
`PolicyEngine.checkCriterion` (line 280–292) resolves `field` through
`EntityFieldType.valueOf(criterion.getField().toUpperCase())`, then asks the
resolved spec for that field's value set. `EntityFieldType` (declaration order
preserved):

```
RESOURCE_URN      (deprecated)
RESOURCE_TYPE     (deprecated)
TYPE
URN
OWNER
DOMAIN
GROUP_MEMBERSHIP
DATA_PLATFORM_INSTANCE
TAG
CONTAINER
GLOSSARY
```

Each enum value maps (today, inside `PolicyEngine`) to a `Set<String>` extracted
from a `ResolvedEntitySpec` via `*FieldResolverProvider` classes (e.g.
`OwnerFieldResolverProvider`, `DomainFieldResolverProvider`,
`GlossaryFieldResolverProvider`). These resolvers read aspects, **not** the
search index — so the translator's job is to bridge "policy field name" (an
abstract aspect-rooted concept) to "ES doc field name" (a concrete indexed
field). The mapping below is the bridge, verified against the search index
mappings DataHub ships today.

### Translatable subset

All entity-side resource fields translate cleanly:

| Policy field             | ES clause (EQUALS)                                                                                                          | Notes |
|--------------------------|-----------------------------------------------------------------------------------------------------------------------------|-------|
| `TYPE`                   | `terms _entityType` (or `_index` filter, depending on how we narrow)                                                        | indexed already |
| `URN`                    | `terms urn`                                                                                                                 | indexed already |
| `OWNER`                  | `terms owners` plus the **ownership-group expansion** (any group owning the asset whose membership includes the actor)      | requires expanding the actor's groups; see below |
| `DOMAIN`                 | `terms domains`                                                                                                             | indexed already |
| `TAG`                    | `terms tags`                                                                                                                | indexed already |
| `GLOSSARY`               | `terms glossaryTerms` (plus parent-term expansion — `GlossaryFieldResolverProvider` walks parents; the translator must too) | indexed already |
| `CONTAINER`              | `terms container`                                                                                                           | indexed already |
| `DATA_PLATFORM_INSTANCE` | `terms platformInstance`                                                                                                    | indexed already |

Conditions:

- `EQUALS` → `terms`.
- `STARTS_WITH` → `prefix` or `wildcard` (prefer `prefix`, it's cheaper).
- `NOT_EQUALS` → `bool.must_not(terms ...)`.

Per-policy: each criterion becomes a `must` clause; the policy resource filter
is a logical AND of its criteria (matches `PolicyEngine.checkFilter` which
streams `allMatch`).

Across policies: a `bool.should` (OR) of per-policy `must` clauses. Adding
`minimum_should_match: 1` makes "any matching policy grants access" the
semantics, which is consistent with how `PolicyEngine.getGrantedPrivileges`
unions privileges across policies.

The **actor-side** clause (`DataHubActorFilter`) is *not* translated to ES at
all — it's used host-side to pre-select which of the actor's policies are even
candidates. `DataHubAuthorizer.getActorPolicies(actorUrn)` (line 163, verified)
returns exactly that subset.

**Important correction to a prior version of this plan.** `DataHubAuthorizer`
does **not** cache `getActorPolicies(actorUrn)` per-actor. What it caches is the
`policyCache: Map<String,List<DataHubPolicyInfo>>` keyed by *privilege name*
(see `DataHubAuthorizer.java:58`) — a flat "privilege → all policies that grant
it" map, refreshed every `refreshIntervalSeconds` (constructor arg from
`application.yaml`'s authorization config; default value is set in the wiring,
not hardcoded as a `POLICY_CACHE_REFRESH_INTERVAL_SECONDS` constant). Every
`getActorPolicies(actorUrn)` call (line 163) iterates that cache and re-runs
`PolicyEngine.policyAppliesToActor` per policy. There is **no** per-actor
memo. The new `SearchPolicyTranslator` therefore must:

1. Call `getActorPolicies(actorUrn)` afresh once per search request, **or**
2. Maintain its own `(actorUrn, policyCacheVersion) → translatedQuery` memo,
   sized small (LFU/LRU, say 1000 actors), and invalidate when the underlying
   `policyCache` mutates. The plan assumes (2) — the cache key encodes the
   `policyCache` identity (e.g., a monotonic version stamp the
   `PolicyRefreshRunnable` increments on each completed refresh).

**Resource owners** (`actorFilter.isResourceOwners() == true`) does need an ES
clause: the policy grants access to anything *owned by the actor or actor's
groups*. That expands to `terms owners` against `{actor URN} ∪ {actor's group
URNs}`.

**Correction on actor-group resolution.** Group URNs come from
`DataHubAuthorizer.getActorGroups(actorUrn)` (lines 188–196, verified). This
method resolves the actor's spec on every call and is **not** cached at the
authorizer level. The plan's earlier suggestion to use `getActorPeers()` is
**wrong**: that method (lines 199–202) is currently a stub returning
`List.of(actorUrn)` with a `// TODO: Fetch users from groups the actor is a
member of` comment, and even when implemented it returns *peer actors*, not
*group URNs*. The translator must call `getActorGroups()` directly and accept
the per-request resolution cost — which is itself a candidate for memoisation
inside the translator alongside the translated-query cache above.

### Non-translatable predicates

- **Structured-property predicates.** `EntityFieldType` has no entry today, but
  custom authorizers/plugins can examine arbitrary aspects. We cannot translate
  what we cannot enumerate.
- **Custom authorizer plugins.** Any policy whose decision goes through a
  pluggable authorizer (per `Authorizer` SPI in `metadata-auth/auth-api`) is
  opaque to us. Mark the policy "post-filter only" and skip it in the pre-filter.
- **`GROUP_MEMBERSHIP`** is an *actor-side* field, not entity-side; it is
  resolved when computing `getActorPolicies` and doesn't appear in ES.

### Two-layer composition

```
  ┌───────────────────────────────────────────────┐
  │ pre-filter (in applyAuthorizationFilter)      │
  │   - cheap, runs in ES                         │
  │   - covers policies whose every criterion     │
  │     is translatable                           │
  └───────────────────────────────────────────────┘
                       │
                       ▼
  ┌───────────────────────────────────────────────┐
  │ post-filter (in restrictSearchResult / restrictUrn)
  │   - runs over the (already-narrowed) result   │
  │     set, calling canViewEntity per hit        │
  │   - handles non-translatable policies and     │
  │     belt-and-braces verification              │
  └───────────────────────────────────────────────┘
```

This is the same shape `LineageSearchService` already uses (broad ES query →
per-URN `canViewEntity` filter at line 711). The new code generalises that pattern.

When *every* applicable policy is translatable the post-filter is a no-op
(every hit will pass `canViewEntity`). When there are non-translatable
policies, the pre-filter is permissive (returns the union of translatable +
non-translatable candidates) and the post-filter tightens it. This is
analogous to ES's own `query` vs `filter` decomposition.

---

## 3. Configuration and feature gating

### Where the config lives

Extend `authorization.view` (in `application.yaml` lines 94–99 and the
`ViewAuthorizationConfiguration` POJO at
`metadata-auth/auth-api/src/main/java/com/datahub/authorization/config/ViewAuthorizationConfiguration.java`).
The semantics are continuous with view authorization: same
`VIEW_RESTRICTED_ENTITY_TYPES` set
(`metadata-auth/.../AuthUtil.java:100-117`), same `canViewEntity` predicate,
same "system actor is exempt" rule. A new top-level block would just duplicate
plumbing.

Not a `FeatureFlags.java` entry: those drive the UI / GraphQL surface. This is
backend enforcement and should be a server-side configuration knob, not a UI
flag that anyone could flip from a settings page.

### Proposed shape

```yaml
authorization:
  view:
    enabled: ${VIEW_AUTHORIZATION_ENABLED:false}   # existing
    recommendations:
      peerGroupEnabled: ...                        # existing
    searchFiltering:
      enabled: ${SEARCH_AUTHORIZATION_FILTERING_ENABLED:false}
      mode: ${SEARCH_AUTHORIZATION_FILTERING_MODE:filter}     # filter | redact
      surfaces:
        search:          ${SEARCH_AUTH_FILTER_SEARCH:true}
        autocomplete:    ${SEARCH_AUTH_FILTER_AUTOCOMPLETE:true}
        browse:          ${SEARCH_AUTH_FILTER_BROWSE:true}
        recommendations: ${SEARCH_AUTH_FILTER_RECOMMENDATIONS:true}
        lineage:         ${SEARCH_AUTH_FILTER_LINEAGE:true}
      maxBoolClauses: ${SEARCH_AUTH_FILTER_MAX_CLAUSES:1024}
      onClauseOverflow: ${SEARCH_AUTH_FILTER_OVERFLOW:postFilter}  # postFilter | failClosed
```

`searchFiltering.enabled` gates everything. With it **off**, every code path
short-circuits to current behaviour byte-for-byte. With it **on** but
`view.enabled` off, `searchFiltering.enabled` is treated as off (the entity-page
guarantee is the floor; no point filtering search if entity pages already leak).

### Migration story

- **Default OFF** in OSS for at least one minor release.
- The first release ships the broken-redact-path fix (Phase 1 below) and the
  new pre-filter behind `searchFiltering.enabled=false`. Operators opt in.
- A future major version flips the default for *fresh installations only*
  (existing `application.yaml` overrides win).

### Risks operators need to know

1. **Saved searches and dashboards may show fewer results once enabled.** Tile
   counts may drop; URLs that previously surfaced N rows may surface < N. Tell
   operators to roll out to staging first.
2. **Aggregation buckets** (facet counts in the left rail of the search UI) will
   shift after the filter is applied. We need to decide whether buckets are
   computed pre- or post-auth — see Open Question 2.
3. **Performance.** Adding hundreds of `bool.should` clauses per request has a
   cost; see Section 5.
4. **System-actor paths** (consumer jobs, MCP processing) must not start
   filtering. Confirm via Open Question 3.

---

## 4. Code change inventory

Every entry below is "what changes" plus "the test that proves it."

### `metadata-io/src/main/java/com/linkedin/metadata/search/utils/ESUtils.java`

- Add `applyAuthorizationFilter(OperationContext, List<String> entityNames, BoolQueryBuilder filterQuery)`.
- Have `applyDefaultSearchFilters` invoke it when
  `view.enabled && view.searchFiltering.enabled && !opContext.isSystemAuth()`.
- The new method calls a new collaborator
  (`SearchPolicyTranslator` — see below) that returns a `BoolQueryBuilder`
  representing "things this actor can view," and ANDs it into `filterQuery`.
- If the translator returns a clause count exceeding `maxBoolClauses`, fall
  back per `onClauseOverflow` (`postFilter` is the safe default).

**Test:** `ESUtilsAuthFilterTest` (Java/TestNG, mirrors `src/test/`). Cases:
empty policies → no-op; single allow-all policy → no-op; URN-list policy →
exact `terms` clause; mixed translatable + non-translatable → pre-filter
covers translatable, post-filter slot left open; clause overflow → falls back
correctly. Feature-flag OFF → method short-circuits.

### New: `metadata-io/src/main/java/com/linkedin/metadata/search/auth/SearchPolicyTranslator.java`

- Pure function: `(List<DataHubPolicyInfo>, ResolvedActor) → BoolQueryBuilder`.
- Walks policies → criteria → `EntityFieldType`. Returns the union (`should`)
  of per-policy `must` clauses. Each criterion's
  `EQUALS|STARTS_WITH|NOT_EQUALS` maps to `terms` / `prefix` /
  `must_not(terms)`.
- Per-policy: if any criterion is non-translatable, the policy is dropped
  from the pre-filter (it will be honored at post-filter time).
- Cached per actor + policy-version key; cache lives in
  `DataHubAuthorizer` (it already caches policies — extend, don't duplicate).

**Test:** `SearchPolicyTranslatorTest`. Highest-risk component. Cover:
- empty policy set returns match-all-deny;
- single owner-based policy expands actor groups correctly;
- `STARTS_WITH` produces `prefix`;
- `NOT_EQUALS` produces `must_not`;
- malformed criterion (unknown field) is skipped, not thrown;
- a policy with one translatable and one non-translatable criterion is
  classified non-translatable.

### `metadata-io/src/main/java/com/linkedin/metadata/search/utils/ESAccessControlUtil.java`

- Add a sibling to `restrictSearchResult` named `dropUnauthorized` that *removes*
  unauthorized entries instead of redacting them. Selection is by
  `view.searchFiltering.mode`.
- Keep the existing redact behavior — it's used by lineage and by anyone who
  explicitly sets `includeRestricted=true`.

**Test:** `ESAccessControlUtilTest`. Two parametrised modes: filter drops the
unauthorized entity outright; redact rewrites URN and sets
`restrictedAspects` (the current behavior, regression-tested).

### `metadata-io/src/main/java/com/linkedin/metadata/search/elasticsearch/query/request/SearchRequestHandler.java`

- Already calls `applyDefaultSearchFilters` (line 222, verified) and already
  calls `ESAccessControlUtil.restrictSearchResult` at **two** sites: line 490
  (the main search execution path) and line 646 (a second result-rewriting
  path). Both must be migrated together to mode-dispatched
  `dropUnauthorized` vs `restrictSearchResult`; missing either leaks results
  from one of the two surfaces it serves.

**Test:** existing `SearchRequestHandlerTest` extended with a low-priv actor
case asserting result count delta. Plus a regression case with the feature
flag off (must match historical output byte-for-byte).

### `metadata-io/src/main/java/com/linkedin/metadata/search/elasticsearch/query/request/AutocompleteRequestHandler.java`

- Already calls `applyDefaultSearchFilters` at line 169 and already drops via
  `restrictUrn` at line 388 — verified. No new wiring needed; the pre-filter
  injection in `ESUtils` carries through automatically.

**Test:** integration test under `smoke-test/` (autocomplete returns fewer
hits for a low-priv user).

### `metadata-io/src/main/java/com/linkedin/metadata/search/elasticsearch/query/ESBrowseDAO.java`

- Already calls `applyDefaultSearchFilters` at line 274 — verified. No new
  call sites needed.
- Aggregation counts (browse tree node counts) need a decision: do we want
  buckets that match what the user can see (so re-run aggregations under the
  same auth filter) or "true" counts (which leak)? Default to matching the
  user's view.

**Test:** browse tree under low-priv actor returns reduced counts.

### `metadata-operation-context/src/main/java/io/datahubproject/metadata/context/SearchContext.java`

- Do **not** reuse `isRestrictedSearch()` — its semantics are "caller opted
  in to receive redacted placeholders." We need a separate read of
  `view.searchFiltering.enabled / .mode` via
  `OperationContextConfig.getViewAuthorizationConfiguration()`.
- Add a convenience accessor (or keep callers reading the config directly —
  small preference).

**Test:** unit assertions that the two flags are independent.

### `metadata-auth/auth-api/src/main/java/com/datahub/authorization/config/ViewAuthorizationConfiguration.java`

- Add nested `SearchFilteringConfig { enabled, mode, surfaces, maxBoolClauses, onClauseOverflow }`.
- Lombok `@Data @Builder` per existing style.

### `metadata-service/configuration/src/main/resources/application.yaml`

- Add the keys from Section 3.
- Wire through `ConfigurationProvider` like the rest of `authorization.view.*`.

**Test:** Spring config loading test mirroring existing tests in
`metadata-io/src/test/java/com/linkedin/metadata/system_info/collectors/PropertiesCollectorConfigurationTest.java`
(also ensures the security classification list is updated — this is a
mandatory guardrail per `AGENTS.md`).

### `metadata-io/src/main/java/com/linkedin/metadata/recommendation/candidatesource/MostPopularSource.java` *(and peers)*

- The comment at line 165 ("If search access controls enabled, restrict user
  activity to peers") describes `restrictPeers`, which filters the
  *usage-events index* to peer events. It does **not** filter the resulting
  entity URN list by per-entity view permission. Add a post-filter step that
  runs each candidate URN through `restrictUrn` (or drops it) before
  returning candidates.
- **Sibling sources need the same treatment.** `RecentlyEditedSource.java` and
  `RecentlyViewedSource.java` (same directory, both `EntityRecommendationSource`)
  follow the exact same shape — query the `DataHubUsageEvent` index, derive an
  entity URN list, return as recommendation candidates. Neither filters the
  candidate URNs by view permission today. The post-filter helper should be
  extracted into a shared utility (e.g. an `EntityRecommendationSource`
  default method or a `RecommendationCandidateAuthFilter`) so all three sources
  pick it up together. Missing this is the difference between "MostPopular hides
  restricted assets but 'Recently Viewed' still shows them."

**Test:** parametrise across all three sources — an entity with no view
privilege for the actor is not returned as a recommendation candidate, even
if peers clicked on / edited / viewed it.

### `metadata-io/src/main/java/com/linkedin/metadata/search/LineageSearchService.java`

- Already filters lineage path URNs via `canViewEntity` at line 711, but the
  *result entities* themselves are not dropped. With redact mode, switch to
  rewriting unauthorized path nodes to restricted URNs (so the path stays
  intact). With filter mode, drop the path.

**Test:** smoke test with a lineage graph spanning datasets the actor can and
cannot view; assert redact preserves topology, filter trims it.

### Phase-1 wiring: register `restricted` end-to-end

- `metadata-models/src/main/resources/entity-registry.yml`: add a `restricted`
  entity with a single key aspect (`restrictedKey`).
- `metadata-models/src/main/pegasus/com/linkedin/restricted/RestrictedKey.pdl`:
  new key aspect (just an encrypted-id string).
- `datahub-graphql-core/src/main/java/com/linkedin/datahub/graphql/GmsGraphQLEngine.java`:
  confirm `RestrictedType` is registered as an entity type (the resolver
  already exists at `datahub-graphql-core/.../restricted/RestrictedType.java`,
  just needs entity-registry support to round-trip).
- This is the change that unblocks the today-broken redact path.

**Test:** integration test that sets `includeRestricted=true` on a search and
gets back a `urn:li:restricted:*` that GraphQL `dataset(urn:)` can resolve to
a `Restricted` GraphQL type without "Failed to find entity with name restricted".

### Additional surfaces — coverage decisions

The pre-filter ride-along (Section 2's "wire it into `applyDefaultSearchFilters`")
only protects callers that route through `SearchRequestHandler`,
`AutocompleteRequestHandler`, and `ESBrowseDAO`. Several listing surfaces
issue ES queries via different paths. Each needs an explicit decision —
"covered by ride-along," "needs its own post-filter," or "intentionally out of
scope."

| Surface / file                                                                                      | Path to ES                                              | Decision (recommended)                                       |
|-----------------------------------------------------------------------------------------------------|---------------------------------------------------------|--------------------------------------------------------------|
| `SearchService.scrollAcrossEntities` (`metadata-io/.../search/SearchService.java:209/246`)          | → `CachingEntitySearchService.scroll` → `SearchRequestHandler` | Covered by ride-along — confirm via integration test on the scroll path. |
| `AggregateAcrossEntitiesResolver` (`datahub-graphql-core/.../resolvers/search/`)                    | → `EntityClient.getAggregationsAcrossEntities`          | **Needs decision.** Aggregation counts can leak the existence of restricted entities. See Open Question 2 below. |
| `GetQuickFiltersResolver` (`datahub-graphql-core/.../resolvers/search/`)                            | → `searchAcrossEntities` with `setSkipAggregates(false)` | Inherits whatever Aggregations decision is. |
| `ContainerEntitiesResolver` (`datahub-graphql-core/.../resolvers/container/`)                       | → `EntityClient.searchAcrossEntities`                   | Covered by ride-along. Verify in smoke test (a container holds datasets the actor can't view). |
| `DomainEntitiesResolver` (`datahub-graphql-core/.../resolvers/domain/`)                             | → `EntityClient.searchAcrossEntities`                   | Covered by ride-along. Verify in smoke test. |
| `ListDataProductAssetsResolver` (`datahub-graphql-core/.../resolvers/dataproduct/`)                 | → `EntityClient.searchAcrossEntities`                   | Covered by ride-along. Verify in smoke test. |
| `ElasticSearchGraphService.getLineage / getImpactLineage` (`metadata-io/.../graph/elastic/`)        | Direct graph-index query, **bypasses** `LineageSearchService` | **Needs its own filter.** Today no entity-level filter. Either route through `LineageSearchService` for filtering or add a parallel `canViewEntity` pass over result URNs. |
| `ElasticSearchTimeseriesAspectService.getAggregatedStats` (`metadata-io/.../timeseries/elastic/`)   | Direct ES aggregation on timeseries index             | **Out of scope for v1.** Timeseries surfaces (usage stats, profile stats) are accessed via `dataset` and `dashboard` resolvers that already check `canView`. Document the assumption. |
| `OpenAPI v3 GenericEntitiesController.scrollAcrossEntities` (`metadata-service/openapi-servlet/.../GenericEntitiesController.java`) | → `EntitySearchService.scrollAcrossEntities`            | Covered by ride-along (same underlying `SearchService`). Integration test must call the OpenAPI endpoint with a low-priv token. |
| Admin-entity `List*Resolver.java` (Domains, Groups, Roles, OwnershipTypes, Posts, Queries, IngestionSources, Secrets, AccessTokens, ServiceAccounts, ExecutionRequests, BusinessAttributes, LifecycleStages) | → `EntityClient.search`                                 | **Intentionally out of scope.** None of these entity types appear in `VIEW_RESTRICTED_ENTITY_TYPES` (`AuthUtil.java:100`), so view-authorization semantics never applied to them. Document explicitly in the user-facing docs that platform-admin entities remain visible to anyone with general read access — this is a deliberate boundary, not a bug. |

### Frontend (redact-mode only; defer if filter is chosen)

- `datahub-web-react/src/app/searchV2/SearchResultsList.tsx` (and the
  pre-V2 equivalent at `app/search/`): handle `EntityType.RESTRICTED` by
  rendering a locked-card placeholder. Today `Restricted` is only handled in
  `app/lineage/LineageEntityNode.tsx` and `LineageExplorer.tsx`.
- `app/browse/` and `app/searchV2/autoComplete/`: same.

If filter is the only mode shipped initially, these can be deferred.

---

## 5. Performance budget

### Clause-count ceiling

Elasticsearch's default `indices.query.bool.max_clause_count` is **1024** in
ES 7.x and 4096 in ES 8.x. A user with K policies, each with M criteria,
produces roughly `K × M` leaf clauses plus expansion for owner-group
expansion. For realistic deployments (`K ≤ 50`, `M ≤ 5`) this is well below
the ceiling. The guardrail is `maxBoolClauses` (configurable, default 1024)
plus a counted-clause check before issuing the query.

**Overflow strategy** (`onClauseOverflow`):

- `postFilter` (default, safe): skip the pre-filter, do a broad ES query,
  drop unauthorized in the post-filter. Latency goes up; correctness
  preserved.
- `failClosed`: return an error to the caller (and a clear log line) — for
  operators who would rather alert than degrade.

### Cache reuse

What `DataHubAuthorizer` actually caches (verified in
`DataHubAuthorizer.java:58–94`):

- A `policyCache: Map<String,List<DataHubPolicyInfo>>` keyed by **privilege
  name** (not actor URN). Refreshed by a `PolicyRefreshRunnable` scheduled at
  `refreshIntervalSeconds`, a constructor argument sourced from Spring config.
  There is no `POLICY_CACHE_REFRESH_INTERVAL_SECONDS` constant — earlier
  versions of this plan invented one; the actual value flows from
  `application.yaml`'s authorization wiring.
- `getActorPolicies(actorUrn)` (line 163) reads that cache and re-runs
  `PolicyEngine.policyAppliesToActor` per policy on **every call**. There is
  no per-actor memo. `getActorGroups(actorUrn)` (line 188) resolves the
  actor's spec on every call; also not cached.

What the new `SearchPolicyTranslator` must therefore own:

- A bounded `(actorUrn, policyCacheVersion) → translatedQuery` cache (LRU,
  e.g. 1000 entries) keyed by a monotonic version stamp that
  `PolicyRefreshRunnable` increments at the end of each successful refresh.
- A bounded `actorUrn → groupUrns` cache with the same version key. (Group
  membership changes are infrequent enough that piggy-backing on the policy
  refresh tick is acceptable; the alternative is a separate, shorter TTL.)

Bypass-under-load risk is manageable because both caches are per actor — even
a thundering herd hits the cache after the first translation per actor per
refresh window.

### p99 latency

I could not find an existing OSS-published `searchAcrossEntities` p99 baseline
in the worktree. `monitoring/.../client-prometheus-config.yaml` exposes
metrics but the budget is a deployment-level concern. **Unknown — needs
maintainer/SRE decision:** propose a 20% p99 budget for the pre-filter on a
representative production-scale corpus, measured against `searchAcrossEntities`
without auth filtering. Acceptance: < 1.2× p99 with feature ON and 50
policies / actor.

---

## 6. Test strategy

### Unit

- `SearchPolicyTranslatorTest` — the highest-risk component.
  - empty policies → match-nothing-extra (no-op);
  - allow-all policy (`allUsers=true`, no resource filter) → no-op;
  - URN-list policy → `terms urn`;
  - owner-based policy → `terms owners`, with group expansion;
  - `STARTS_WITH` and `NOT_EQUALS` translate as documented;
  - unknown field type → criterion dropped, policy marked non-translatable;
  - mixed translatable + non-translatable in same policy → policy
    dropped from pre-filter;
  - clause-count cap → respects `maxBoolClauses`.
- `ESUtilsAuthFilterTest` — `applyDefaultSearchFilters` integration with the
  translator; feature flag off behavior is identical to today.
- `ESAccessControlUtilTest` — filter mode vs redact mode dispatch.

### Integration / smoke

Under `smoke-test/`:

- Boot DataHub.
- Create two users (admin + low-priv) and one policy granting low-priv view
  on a single dataset's URN.
- Ingest 3 datasets, 2 dashboards, 1 chart.
- Run `searchAcrossEntities`, `autocomplete`, `browseV2`, recommendations
  candidate fetch as each user. Assert different result sets.
- Toggle the feature flag off; rerun; assert identical results to today's
  baseline.

### Backwards-compat regression

A dedicated regression test bank that runs the existing search/browse/autocomplete
suites with `searchFiltering.enabled=false` and asserts byte-for-byte equal
output to a baseline snapshot.

### Performance

A `metadata-io/src/test/java/.../SearchAuthFilterPerfTest.java` with a
synthetic actor holding N=100 policies, asserting < threshold ms added to
query time (threshold TBD per Section 5).

---

## 7. Sequencing / phases

Each phase below is independently shippable.

**Phase 1 — Fix the broken redact path (small, intrinsically valuable).**
Register `restricted` in `entity-registry.yml`, add `RestrictedKey.pdl`,
confirm `RestrictedType` is wired through `GmsGraphQLEngine`. After this,
calling `searchAcrossEntities` with `searchFlags.includeRestricted=true`
stops throwing and returns navigable URNs. Worth shipping on its own because
the `Restricted` GraphQL type is otherwise unreachable.

**Phase 2 — Pre-filter translatable-subset, default OFF.**
Land `SearchPolicyTranslator` + `applyAuthorizationFilter` injection +
`ViewAuthorizationConfiguration.searchFiltering` keys. Default OFF.
Operators opt in. This is the bulk of the work.

**Phase 3 — Post-filter and per-surface integration.**
`dropUnauthorized` in `ESAccessControlUtil`; mode dispatch in
`SearchRequestHandler` (both call sites — lines 490 and 646);
post-filter for all three `EntityRecommendationSource` implementations
(`MostPopularSource`, `RecentlyEditedSource`, `RecentlyViewedSource`);
`LineageSearchService` redact-mode wiring; the `ElasticSearchGraphService`
lineage path; and the `AggregateAcrossEntitiesResolver` decision per Open
Question 2. After this every surface in the Section 4 coverage table is
addressed.

**Phase 4 — Frontend rendering for restricted placeholders** (only needed if
redact is enabled for non-lineage surfaces). Search/browse/autocomplete cards
render a locked tile.

**Phase 5 — Flip default ON in a future major version**, for fresh installs.

Phases 1 and 2 give the bulk of the security value (any policy with a clean
URN-list / domain / tag resource filter is enforced). Phase 3 closes the
plugin-policy gap. Phase 4 is the polish for operators who chose redact mode.

---

## 8. Open questions

Listed only when the source genuinely doesn't answer. Each needs a
maintainer/product decision before I can finalize the corresponding section.

1. **Does Acryl/DataHub Cloud already ship a private implementation we should
   align with?** The fork in `acryldata/datahub` is byte-identical on the
   files touched (verified per briefing). The Cloud product almost certainly
   has one. **Unknown — needs Acryl team input.** Wrong here means we ship a
   diverging API surface.

2. **Pagination and aggregation semantics under filter mode.** When the user
   asks for `count=20, page=2` and 5 hits on page 2 were filtered, do we
   return 15 hits + a smaller `numEntities`, or back-fill from page 3?
   Concretely, the **pre-filter** branch produces correct `numEntities` for
   free (ES counts only post-filter docs), but the **post-filter** branch
   (where `dropUnauthorized` runs after ES returns) needs explicit
   bookkeeping: either accept the resulting "ragged page" UX or over-fetch
   inside the loop until the page is full or scroll exhausts.
   Aggregation surfaces specifically: `AggregateAcrossEntitiesResolver` and
   `GetQuickFiltersResolver` (see the surfaces table in Section 4) call
   `getAggregationsAcrossEntities`. If buckets reflect pre-filter counts the
   facet rail leaks the existence of restricted assets; if post-filter, then
   admins and low-priv users see different facet counts (already true today
   for many other reasons, e.g. soft-deleted). **Unknown — needs product
   decision.** I would default to "post-filter everywhere, `numEntities` and
   bucket counts reflect what the user can see" but the API contract may
   already imply otherwise.
   A related, narrower concern: **scroll-id stability.** ES scroll-IDs cache
   a point-in-time snapshot. If a user's permissions change mid-scroll the
   pre-filter clause baked into the original request becomes stale. Decide
   whether scroll requests should re-evaluate the auth clause on each
   continuation (safer; rebuilds the query) or honor the snapshot (faster;
   matches ES semantics). Default to "re-evaluate" and document.

3. **System-actor paths.** `opContext.isSystemAuth()` exempts a request from
   `ESAccessControlUtil.restrictSearchResult` (verified at line 37) and from
   `AuthorizationUtils.canView`. Confirm that every legitimate
   ingestion/consumer/MCP-processing code path that issues a search is
   running as the system actor. **Unknown — needs an audit:** grep for
   `opContext` construction inside `metadata-jobs/`, `mae-consumer`,
   `mce-consumer`, ingestion REST handlers, and any cron/scheduler job that
   issues searches. If any of those are using a user actor, enabling the
   filter could silently break them.

4. **Glossary-based policies feature flag.** `FeatureFlags.glossaryBasedPoliciesEnabled`
   is UI-only per the briefing. If a future glossary-based policy reaches the
   resource-filter side (rather than just the actor-tagging side), our
   `EntityFieldType.GLOSSARY` translation must agree on semantics. **Unknown
   — confirm with whoever owns the glossary-policies roadmap.**

5. **Latency budget.** Section 5 proposes 1.2× p99 with 50 policies; this
   needs SRE sign-off against an actual production baseline that I could not
   locate in the repo.

---

*End of plan. ~5 pages rendered. Reviewers: please push back on Section 1
(filter vs redact default) and Section 3 (config shape) first — those are
the load-bearing decisions; everything else follows mechanically.*
