package com.linkedin.metadata.search.auth;

import com.datahub.authorization.EntityFieldType;
import com.datahub.plugins.auth.authorization.Authorizer;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.linkedin.common.urn.Urn;
import com.linkedin.metadata.authorization.PoliciesConfig;
import com.linkedin.policy.DataHubActorFilter;
import com.linkedin.policy.DataHubPolicyInfo;
import com.linkedin.policy.DataHubResourceFilter;
import com.linkedin.policy.PolicyMatchCriterion;
import com.linkedin.policy.PolicyMatchFilter;
import io.datahubproject.metadata.context.OperationContext;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import lombok.Builder;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;

/**
 * Translates the policies that apply to an actor into an Elasticsearch boolean query representing
 * "entities this actor is allowed to view." Used as a pre-filter on search/autocomplete/browse to
 * keep unauthorized entities out of the result set before they leave Elasticsearch.
 *
 * <p>Translation is best-effort: each policy whose resource filter contains only translatable
 * criteria contributes a {@code must} clause; policies with at least one non-translatable
 * criterion are dropped from the pre-filter and reported via {@link Result#hasNonTranslatable()}
 * so the caller can fall back to the per-hit post-filter ({@code canViewEntity}).
 *
 * <p>Results are cached per (actor, policy-cache-version) so a thundering herd is amortised. The
 * policy-cache-version is supplied by the {@link Authorizer} and bumps on every policy refresh.
 */
@Slf4j
public class SearchPolicyTranslator {

  // ES field names for the translatable subset of EntityFieldType.
  private static final String FIELD_URN = "urn";
  private static final String FIELD_ENTITY_TYPE = "_entityType";
  private static final String FIELD_OWNERS = "owners";
  private static final String FIELD_DOMAINS = "domains";
  private static final String FIELD_TAGS = "tags";
  private static final String FIELD_GLOSSARY_TERMS = "glossaryTerms";
  private static final String FIELD_CONTAINER = "container";
  private static final String FIELD_PLATFORM_INSTANCE = "platformInstance";

  // The actor's session may not change frequently, but the cache is bounded so policy churn
  // doesn't grow unbounded under load.
  private static final int DEFAULT_CACHE_SIZE = 1000;

  private final Cache<CacheKey, Result> cache;

  public SearchPolicyTranslator() {
    this(DEFAULT_CACHE_SIZE);
  }

  public SearchPolicyTranslator(int cacheSize) {
    this.cache = Caffeine.newBuilder().maximumSize(Math.max(1, cacheSize)).build();
  }

  /**
   * Translates the policies that grant the requesting actor view-like privileges into an ES query.
   * Returns {@link Result#denyAll()} when the actor has no applicable policies; the caller treats
   * that as "show nothing" (which is the safe default when filtering is enabled but no policy
   * grants the actor anything).
   */
  @Nonnull
  public Result translate(@Nonnull OperationContext opContext, int maxBoolClauses) {
    Objects.requireNonNull(opContext, "opContext");

    final Urn actorUrn = opContext.getSessionActorContext().getActorUrn();
    final Authorizer authorizer = opContext.getAuthorizationContext().getAuthorizer();
    final long version = authorizer.getPolicyCacheVersion();
    final CacheKey key = new CacheKey(actorUrn.toString(), version);

    Result cached = cache.getIfPresent(key);
    if (cached != null) {
      return cached;
    }

    Set<DataHubPolicyInfo> policies;
    try {
      policies = authorizer.getActorPolicies(actorUrn);
    } catch (RuntimeException e) {
      log.warn(
          "Failed to fetch actor policies for {} — falling back to post-filter only",
          actorUrn,
          e);
      // Fall back: returning a non-translatable result forces the post-filter to run.
      Result fallback = Result.postFilterOnly();
      cache.put(key, fallback);
      return fallback;
    }

    final Collection<Urn> actorGroups = authorizer.getActorGroups(actorUrn);
    Result result = build(actorUrn, actorGroups, policies, maxBoolClauses);
    cache.put(key, result);
    return result;
  }

  @Nonnull
  private Result build(
      @Nonnull Urn actorUrn,
      @Nonnull Collection<Urn> actorGroups,
      @Nonnull Set<DataHubPolicyInfo> policies,
      int maxBoolClauses) {
    final BoolQueryBuilder outer = QueryBuilders.boolQuery();
    int clauseCount = 0;
    boolean hasNonTranslatable = false;
    boolean grantsAnything = false;

    for (DataHubPolicyInfo policy : policies) {
      // Only metadata-type, active policies can grant view-like resource access.
      if (!PoliciesConfig.ACTIVE_POLICY_STATE.equals(policy.getState())) {
        continue;
      }
      if (!PoliciesConfig.METADATA_POLICY_TYPE.equalsIgnoreCase(policy.getType())) {
        continue;
      }

      final PolicyTranslation pt = translatePolicy(actorUrn, actorGroups, policy);
      if (pt == null) {
        // Non-translatable: the post-filter has to handle this policy.
        hasNonTranslatable = true;
        continue;
      }

      grantsAnything = true;
      if (pt.matchAll) {
        // One policy grants everything — short-circuit to a permissive pre-filter.
        return Result.builder()
            .query(null) // null query == no pre-filter constraint
            .hasNonTranslatable(hasNonTranslatable)
            .grantsAnything(true)
            .clauseCount(0)
            .build();
      }

      clauseCount += pt.clauseCount;
      if (clauseCount > maxBoolClauses) {
        // Bail out — caller will see hasNonTranslatable=true and apply onClauseOverflow.
        return Result.builder()
            .query(null)
            .hasNonTranslatable(true)
            .grantsAnything(grantsAnything)
            .clauseCount(clauseCount)
            .overflow(true)
            .build();
      }
      outer.should(pt.query);
    }

    if (!grantsAnything) {
      // No translatable policy granted anything. The post-filter still gets a chance if there
      // were non-translatable policies; otherwise we synthesise a deny-all clause so the search
      // returns empty.
      if (hasNonTranslatable) {
        return Result.postFilterOnly();
      }
      return Result.denyAll();
    }

    outer.minimumShouldMatch(1);
    return Result.builder()
        .query(outer)
        .hasNonTranslatable(hasNonTranslatable)
        .grantsAnything(true)
        .clauseCount(clauseCount)
        .build();
  }

  @Nullable
  private PolicyTranslation translatePolicy(
      @Nonnull Urn actorUrn,
      @Nonnull Collection<Urn> actorGroups,
      @Nonnull DataHubPolicyInfo policy) {
    final BoolQueryBuilder per = QueryBuilders.boolQuery();
    int clauseCount = 0;
    boolean matchAll = true;

    final DataHubResourceFilter resources = policy.getResources();
    if (resources != null) {
      final PolicyMatchFilter filter = resources.getFilter();
      if (filter != null && filter.getCriteria() != null && !filter.getCriteria().isEmpty()) {
        matchAll = false;
        for (PolicyMatchCriterion criterion : filter.getCriteria()) {
          final QueryBuilder clause = translateCriterion(criterion);
          if (clause == null) {
            return null; // non-translatable criterion poisons the policy
          }
          per.must(clause);
          clauseCount += clauseCountOf(criterion);
        }
      }
    }

    // resourceOwners: actor or any of the actor's groups appears in `owners`.
    final DataHubActorFilter actorFilter = policy.getActors();
    if (actorFilter != null && actorFilter.isResourceOwners()) {
      matchAll = false;
      final Set<String> ownerUrns = new LinkedHashSet<>();
      ownerUrns.add(actorUrn.toString());
      for (Urn group : actorGroups) {
        ownerUrns.add(group.toString());
      }
      per.must(QueryBuilders.termsQuery(FIELD_OWNERS + ".keyword", ownerUrns));
      clauseCount += 1;
    }

    if (matchAll) {
      return PolicyTranslation.matchAll();
    }
    return new PolicyTranslation(per, clauseCount, false);
  }

  @Nullable
  private QueryBuilder translateCriterion(@Nonnull PolicyMatchCriterion criterion) {
    final EntityFieldType fieldType;
    try {
      fieldType = EntityFieldType.valueOf(criterion.getField().toUpperCase(Locale.ROOT));
    } catch (IllegalArgumentException e) {
      // Unknown field — caller's authorizer plugin may understand it, but we can't.
      return null;
    }

    final String esField = esFieldFor(fieldType);
    if (esField == null) {
      return null;
    }

    final List<String> values =
        criterion.getValues() == null ? Collections.emptyList() : new ArrayList<>(criterion.getValues());
    if (values.isEmpty()) {
      // An EQUALS with no values matches nothing; a NOT_EQUALS with no values matches everything.
      // The latter contributes nothing to the must-list — skip it (return a match-all).
      switch (criterion.getCondition()) {
        case NOT_EQUALS:
          return QueryBuilders.matchAllQuery();
        case EQUALS:
        case STARTS_WITH:
        default:
          return QueryBuilders.boolQuery().mustNot(QueryBuilders.matchAllQuery());
      }
    }

    // urn and _entityType are already indexed as keyword (no .keyword sub-field). All other
    // translatable fields (owners, domains, tags, …) are text with a .keyword sub-field for
    // exact-match queries.
    final String keyword =
        (esField.equals(FIELD_ENTITY_TYPE) || esField.equals(FIELD_URN))
            ? esField
            : esField + ".keyword";

    switch (criterion.getCondition()) {
      case EQUALS:
        return QueryBuilders.termsQuery(keyword, values);
      case STARTS_WITH:
        BoolQueryBuilder anyPrefix = QueryBuilders.boolQuery();
        for (String v : values) {
          anyPrefix.should(QueryBuilders.prefixQuery(keyword, v));
        }
        anyPrefix.minimumShouldMatch(1);
        return anyPrefix;
      case NOT_EQUALS:
        return QueryBuilders.boolQuery().mustNot(QueryBuilders.termsQuery(keyword, values));
      default:
        return null;
    }
  }

  @Nullable
  private static String esFieldFor(@Nonnull EntityFieldType fieldType) {
    switch (fieldType) {
      case URN:
        return FIELD_URN;
      case TYPE:
        return FIELD_ENTITY_TYPE;
      case OWNER:
        return FIELD_OWNERS;
      case DOMAIN:
        return FIELD_DOMAINS;
      case TAG:
        return FIELD_TAGS;
      case GLOSSARY:
        return FIELD_GLOSSARY_TERMS;
      case CONTAINER:
        return FIELD_CONTAINER;
      case DATA_PLATFORM_INSTANCE:
        return FIELD_PLATFORM_INSTANCE;
      // Deprecated and actor-side fields cannot be translated to an entity-side ES clause.
      case RESOURCE_URN:
      case RESOURCE_TYPE:
      case GROUP_MEMBERSHIP:
      default:
        return null;
    }
  }

  private static int clauseCountOf(@Nonnull PolicyMatchCriterion criterion) {
    // A terms/must_not(terms) clause counts as one regardless of value count in OS/ES bool counting,
    // but a STARTS_WITH translates to one prefix query per value joined by should. Approximate.
    int values = criterion.getValues() == null ? 1 : Math.max(criterion.getValues().size(), 1);
    return criterion.getCondition() == com.linkedin.policy.PolicyMatchCondition.STARTS_WITH
        ? values
        : 1;
  }

  /** Translation product of a single policy. */
  private static final class PolicyTranslation {
    final BoolQueryBuilder query;
    final int clauseCount;
    final boolean matchAll;

    PolicyTranslation(BoolQueryBuilder query, int clauseCount, boolean matchAll) {
      this.query = query;
      this.clauseCount = clauseCount;
      this.matchAll = matchAll;
    }

    static PolicyTranslation matchAll() {
      return new PolicyTranslation(null, 0, true);
    }
  }

  @Value
  private static class CacheKey {
    String actorUrn;
    long policyVersion;
  }

  /** What the translator hands back to {@code ESUtils.applyAuthorizationFilter}. */
  @Value
  @Builder
  public static class Result {
    /**
     * Bool query representing things the actor is allowed to view. {@code null} means "no
     * pre-filter constraint" — either because every policy is permissive or because the caller
     * should fall back to the post-filter exclusively.
     */
    @Nullable BoolQueryBuilder query;

    /** True when at least one policy was dropped from the pre-filter and needs the post-filter. */
    boolean hasNonTranslatable;

    /** True when at least one policy granted the actor a viewable resource. */
    boolean grantsAnything;

    /** Approximate bool-clause count of {@link #query}. */
    int clauseCount;

    /** True when translation aborted because the clause budget was exceeded. */
    boolean overflow;

    public static Result denyAll() {
      BoolQueryBuilder deny =
          QueryBuilders.boolQuery().mustNot(QueryBuilders.matchAllQuery());
      return Result.builder()
          .query(deny)
          .hasNonTranslatable(false)
          .grantsAnything(false)
          .clauseCount(1)
          .build();
    }

    public static Result postFilterOnly() {
      return Result.builder()
          .query(null)
          .hasNonTranslatable(true)
          .grantsAnything(true)
          .clauseCount(0)
          .build();
    }
  }
}
