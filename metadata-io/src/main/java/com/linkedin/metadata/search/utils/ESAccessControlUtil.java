package com.linkedin.metadata.search.utils;

import static com.datahub.authorization.AuthUtil.VIEW_RESTRICTED_ENTITY_TYPES;

import com.datahub.authorization.AuthUtil;
import com.datahub.authorization.config.ViewAuthorizationConfiguration;
import com.linkedin.common.urn.Urn;
import com.linkedin.data.template.StringArray;
import com.linkedin.metadata.models.registry.EntityRegistry;
import com.linkedin.metadata.search.SearchEntity;
import com.linkedin.metadata.search.SearchEntityArray;
import com.linkedin.metadata.search.SearchResult;
import io.datahubproject.metadata.context.OperationContext;
import io.datahubproject.metadata.services.RestrictedService;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nonnull;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ESAccessControlUtil {
  private ESAccessControlUtil() {}

  /**
   * Top-level dispatch over a {@link SearchResult}. Based on
   * {@code authorization.view.searchFiltering.mode}, either drops unauthorized hits ({@code filter})
   * or rewrites them to {@code urn:li:restricted:*} placeholders ({@code redact}). Falls back to
   * legacy behaviour (honour {@code SearchFlags.includeRestricted} = redact-only) when search
   * filtering is disabled. System actors and view-disabled installations bypass entirely.
   *
   * <p>Mutates {@code searchResult} in place: unauthorized entities are removed from the entity
   * list under filter mode, and {@code numEntities} is decremented accordingly. Under redact mode
   * entities are rewritten in place without removal so totals stay stable.
   */
  public static void enforceViewAuthorization(
      @Nonnull OperationContext opContext, @Nonnull SearchResult searchResult) {
    if (!shouldRun(opContext)) {
      // Preserve the legacy redact path for callers that opted in via SearchFlags.includeRestricted.
      restrictSearchResult(opContext, searchResult);
      return;
    }
    final ViewAuthorizationConfiguration.SearchFilteringConfig sfc =
        opContext.getOperationContextConfig().getViewAuthorizationConfiguration().getSearchFiltering();
    if (sfc.resolvedMode() == ViewAuthorizationConfiguration.SearchFilteringConfig.Mode.REDACT) {
      redactInPlace(opContext, searchResult.getEntities());
      return;
    }
    final int removed = dropUnauthorized(opContext, searchResult.getEntities());
    if (removed > 0) {
      searchResult.setNumEntities(Math.max(0, searchResult.getNumEntities() - removed));
    }
  }

  /**
   * Removes search hits the actor cannot view from {@code searchEntities}. Returns the count of
   * removed hits so callers can adjust {@code numEntities}.
   */
  public static int dropUnauthorized(
      @Nonnull OperationContext opContext, @Nonnull SearchEntityArray searchEntities) {
    if (!shouldRun(opContext)) {
      return 0;
    }
    int removed = 0;
    java.util.Iterator<SearchEntity> it = searchEntities.iterator();
    while (it.hasNext()) {
      SearchEntity searchEntity = it.next();
      final Urn urn = searchEntity.getEntity();
      final String entityType = urn.getEntityType();
      if (VIEW_RESTRICTED_ENTITY_TYPES.contains(entityType)
          && !AuthUtil.canViewEntity(opContext, urn)) {
        it.remove();
        removed++;
      }
    }
    return removed;
  }

  /** List-flavoured variant used by callers that don't have a {@link SearchEntityArray}. */
  public static <T extends Collection<SearchEntity>> int dropUnauthorized(
      @Nonnull OperationContext opContext, @Nonnull T searchEntities) {
    if (!shouldRun(opContext)) {
      return 0;
    }
    final List<SearchEntity> denied = new ArrayList<>();
    for (SearchEntity searchEntity : searchEntities) {
      final Urn urn = searchEntity.getEntity();
      final String entityType = urn.getEntityType();
      if (VIEW_RESTRICTED_ENTITY_TYPES.contains(entityType)
          && !AuthUtil.canViewEntity(opContext, urn)) {
        denied.add(searchEntity);
      }
    }
    searchEntities.removeAll(denied);
    return denied.size();
  }

  /**
   * Dispatches between filter and redact modes for a raw collection of search entities. Returns
   * the count of removed entries so the caller can decrement {@code numEntities} for filter mode;
   * redact mutates entries in place and returns 0.
   */
  public static int enforceViewAuthorization(
      @Nonnull OperationContext opContext, @Nonnull Collection<SearchEntity> searchEntities) {
    if (!shouldRun(opContext)) {
      // Legacy redact path stays active so SearchFlags.includeRestricted still works.
      restrictSearchResult(opContext, searchEntities);
      return 0;
    }
    final ViewAuthorizationConfiguration.SearchFilteringConfig sfc =
        opContext.getOperationContextConfig().getViewAuthorizationConfiguration().getSearchFiltering();
    if (sfc.resolvedMode() == ViewAuthorizationConfiguration.SearchFilteringConfig.Mode.REDACT) {
      redactInPlace(opContext, searchEntities);
      return 0;
    }
    return dropUnauthorized(opContext, searchEntities);
  }

  /**
   * Given an OperationContext and SearchResult, mark the restricted entities. Currently, the entire
   * entity is marked as restricted using the key aspect name.
   *
   * @param searchResult restricted search result
   */
  public static void restrictSearchResult(
      @Nonnull OperationContext opContext, @Nonnull SearchResult searchResult) {
    restrictSearchResult(opContext, searchResult.getEntities());
  }

  public static Collection<SearchEntity> restrictSearchResult(
      @Nonnull OperationContext opContext, Collection<SearchEntity> searchEntities) {
    if (opContext.getOperationContextConfig().getViewAuthorizationConfiguration().isEnabled()
        && !opContext.isSystemAuth()) {
      if (opContext.getSearchContext().isRestrictedSearch()) {
        redactInPlace(opContext, searchEntities);
      }
    }
    return searchEntities;
  }

  public static boolean restrictUrn(@Nonnull OperationContext opContext, @Nonnull Urn urn) {
    if (opContext.getOperationContextConfig().getViewAuthorizationConfiguration().isEnabled()
        && !opContext.isSystemAuth()) {
      return !AuthUtil.canViewEntity(opContext, urn);
    }
    return false;
  }

  private static void redactInPlace(
      @Nonnull OperationContext opContext, @Nonnull Collection<SearchEntity> searchEntities) {
    final EntityRegistry entityRegistry = Objects.requireNonNull(opContext.getEntityRegistry());
    final RestrictedService restrictedService =
        Objects.requireNonNull(opContext.getServicesRegistryContext()).getRestrictedService();
    for (SearchEntity searchEntity : searchEntities) {
      final String entityType = searchEntity.getEntity().getEntityType();
      final com.linkedin.metadata.models.EntitySpec entitySpec =
          entityRegistry.getEntitySpec(entityType);
      if (VIEW_RESTRICTED_ENTITY_TYPES.contains(entityType)
          && !AuthUtil.canViewEntity(opContext, searchEntity.getEntity())) {
        searchEntity.setRestrictedAspects(new StringArray(List.of(entitySpec.getKeyAspectName())));
        searchEntity.setEntity(restrictedService.encryptRestrictedUrn(searchEntity.getEntity()));
      }
    }
  }

  /**
   * True when search-filtering is enabled, view-authorization is enabled, and the actor is not the
   * system actor — i.e. when the per-hit pass should run.
   */
  private static boolean shouldRun(@Nonnull OperationContext opContext) {
    final ViewAuthorizationConfiguration viewConfig =
        opContext.getOperationContextConfig().getViewAuthorizationConfiguration();
    if (viewConfig == null || !viewConfig.isEnabled()) {
      return false;
    }
    final ViewAuthorizationConfiguration.SearchFilteringConfig sfc = viewConfig.getSearchFiltering();
    if (sfc == null || !sfc.isEnabled()) {
      return false;
    }
    return !opContext.isSystemAuth();
  }
}
