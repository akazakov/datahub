package com.datahub.authorization.config;

import java.util.Locale;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder(toBuilder = true)
@Data
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@NoArgsConstructor(access = AccessLevel.PACKAGE)
public class ViewAuthorizationConfiguration {
  private boolean enabled;
  private ViewAuthorizationRecommendationsConfig recommendations;
  private SearchFilteringConfig searchFiltering;

  /**
   * Returns the configured search-filtering block, or a disabled default when unset (Spring binds
   * it from YAML at runtime; the default keeps tests and bare configurations safe).
   */
  public SearchFilteringConfig getSearchFiltering() {
    if (searchFiltering == null) {
      return SearchFilteringConfig.disabled();
    }
    return searchFiltering;
  }

  @Builder(toBuilder = true)
  @Data
  @AllArgsConstructor(access = AccessLevel.PACKAGE)
  @NoArgsConstructor(access = AccessLevel.PACKAGE)
  public static class ViewAuthorizationRecommendationsConfig {
    private boolean peerGroupEnabled;
  }

  /**
   * Configuration for search-time permission filtering. When enabled (alongside view.enabled), the
   * search/autocomplete/browse paths inject an authorization clause derived from the actor's
   * policies and apply a post-filter pass for non-translatable policies. The {@link Mode} selects
   * whether unauthorized hits are dropped (filter) or rewritten to restricted URNs (redact).
   */
  @Builder(toBuilder = true)
  @Data
  @AllArgsConstructor(access = AccessLevel.PACKAGE)
  @NoArgsConstructor(access = AccessLevel.PACKAGE)
  public static class SearchFilteringConfig {
    private boolean enabled;
    private String mode;
    private SurfacesConfig surfaces;
    private int maxBoolClauses;
    private String onClauseOverflow;

    public static SearchFilteringConfig disabled() {
      return SearchFilteringConfig.builder()
          .enabled(false)
          .mode("filter")
          .maxBoolClauses(1024)
          .onClauseOverflow("postFilter")
          .surfaces(SurfacesConfig.builder().build())
          .build();
    }

    public SurfacesConfig getSurfaces() {
      if (surfaces == null) {
        return SurfacesConfig.builder().build();
      }
      return surfaces;
    }

    public Mode resolvedMode() {
      return Mode.fromString(this.mode);
    }

    public OverflowStrategy resolvedOverflow() {
      return OverflowStrategy.fromString(this.onClauseOverflow);
    }

    public enum Mode {
      FILTER,
      REDACT;

      public static Mode fromString(String value) {
        if (value == null) {
          return FILTER;
        }
        try {
          return Mode.valueOf(value.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
          return FILTER;
        }
      }
    }

    public enum OverflowStrategy {
      POST_FILTER,
      FAIL_CLOSED;

      public static OverflowStrategy fromString(String value) {
        if (value == null) {
          return POST_FILTER;
        }
        switch (value.toLowerCase(Locale.ROOT)) {
          case "failclosed":
          case "fail_closed":
            return FAIL_CLOSED;
          case "postfilter":
          case "post_filter":
          default:
            return POST_FILTER;
        }
      }
    }
  }

  @Builder(toBuilder = true)
  @Data
  @AllArgsConstructor(access = AccessLevel.PACKAGE)
  @NoArgsConstructor(access = AccessLevel.PACKAGE)
  public static class SurfacesConfig {
    private boolean search;
    private boolean autocomplete;
    private boolean browse;
    private boolean recommendations;
    private boolean lineage;
  }
}
