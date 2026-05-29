package com.linkedin.metadata.search.auth;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import com.datahub.plugins.auth.authorization.Authorizer;
import com.linkedin.common.UrnArray;
import com.linkedin.common.urn.Urn;
import com.linkedin.common.urn.UrnUtils;
import com.linkedin.data.template.StringArray;
import com.linkedin.metadata.authorization.PoliciesConfig;
import com.linkedin.policy.DataHubActorFilter;
import com.linkedin.policy.DataHubPolicyInfo;
import com.linkedin.policy.DataHubResourceFilter;
import com.linkedin.policy.PolicyMatchCondition;
import com.linkedin.policy.PolicyMatchCriterion;
import com.linkedin.policy.PolicyMatchCriterionArray;
import com.linkedin.policy.PolicyMatchFilter;
import io.datahubproject.metadata.context.ActorContext;
import io.datahubproject.metadata.context.AuthorizationContext;
import io.datahubproject.metadata.context.OperationContext;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import org.testng.annotations.Test;

public class SearchPolicyTranslatorTest {

  private static final Urn USER_A = UrnUtils.getUrn("urn:li:corpuser:a");
  private static final Urn GROUP_X = UrnUtils.getUrn("urn:li:corpGroup:x");
  private static final Urn DOMAIN_FINANCE = UrnUtils.getUrn("urn:li:domain:finance");
  private static final String DATASET_URN_PREFIX =
      "urn:li:dataset:(urn:li:dataPlatform:snowflake,prod.finance.";
  private static final int MAX_CLAUSES = 1024;

  /** Empty policy set: caller has nothing — result is a deny-all that returns no hits. */
  @Test
  public void emptyPolicies_returnsDenyAll() {
    SearchPolicyTranslator translator = new SearchPolicyTranslator(8);
    OperationContext ctx = mockContext(USER_A, Collections.emptySet(), Collections.emptyList());

    SearchPolicyTranslator.Result result = translator.translate(ctx, MAX_CLAUSES);

    assertFalse(result.isGrantsAnything());
    assertNotNull(result.getQuery());
    // Deny-all is must_not(matchAll) — the query shape we documented.
    assertTrue(result.getQuery().toString().contains("must_not"));
  }

  /** An allow-all policy short-circuits to no pre-filter (everything stays in result set). */
  @Test
  public void allowAllPolicy_returnsNoConstraint() {
    SearchPolicyTranslator translator = new SearchPolicyTranslator(8);
    DataHubPolicyInfo policy = activePolicy().setActors(new DataHubActorFilter().setAllUsers(true));

    OperationContext ctx = mockContext(USER_A, Set.of(policy), Collections.emptyList());

    SearchPolicyTranslator.Result result = translator.translate(ctx, MAX_CLAUSES);

    assertTrue(result.isGrantsAnything());
    assertNull(result.getQuery());
  }

  /** URN-list EQUALS criterion translates to a terms query on the keyword field. */
  @Test
  public void urnListEquals_producesTermsClause() {
    SearchPolicyTranslator translator = new SearchPolicyTranslator(8);
    String urn = "urn:li:dataset:(urn:li:dataPlatform:snowflake,a.b.c,PROD)";
    DataHubPolicyInfo policy =
        activePolicy()
            .setActors(new DataHubActorFilter().setAllUsers(true))
            .setResources(resourceFilter("URN", PolicyMatchCondition.EQUALS, urn));

    SearchPolicyTranslator.Result result =
        translator.translate(
            mockContext(USER_A, Set.of(policy), Collections.emptyList()), MAX_CLAUSES);

    assertTrue(result.isGrantsAnything());
    assertNotNull(result.getQuery());
    String body = result.getQuery().toString();
    // urn is already indexed as keyword (no .keyword sub-field), unlike owners/domains/etc.
    assertTrue(body.contains("\"urn\""), body);
    assertTrue(body.contains(urn), body);
  }

  /** STARTS_WITH produces a prefix query rather than a terms query. */
  @Test
  public void startsWith_producesPrefixClause() {
    SearchPolicyTranslator translator = new SearchPolicyTranslator(8);
    DataHubPolicyInfo policy =
        activePolicy()
            .setActors(new DataHubActorFilter().setAllUsers(true))
            .setResources(
                resourceFilter("URN", PolicyMatchCondition.STARTS_WITH, DATASET_URN_PREFIX));

    SearchPolicyTranslator.Result result =
        translator.translate(
            mockContext(USER_A, Set.of(policy), Collections.emptyList()), MAX_CLAUSES);

    String body = result.getQuery().toString();
    assertTrue(body.toLowerCase().contains("prefix"), body);
  }

  /** NOT_EQUALS wraps the terms clause in must_not. */
  @Test
  public void notEquals_producesMustNotClause() {
    SearchPolicyTranslator translator = new SearchPolicyTranslator(8);
    DataHubPolicyInfo policy =
        activePolicy()
            .setActors(new DataHubActorFilter().setAllUsers(true))
            .setResources(
                resourceFilter(
                    "DOMAIN", PolicyMatchCondition.NOT_EQUALS, DOMAIN_FINANCE.toString()));

    SearchPolicyTranslator.Result result =
        translator.translate(
            mockContext(USER_A, Set.of(policy), Collections.emptyList()), MAX_CLAUSES);

    String body = result.getQuery().toString();
    assertTrue(body.contains("must_not"), body);
    assertTrue(body.contains("domains.keyword"), body);
  }

  /**
   * A policy whose criterion targets an unknown field is non-translatable; the policy is dropped
   * from the pre-filter and {@code hasNonTranslatable} flips on.
   */
  @Test
  public void unknownField_marksPolicyNonTranslatable() {
    SearchPolicyTranslator translator = new SearchPolicyTranslator(8);
    DataHubPolicyInfo policy =
        activePolicy()
            .setActors(new DataHubActorFilter().setAllUsers(true))
            .setResources(
                resourceFilter("STRUCTURED_PROPERTY", PolicyMatchCondition.EQUALS, "anything"));

    SearchPolicyTranslator.Result result =
        translator.translate(
            mockContext(USER_A, Set.of(policy), Collections.emptyList()), MAX_CLAUSES);

    assertTrue(result.isHasNonTranslatable());
    assertNull(result.getQuery());
  }

  /**
   * One criterion translatable, one not, in the same policy: the whole policy is dropped from the
   * pre-filter (post-filter has to honour it).
   */
  @Test
  public void mixedCriteria_dropPolicyFromPreFilter() {
    SearchPolicyTranslator translator = new SearchPolicyTranslator(8);

    PolicyMatchCriterion good =
        new PolicyMatchCriterion()
            .setField("DOMAIN")
            .setCondition(PolicyMatchCondition.EQUALS)
            .setValues(new StringArray(List.of(DOMAIN_FINANCE.toString())));
    PolicyMatchCriterion bad =
        new PolicyMatchCriterion()
            .setField("STRUCTURED_PROPERTY")
            .setCondition(PolicyMatchCondition.EQUALS)
            .setValues(new StringArray(List.of("v")));

    DataHubPolicyInfo policy =
        activePolicy()
            .setActors(new DataHubActorFilter().setAllUsers(true))
            .setResources(
                new DataHubResourceFilter()
                    .setFilter(
                        new PolicyMatchFilter()
                            .setCriteria(new PolicyMatchCriterionArray(List.of(good, bad)))));

    SearchPolicyTranslator.Result result =
        translator.translate(
            mockContext(USER_A, Set.of(policy), Collections.emptyList()), MAX_CLAUSES);

    // The policy is dropped from the pre-filter; the post-filter runs to honour it. That state is
    // represented by hasNonTranslatable=true with no pre-filter query.
    assertTrue(result.isHasNonTranslatable());
    assertNull(result.getQuery());
  }

  /**
   * resourceOwners expands {actor} ∪ {actor's groups} into a terms clause on owners. The group
   * URNs must appear in the synthesised query.
   */
  @Test
  public void resourceOwners_expandsActorAndGroups() {
    SearchPolicyTranslator translator = new SearchPolicyTranslator(8);

    DataHubPolicyInfo policy =
        activePolicy().setActors(new DataHubActorFilter().setResourceOwners(true));

    SearchPolicyTranslator.Result result =
        translator.translate(
            mockContext(USER_A, Set.of(policy), List.of(GROUP_X)), MAX_CLAUSES);

    String body = result.getQuery().toString();
    assertTrue(body.contains("owners.keyword"), body);
    assertTrue(body.contains(USER_A.toString()), body);
    assertTrue(body.contains(GROUP_X.toString()), body);
  }

  /** Inactive policies are skipped — they do not contribute a clause. */
  @Test
  public void inactivePolicy_isSkipped() {
    SearchPolicyTranslator translator = new SearchPolicyTranslator(8);
    DataHubPolicyInfo policy =
        new DataHubPolicyInfo()
            .setDisplayName("")
            .setState(PoliciesConfig.INACTIVE_POLICY_STATE)
            .setType(PoliciesConfig.METADATA_POLICY_TYPE)
            .setPrivileges(new StringArray(List.of("VIEW_ENTITY_PAGE")))
            .setActors(new DataHubActorFilter().setAllUsers(true));

    SearchPolicyTranslator.Result result =
        translator.translate(
            mockContext(USER_A, Set.of(policy), Collections.emptyList()), MAX_CLAUSES);

    // Inactive policy yields nothing — deny-all is the safe default.
    assertFalse(result.isGrantsAnything());
  }

  /** Translation is cached so two back-to-back calls for the same actor share work. */
  @Test
  public void cache_returnsSameInstanceForSameVersion() {
    SearchPolicyTranslator translator = new SearchPolicyTranslator(8);
    DataHubPolicyInfo policy =
        activePolicy()
            .setActors(new DataHubActorFilter().setAllUsers(true))
            .setResources(resourceFilter("DOMAIN", PolicyMatchCondition.EQUALS, "urn:li:domain:x"));

    OperationContext ctx = mockContext(USER_A, Set.of(policy), Collections.emptyList());

    SearchPolicyTranslator.Result first = translator.translate(ctx, MAX_CLAUSES);
    SearchPolicyTranslator.Result second = translator.translate(ctx, MAX_CLAUSES);

    assertEquals(first, second);
  }

  // --- helpers -----------------------------------------------------------------------------------

  private static DataHubPolicyInfo activePolicy() {
    return new DataHubPolicyInfo()
        .setDisplayName("")
        .setState(PoliciesConfig.ACTIVE_POLICY_STATE)
        .setType(PoliciesConfig.METADATA_POLICY_TYPE)
        .setPrivileges(new StringArray(List.of("VIEW_ENTITY_PAGE")));
  }

  private static DataHubResourceFilter resourceFilter(
      String field, PolicyMatchCondition cond, String value) {
    return new DataHubResourceFilter()
        .setFilter(
            new PolicyMatchFilter()
                .setCriteria(
                    new PolicyMatchCriterionArray(
                        List.of(
                            new PolicyMatchCriterion()
                                .setField(field)
                                .setCondition(cond)
                                .setValues(new StringArray(List.of(value)))))));
  }

  private static OperationContext mockContext(
      Urn actor, Set<DataHubPolicyInfo> policies, List<Urn> groups) {
    Authorizer authorizer = mock(Authorizer.class);
    when(authorizer.getActorPolicies(actor)).thenReturn(policies);
    when(authorizer.getActorGroups(actor)).thenReturn(groups);
    when(authorizer.getPolicyCacheVersion()).thenReturn(1L);

    AuthorizationContext authzCtx = mock(AuthorizationContext.class);
    when(authzCtx.getAuthorizer()).thenReturn(authorizer);

    ActorContext sessionCtx = mock(ActorContext.class);
    when(sessionCtx.getActorUrn()).thenReturn(actor);

    OperationContext ctx = mock(OperationContext.class);
    when(ctx.getAuthorizationContext()).thenReturn(authzCtx);
    when(ctx.getSessionActorContext()).thenReturn(sessionCtx);
    return ctx;
  }
}
