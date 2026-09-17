package com.c4_soft.springaddons.security.oidc.starter;

import static com.c4_soft.springaddons.security.oidc.starter.AuthorizedClientTestFixtures.context;
import static com.c4_soft.springaddons.security.oidc.starter.AuthorizedClientTestFixtures.contextWithScopes;
import static org.assertj.core.api.Assertions.assertThat;
import java.time.Duration;
import org.junit.jupiter.api.Test;

class RefreshTokenFlowRegistryTest {

  @Test
  void givenSameRegistrationPrincipalAndTokens_whenFlowKey_thenSameKey() {
    assertThat(RefreshTokenFlowRegistry.flowKey(context("login", "ch4mp", "at", "rt")))
        .isEqualTo(RefreshTokenFlowRegistry.flowKey(context("login", "ch4mp", "at", "rt")));
  }

  @Test
  void givenAnotherRegistration_whenFlowKey_thenAnotherKey() {
    assertThat(RefreshTokenFlowRegistry.flowKey(context("login", "ch4mp", "at", "rt")))
        .isNotEqualTo(RefreshTokenFlowRegistry.flowKey(context("other", "ch4mp", "at", "rt")));
  }

  @Test
  void givenAnotherPrincipal_whenFlowKey_thenAnotherKey() {
    assertThat(RefreshTokenFlowRegistry.flowKey(context("login", "ch4mp", "at", "rt")))
        .isNotEqualTo(
            RefreshTokenFlowRegistry.flowKey(context("login", "tonton-pirate", "at", "rt")));
  }

  @Test
  void givenAnotherRefreshToken_whenFlowKey_thenAnotherKey() {
    assertThat(RefreshTokenFlowRegistry.flowKey(context("login", "ch4mp", "at", "rt")))
        .isNotEqualTo(RefreshTokenFlowRegistry.flowKey(context("login", "ch4mp", "at", "other")));
  }

  @Test
  void givenAnotherAccessToken_whenFlowKey_thenAnotherKey() {
    assertThat(RefreshTokenFlowRegistry.flowKey(context("login", "ch4mp", "at", "rt")))
        .isNotEqualTo(RefreshTokenFlowRegistry.flowKey(context("login", "ch4mp", "other", "rt")));
  }

  @Test
  void givenValuesConcatenatingToTheSameString_whenFlowKey_thenAnotherKey() {
    assertThat(RefreshTokenFlowRegistry.flowKey(context("login", "ch4mp", "at", "rt")))
        .isNotEqualTo(RefreshTokenFlowRegistry.flowKey(context("logi", "nch4mp", "at", "rt")));
  }

  @Test
  void givenRequestedScopes_whenFlowKey_thenAnotherKeyThanWithoutScopes() {
    assertThat(RefreshTokenFlowRegistry
        .flowKey(contextWithScopes(context("login", "ch4mp", "at", "rt"), "openid")))
            .isNotEqualTo(RefreshTokenFlowRegistry.flowKey(context("login", "ch4mp", "at", "rt")));
  }

  @Test
  void givenSameScopesInAnotherOrder_whenFlowKey_thenSameKey() {
    assertThat(RefreshTokenFlowRegistry
        .flowKey(contextWithScopes(context("login", "ch4mp", "at", "rt"), "openid", "profile")))
            .isEqualTo(RefreshTokenFlowRegistry.flowKey(
                contextWithScopes(context("login", "ch4mp", "at", "rt"), "profile", "openid")));
  }

  @Test
  void givenAFlowIsAcquired_whenAcquiringAgainWithTheSameKey_thenTheCallerIsNotLeader() {
    final var registry = new RefreshTokenFlowRegistry<String>(Duration.ofSeconds(30));

    final var first = registry.acquire("key", flow -> "payload");
    assertThat(first.leader()).isTrue();

    final var second = registry.acquire("key", flow -> "another payload");
    assertThat(second.leader()).isFalse();
    assertThat(second.flow().getPayload()).isEqualTo("payload");
  }

  @Test
  void givenAFlowIsReleased_whenAcquiringAgainWithTheSameKey_thenTheCallerIsLeader() {
    final var registry = new RefreshTokenFlowRegistry<String>(Duration.ofSeconds(30));

    final var first = registry.acquire("key", flow -> "payload");
    registry.release("key", first.flow());
    assertThat(registry.size()).isZero();

    assertThat(registry.acquire("key", flow -> "another payload").leader()).isTrue();
  }

  @Test
  void givenAFlowTerminatedWithoutRetention_whenAcquiringAgainWithTheSameKey_thenTheCallerIsLeader() {
    final var registry = new RefreshTokenFlowRegistry<String>(Duration.ofSeconds(30));

    registry.acquire("key", flow -> "payload").flow().terminated(Duration.ZERO);

    final var second = registry.acquire("key", flow -> "another payload");
    assertThat(second.leader()).isTrue();
    assertThat(second.flow().getPayload()).isEqualTo("another payload");
    assertThat(registry.size()).isOne();
  }

  @Test
  void givenAnotherKey_whenAcquire_thenTheCallerIsLeader() {
    final var registry = new RefreshTokenFlowRegistry<String>(Duration.ofSeconds(30));

    assertThat(registry.acquire("key", flow -> "payload").leader()).isTrue();
    assertThat(registry.acquire("another key", flow -> "another payload").leader()).isTrue();
    assertThat(registry.size()).isEqualTo(2);
  }
}
