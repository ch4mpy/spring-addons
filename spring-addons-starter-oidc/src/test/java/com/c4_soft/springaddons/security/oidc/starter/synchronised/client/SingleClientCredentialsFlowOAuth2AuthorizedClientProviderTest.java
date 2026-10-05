package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import static com.c4_soft.springaddons.security.oidc.starter.AuthorizedClientTestFixtures.clientCredentialsAuthorizedClient;
import static com.c4_soft.springaddons.security.oidc.starter.AuthorizedClientTestFixtures.clientCredentialsContext;
import static com.c4_soft.springaddons.security.oidc.starter.AuthorizedClientTestFixtures.clientCredentialsRegistration;
import static com.c4_soft.springaddons.security.oidc.starter.AuthorizedClientTestFixtures.context;
import static com.c4_soft.springaddons.security.oidc.starter.synchronised.client.SingleRefreshTokenFlowOAuth2AuthorizedClientProviderTest.delegate;
import static com.c4_soft.springaddons.security.oidc.starter.synchronised.client.SingleRefreshTokenFlowOAuth2AuthorizedClientProviderTest.inParallel;
import static org.assertj.core.api.Assertions.assertThat;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ClientCredentialsOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;

class SingleClientCredentialsFlowOAuth2AuthorizedClientProviderTest {

  private static final Duration TIMEOUT = Duration.ofSeconds(5);
  private static final Duration TEN_SECONDS = Duration.ofSeconds(10);

  @Test
  void givenConcurrentRequestsWithoutAuthorizedClient_whenAuthorize_thenASingleFlowIsRun()
      throws Exception {
    final var issued = clientCredentialsAuthorizedClient("machine", "batch", "new-at");
    final var gate = new CountDownLatch(1);
    final var delegate = delegate(gate, context -> issued);
    final var provider = provider(delegate);
    final var context = clientCredentialsContext("machine", "batch");

    final var results = inParallel(gate, IntStream.range(0, 8)
        .<Callable<OAuth2AuthorizedClient>>mapToObj(i -> () -> provider.authorize(context))
        .toList());

    assertThat(delegate.invocations()).isOne();
    assertThat(results).hasSize(8).allMatch(issued::equals);
  }

  @Test
  void givenConcurrentRequestsWithTheSameExpiredClient_whenAuthorize_thenASingleFlowIsRun()
      throws Exception {
    final var issued = clientCredentialsAuthorizedClient("machine", "batch", "new-at");
    final var gate = new CountDownLatch(1);
    final var delegate = delegate(gate, context -> issued);
    final var provider = provider(delegate);
    final var context = clientCredentialsContext("machine", "batch", "expired-at");

    final var results = inParallel(gate, IntStream.range(0, 8)
        .<Callable<OAuth2AuthorizedClient>>mapToObj(i -> () -> provider.authorize(context))
        .toList());

    assertThat(delegate.invocations()).isOne();
    assertThat(results).hasSize(8).allMatch(issued::equals);
  }

  @Test
  void givenConcurrentRequestsForTwoPrincipals_whenAuthorize_thenOneFlowPerPrincipal()
      throws Exception {
    final var gate = new CountDownLatch(1);
    final var delegate =
        delegate(gate, context -> clientCredentialsAuthorizedClient("machine", "batch", "new-at"));
    final var provider = provider(delegate);
    final var first = clientCredentialsContext("machine", "batch");
    final var second = clientCredentialsContext("machine", "other-batch");

    inParallel(gate,
        IntStream.range(0, 8).<Callable<OAuth2AuthorizedClient>>mapToObj(
            i -> () -> provider.authorize(i % 2 == 0 ? first : second)).toList());

    assertThat(delegate.invocations()).isEqualTo(2);
  }

  @Test
  void givenTheTokenIsStillValid_whenAuthorizeTwice_thenNothingIsShared() {
    final var delegate = delegate(context -> null);
    final var provider = provider(delegate);
    final var context = clientCredentialsContext("machine", "batch", "valid-at");

    assertThat(provider.authorize(context)).isNull();
    assertThat(provider.authorize(context)).isNull();

    assertThat(delegate.invocations()).isEqualTo(2);
  }

  @Test
  void givenAnotherGrantType_whenAuthorize_thenTheDelegateIsCalledForEachRequest() {
    final var delegate = delegate(context -> context.getAuthorizedClient());
    final var provider = provider(delegate);
    final var context = context("login", "ch4mp", "at", "rt");

    provider.authorize(context);
    provider.authorize(context);

    assertThat(delegate.invocations()).isEqualTo(2);
  }

  @Test
  void givenAnExpiredTokenInTheAuthorizedClientService_whenConcurrentRequestsToTheManager_thenASingleTokenRequestIsSent()
      throws Exception {
    final var registration = clientCredentialsRegistration("machine");
    final var registrations = new InMemoryClientRegistrationRepository(registration);
    final var authorizedClients = new InMemoryOAuth2AuthorizedClientService(registrations);
    final var expiredAt = Instant.now().minusSeconds(3600);
    authorizedClients.saveAuthorizedClient(
        new OAuth2AuthorizedClient(registration, "batch",
            new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "expired-at",
                expiredAt.minusSeconds(300), expiredAt)),
        new TestingAuthenticationToken("batch", "secret"));

    final var gate = new CountDownLatch(1);
    final var tokenRequests = new AtomicInteger();
    final var clientCredentialsProvider = new ClientCredentialsOAuth2AuthorizedClientProvider();
    clientCredentialsProvider.setAccessTokenResponseClient(grantRequest -> {
      tokenRequests.incrementAndGet();
      try {
        gate.await(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
      return OAuth2AccessTokenResponse.withToken("new-at")
          .tokenType(OAuth2AccessToken.TokenType.BEARER).expiresIn(300).build();
    });
    final var manager =
        new AuthorizedClientServiceOAuth2AuthorizedClientManager(registrations, authorizedClients);
    manager.setAuthorizedClientProvider(provider(clientCredentialsProvider));
    final var request =
        OAuth2AuthorizeRequest.withClientRegistrationId("machine").principal("batch").build();

    final var tokens = inParallel(gate,
        IntStream.range(0, 32).<Callable<String>>mapToObj(
            i -> () -> manager.authorize(request).getAccessToken().getTokenValue()).toList());

    assertThat(tokenRequests).hasValue(1);
    assertThat(tokens).hasSize(32).allMatch("new-at"::equals);
  }

  private static SingleClientCredentialsFlowOAuth2AuthorizedClientProvider provider(
      OAuth2AuthorizedClientProvider delegate) {
    return new SingleClientCredentialsFlowOAuth2AuthorizedClientProvider(delegate, TIMEOUT,
        TEN_SECONDS, TEN_SECONDS);
  }
}
