package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import static com.c4_soft.springaddons.security.oidc.starter.AuthorizedClientTestFixtures.clientCredentialsAuthorizedClient;
import static com.c4_soft.springaddons.security.oidc.starter.AuthorizedClientTestFixtures.clientCredentialsContext;
import static com.c4_soft.springaddons.security.oidc.starter.AuthorizedClientTestFixtures.clientCredentialsRegistration;
import static com.c4_soft.springaddons.security.oidc.starter.AuthorizedClientTestFixtures.context;
import static com.c4_soft.springaddons.security.oidc.starter.reactive.client.SingleRefreshTokenFlowReactiveOAuth2AuthorizedClientProviderTest.delegate;
import static com.c4_soft.springaddons.security.oidc.starter.reactive.client.SingleRefreshTokenFlowReactiveOAuth2AuthorizedClientProviderTest.inParallel;
import static org.assertj.core.api.Assertions.assertThat;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.client.AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ClientCredentialsReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import reactor.core.publisher.Mono;

class SingleClientCredentialsFlowReactiveOAuth2AuthorizedClientProviderTest {

  private static final Duration TIMEOUT = Duration.ofSeconds(5);
  private static final Duration TEN_SECONDS = Duration.ofSeconds(10);
  /** Long enough for all the concurrent requests to reach the provider before the flow completes */
  private static final Duration FLOW_DURATION = Duration.ofMillis(300);

  @Test
  void givenConcurrentRequestsWithoutAuthorizedClient_whenAuthorize_thenASingleFlowIsRun() {
    final var issued = clientCredentialsAuthorizedClient("machine", "batch", "new-at");
    final var delegate = delegate(context -> Mono.just(issued).delayElement(FLOW_DURATION));
    final var provider = provider(delegate);
    final var context = clientCredentialsContext("machine", "batch");

    final var results =
        inParallel(IntStream.range(0, 8).mapToObj(i -> provider.authorize(context)).toList());

    assertThat(delegate.invocations()).isOne();
    assertThat(results).hasSize(8).allMatch(issued::equals);
  }

  @Test
  void givenConcurrentRequestsWithTheSameExpiredClient_whenAuthorize_thenASingleFlowIsRun() {
    final var issued = clientCredentialsAuthorizedClient("machine", "batch", "new-at");
    final var delegate = delegate(context -> Mono.just(issued).delayElement(FLOW_DURATION));
    final var provider = provider(delegate);
    final var context = clientCredentialsContext("machine", "batch", "expired-at");

    final var results =
        inParallel(IntStream.range(0, 8).mapToObj(i -> provider.authorize(context)).toList());

    assertThat(delegate.invocations()).isOne();
    assertThat(results).hasSize(8).allMatch(issued::equals);
  }

  @Test
  void givenConcurrentRequestsForTwoPrincipals_whenAuthorize_thenOneFlowPerPrincipal() {
    final var delegate = delegate(context -> Mono
        .just(clientCredentialsAuthorizedClient("machine", "batch", "new-at"))
        .delayElement(FLOW_DURATION));
    final var provider = provider(delegate);
    final var first = clientCredentialsContext("machine", "batch");
    final var second = clientCredentialsContext("machine", "other-batch");

    inParallel(IntStream.range(0, 8).mapToObj(i -> provider.authorize(i % 2 == 0 ? first : second))
        .toList());

    assertThat(delegate.invocations()).isEqualTo(2);
  }

  @Test
  void givenTheTokenIsStillValid_whenAuthorizeTwice_thenNothingIsShared() {
    final var delegate = delegate(context -> Mono.empty());
    final var provider = provider(delegate);
    final var context = clientCredentialsContext("machine", "batch", "valid-at");

    assertThat(provider.authorize(context).block()).isNull();
    assertThat(provider.authorize(context).block()).isNull();

    assertThat(delegate.invocations()).isEqualTo(2);
  }

  @Test
  void givenAnotherGrantType_whenAuthorize_thenTheDelegateIsCalledForEachRequest() {
    final var delegate = delegate(context -> Mono.just(context.getAuthorizedClient()));
    final var provider = provider(delegate);
    final var context = context("login", "ch4mp", "at", "rt");

    provider.authorize(context).block();
    provider.authorize(context).block();

    assertThat(delegate.invocations()).isEqualTo(2);
  }

  @Test
  void givenAnExpiredTokenInTheAuthorizedClientService_whenConcurrentRequestsToTheManager_thenASingleTokenRequestIsSent() {
    final var registration = clientCredentialsRegistration("machine");
    final var registrations = new InMemoryReactiveClientRegistrationRepository(registration);
    final var authorizedClients = new InMemoryReactiveOAuth2AuthorizedClientService(registrations);
    final var expiredAt = Instant.now().minusSeconds(3600);
    authorizedClients
        .saveAuthorizedClient(
            new OAuth2AuthorizedClient(registration, "batch",
                new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "expired-at",
                    expiredAt.minusSeconds(300), expiredAt)),
            new TestingAuthenticationToken("batch", "secret"))
        .block();

    final var tokenRequests = new AtomicInteger();
    final var clientCredentialsProvider =
        new ClientCredentialsReactiveOAuth2AuthorizedClientProvider();
    clientCredentialsProvider.setAccessTokenResponseClient(grantRequest -> Mono.defer(() -> {
      tokenRequests.incrementAndGet();
      return Mono.just(OAuth2AccessTokenResponse.withToken("new-at")
          .tokenType(OAuth2AccessToken.TokenType.BEARER).expiresIn(300).build());
    }).delayElement(FLOW_DURATION));
    final var manager = new AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager(
        registrations, authorizedClients);
    manager.setAuthorizedClientProvider(provider(clientCredentialsProvider));
    final var request =
        OAuth2AuthorizeRequest.withClientRegistrationId("machine").principal("batch").build();

    final var tokens = inParallel(IntStream.range(0, 32).mapToObj(
        i -> manager.authorize(request).map(client -> client.getAccessToken().getTokenValue()))
        .toList());

    assertThat(tokenRequests).hasValue(1);
    assertThat(tokens).hasSize(32).allMatch("new-at"::equals);
  }

  private static SingleClientCredentialsFlowReactiveOAuth2AuthorizedClientProvider provider(
      ReactiveOAuth2AuthorizedClientProvider delegate) {
    return new SingleClientCredentialsFlowReactiveOAuth2AuthorizedClientProvider(delegate, TIMEOUT,
        TEN_SECONDS, TEN_SECONDS);
  }
}
