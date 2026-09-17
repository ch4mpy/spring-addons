package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import static com.c4_soft.springaddons.security.oidc.starter.AuthorizedClientTestFixtures.authorizedClient;
import static com.c4_soft.springaddons.security.oidc.starter.AuthorizedClientTestFixtures.context;
import static com.c4_soft.springaddons.security.oidc.starter.AuthorizedClientTestFixtures.registration;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

class SingleRefreshTokenFlowReactiveOAuth2AuthorizedClientProviderTest {

  private static final Duration TIMEOUT = Duration.ofSeconds(5);
  private static final Duration TEN_SECONDS = Duration.ofSeconds(10);
  /** Long enough for all the concurrent requests to reach the provider before the flow completes */
  private static final Duration FLOW_DURATION = Duration.ofMillis(300);

  @Test
  void givenConcurrentRequestsWithTheSameAuthorizedClient_whenAuthorize_thenASingleFlowIsRun() {
    final var refreshed = authorizedClient("login", "ch4mp", "new-at", "new-rt");
    final var delegate = delegate(context -> Mono.just(refreshed).delayElement(FLOW_DURATION));
    final var provider = provider(delegate, TEN_SECONDS, TEN_SECONDS);
    final var context = context("login", "ch4mp", "at", "rt");

    final var results = inParallel(IntStream.range(0, 8)
        .mapToObj(i -> provider.authorize(context)).toList());

    assertThat(delegate.invocations()).isOne();
    assertThat(results).hasSize(8).allMatch(refreshed::equals);
  }

  @Test
  void givenConcurrentRequestsFromTwoSessions_whenAuthorize_thenOneFlowPerSession() {
    final var delegate = delegate(context -> Mono
        .just(authorizedClient("login", "ch4mp", "new-at", "new-rt")).delayElement(FLOW_DURATION));
    final var provider = provider(delegate, TEN_SECONDS, TEN_SECONDS);
    // Same user, two sessions: two distinct refresh tokens
    final var first = context("login", "ch4mp", "at-1", "rt-1");
    final var second = context("login", "ch4mp", "at-2", "rt-2");

    inParallel(IntStream.range(0, 8).mapToObj(i -> provider.authorize(i % 2 == 0 ? first : second))
        .toList());

    assertThat(delegate.invocations()).isEqualTo(2);
  }

  @Test
  void givenAFlowJustCompleted_whenAuthorizeWithTheSameStaleClient_thenItsResultIsReused() {
    final var refreshed = authorizedClient("login", "ch4mp", "new-at", "new-rt");
    final var delegate = delegate(context -> Mono.just(refreshed));
    final var provider = provider(delegate, TEN_SECONDS, TEN_SECONDS);
    final var context = context("login", "ch4mp", "at", "rt");

    assertThat(provider.authorize(context).block()).isEqualTo(refreshed);
    assertThat(provider.authorize(context).block()).isEqualTo(refreshed);

    assertThat(delegate.invocations()).isOne();
  }

  @Test
  void givenSuccessesAreNotCached_whenAuthorizeTwice_thenTwoFlowsAreRun() {
    final var delegate =
        delegate(context -> Mono.just(authorizedClient("login", "ch4mp", "new-at", "new-rt")));
    final var provider = provider(delegate, Duration.ZERO, TEN_SECONDS);
    final var context = context("login", "ch4mp", "at", "rt");

    provider.authorize(context).block();
    provider.authorize(context).block();

    assertThat(delegate.invocations()).isEqualTo(2);
  }

  @Test
  void givenTheDelegateDeclinesToRefresh_whenAuthorizeTwice_thenNothingIsShared() {
    final var delegate = delegate(context -> Mono.empty());
    final var provider = provider(delegate, TEN_SECONDS, TEN_SECONDS);
    final var context = context("login", "ch4mp", "at", "rt");

    assertThat(provider.authorize(context).block()).isNull();
    assertThat(provider.authorize(context).block()).isNull();

    assertThat(delegate.invocations()).isEqualTo(2);
  }

  @Test
  void givenTheFlowFailed_whenAuthorizeWithTheSameStaleClient_thenTheFailureIsReused() {
    final var delegate = delegate(context -> Mono.error(invalidGrant()));
    final var provider = provider(delegate, TEN_SECONDS, TEN_SECONDS);
    final var context = context("login", "ch4mp", "at", "rt");

    assertThatThrownBy(() -> provider.authorize(context).block())
        .isInstanceOf(ClientAuthorizationException.class);
    assertThatThrownBy(() -> provider.authorize(context).block())
        .isInstanceOf(ClientAuthorizationException.class)
        .extracting(e -> ((ClientAuthorizationException) e).getError().getErrorCode())
        .isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);

    assertThat(delegate.invocations()).isOne();
  }

  @Test
  void givenConcurrentRequestsAndAFailingFlow_whenAuthorize_thenAllRequestsGetTheSameError() {
    final var delegate = delegate(context -> Mono.delay(FLOW_DURATION)
        .then(Mono.<OAuth2AuthorizedClient>error(invalidGrant())));
    final var provider = provider(delegate, TEN_SECONDS, TEN_SECONDS);
    final var context = context("login", "ch4mp", "at", "rt");

    final var errorCodes = inParallel(IntStream.range(0, 8)
        .mapToObj(i -> provider.authorize(context).map(client -> "no error")
            .onErrorResume(ClientAuthorizationException.class,
                e -> Mono.just(e.getError().getErrorCode())))
        .toList());

    assertThat(delegate.invocations()).isOne();
    assertThat(errorCodes).hasSize(8).allMatch(OAuth2ErrorCodes.INVALID_GRANT::equals);
  }

  @Test
  void givenFailuresAreNotCached_whenAuthorizeTwice_thenTwoFlowsAreRun() {
    final var delegate = delegate(context -> Mono.error(invalidGrant()));
    final var provider = provider(delegate, TEN_SECONDS, Duration.ZERO);
    final var context = context("login", "ch4mp", "at", "rt");

    assertThatThrownBy(() -> provider.authorize(context).block())
        .isInstanceOf(ClientAuthorizationException.class);
    assertThatThrownBy(() -> provider.authorize(context).block())
        .isInstanceOf(ClientAuthorizationException.class);

    assertThat(delegate.invocations()).isEqualTo(2);
  }

  @Test
  void givenTheContextHasNoAuthorizedClient_whenAuthorize_thenTheDelegateIsCalledForEachRequest() {
    final var delegate = delegate(context -> Mono.empty());
    final var provider = provider(delegate, TEN_SECONDS, TEN_SECONDS);
    final var context = OAuth2AuthorizationContext.withClientRegistration(registration("login"))
        .principal(new TestingAuthenticationToken("ch4mp", "secret")).build();

    provider.authorize(context).block();
    provider.authorize(context).block();

    assertThat(delegate.invocations()).isEqualTo(2);
  }

  @Test
  void givenAFlowDoesNotComplete_whenJoiningIt_thenTheRequestFailsWithServerError() {
    final var delegate = delegate(context -> Mono.never());
    final var provider = new SingleRefreshTokenFlowReactiveOAuth2AuthorizedClientProvider(delegate,
        Duration.ofSeconds(1), TEN_SECONDS, TEN_SECONDS);
    final var context = context("login", "ch4mp", "at", "rt");

    // The leader subscribes and never completes
    provider.authorize(context).subscribe();

    assertThatThrownBy(() -> provider.authorize(context).block())
        .isInstanceOf(ClientAuthorizationException.class)
        .extracting(e -> ((ClientAuthorizationException) e).getError().getErrorCode())
        .isEqualTo(OAuth2ErrorCodes.SERVER_ERROR);
  }

  @Test
  void givenTheLeaderCancels_whenJoiningItsFlow_thenTheResultIsStillShared() {
    final var refreshed = authorizedClient("login", "ch4mp", "new-at", "new-rt");
    final var delegate = delegate(context -> Mono.just(refreshed).delayElement(FLOW_DURATION));
    final var provider = provider(delegate, TEN_SECONDS, TEN_SECONDS);
    final var context = context("login", "ch4mp", "at", "rt");

    final var leader = provider.authorize(context).subscribe();
    final var joined = provider.authorize(context);
    leader.dispose();

    assertThat(joined.block()).isEqualTo(refreshed);
    assertThat(delegate.invocations()).isOne();
  }

  private static SingleRefreshTokenFlowReactiveOAuth2AuthorizedClientProvider provider(
      ReactiveOAuth2AuthorizedClientProvider delegate, Duration successCachingDuration,
      Duration errorCachingDuration) {
    return new SingleRefreshTokenFlowReactiveOAuth2AuthorizedClientProvider(delegate, TIMEOUT,
        successCachingDuration, errorCachingDuration);
  }

  private static ClientAuthorizationException invalidGrant() {
    return new ClientAuthorizationException(
        new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "Refresh token is already spent", null),
        "login");
  }

  private static <T> List<T> inParallel(List<Mono<T>> requests) {
    return Flux.merge(requests).collectList().block(TIMEOUT);
  }

  private static CountingDelegate delegate(
      Function<OAuth2AuthorizationContext, Mono<OAuth2AuthorizedClient>> refresh) {
    return new CountingDelegate(refresh);
  }

  /**
   * Counts how many {@code refresh_token} flows are actually subscribed to.
   */
  static final class CountingDelegate implements ReactiveOAuth2AuthorizedClientProvider {
    private final AtomicInteger invocations = new AtomicInteger();
    private final Function<OAuth2AuthorizationContext, Mono<OAuth2AuthorizedClient>> refresh;

    CountingDelegate(Function<OAuth2AuthorizationContext, Mono<OAuth2AuthorizedClient>> refresh) {
      this.refresh = refresh;
    }

    int invocations() {
      return invocations.get();
    }

    @Override
    public Mono<OAuth2AuthorizedClient> authorize(OAuth2AuthorizationContext context) {
      return Mono.defer(() -> {
        invocations.incrementAndGet();
        return refresh.apply(context);
      });
    }
  }
}
