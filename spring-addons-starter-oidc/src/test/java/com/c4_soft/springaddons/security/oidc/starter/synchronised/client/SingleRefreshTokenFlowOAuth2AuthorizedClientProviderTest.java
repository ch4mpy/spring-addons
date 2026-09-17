package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import static com.c4_soft.springaddons.security.oidc.starter.AuthorizedClientTestFixtures.authorizedClient;
import static com.c4_soft.springaddons.security.oidc.starter.AuthorizedClientTestFixtures.context;
import static com.c4_soft.springaddons.security.oidc.starter.AuthorizedClientTestFixtures.registration;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

class SingleRefreshTokenFlowOAuth2AuthorizedClientProviderTest {

  private static final Duration TIMEOUT = Duration.ofSeconds(5);
  private static final Duration TEN_SECONDS = Duration.ofSeconds(10);

  @Test
  void givenConcurrentRequestsWithTheSameAuthorizedClient_whenAuthorize_thenASingleFlowIsRun()
      throws Exception {
    final var refreshed = authorizedClient("login", "ch4mp", "new-at", "new-rt");
    final var gate = new CountDownLatch(1);
    final var delegate = delegate(gate, context -> refreshed);
    final var provider = provider(delegate, TEN_SECONDS, TEN_SECONDS);
    final var context = context("login", "ch4mp", "at", "rt");

    final var results = inParallel(gate, IntStream.range(0, 8)
        .<Callable<OAuth2AuthorizedClient>>mapToObj(i -> () -> provider.authorize(context))
        .toList());

    assertThat(delegate.invocations()).isOne();
    assertThat(results).hasSize(8).allMatch(refreshed::equals);
  }

  @Test
  void givenConcurrentRequestsFromTwoSessions_whenAuthorize_thenOneFlowPerSession()
      throws Exception {
    final var gate = new CountDownLatch(1);
    final var delegate = delegate(gate,
        context -> authorizedClient("login", "ch4mp", "new-at", "new-rt"));
    final var provider = provider(delegate, TEN_SECONDS, TEN_SECONDS);
    // Same user, two sessions: two distinct refresh tokens
    final var first = context("login", "ch4mp", "at-1", "rt-1");
    final var second = context("login", "ch4mp", "at-2", "rt-2");

    inParallel(gate,
        IntStream.range(0, 8).<Callable<OAuth2AuthorizedClient>>mapToObj(
            i -> () -> provider.authorize(i % 2 == 0 ? first : second)).toList());

    assertThat(delegate.invocations()).isEqualTo(2);
  }

  @Test
  void givenAFlowJustCompleted_whenAuthorizeWithTheSameStaleClient_thenItsResultIsReused() {
    final var refreshed = authorizedClient("login", "ch4mp", "new-at", "new-rt");
    final var delegate = delegate(context -> refreshed);
    final var provider = provider(delegate, TEN_SECONDS, TEN_SECONDS);
    final var context = context("login", "ch4mp", "at", "rt");

    assertThat(provider.authorize(context)).isEqualTo(refreshed);
    assertThat(provider.authorize(context)).isEqualTo(refreshed);

    assertThat(delegate.invocations()).isOne();
  }

  @Test
  void givenSuccessesAreNotCached_whenAuthorizeTwice_thenTwoFlowsAreRun() {
    final var delegate =
        delegate(context -> authorizedClient("login", "ch4mp", "new-at", "new-rt"));
    final var provider = provider(delegate, Duration.ZERO, TEN_SECONDS);
    final var context = context("login", "ch4mp", "at", "rt");

    provider.authorize(context);
    provider.authorize(context);

    assertThat(delegate.invocations()).isEqualTo(2);
  }

  @Test
  void givenTheDelegateDeclinesToRefresh_whenAuthorizeTwice_thenNothingIsShared() {
    final var delegate = delegate(context -> null);
    final var provider = provider(delegate, TEN_SECONDS, TEN_SECONDS);
    final var context = context("login", "ch4mp", "at", "rt");

    assertThat(provider.authorize(context)).isNull();
    assertThat(provider.authorize(context)).isNull();

    assertThat(delegate.invocations()).isEqualTo(2);
  }

  @Test
  void givenTheFlowFailed_whenAuthorizeWithTheSameStaleClient_thenTheFailureIsReused() {
    final var delegate = delegate(context -> {
      throw invalidGrant();
    });
    final var provider = provider(delegate, TEN_SECONDS, TEN_SECONDS);
    final var context = context("login", "ch4mp", "at", "rt");

    assertThatThrownBy(() -> provider.authorize(context))
        .isInstanceOf(ClientAuthorizationException.class);
    assertThatThrownBy(() -> provider.authorize(context))
        .isInstanceOf(ClientAuthorizationException.class)
        .extracting(e -> ((ClientAuthorizationException) e).getError().getErrorCode())
        .isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);

    assertThat(delegate.invocations()).isOne();
  }

  @Test
  void givenConcurrentRequestsAndAFailingFlow_whenAuthorize_thenAllRequestsGetTheSameError()
      throws Exception {
    final var gate = new CountDownLatch(1);
    final var delegate = delegate(gate, context -> {
      throw invalidGrant();
    });
    final var provider = provider(delegate, TEN_SECONDS, TEN_SECONDS);
    final var context = context("login", "ch4mp", "at", "rt");

    final var errorCodes = inParallel(gate, IntStream.range(0, 8).<Callable<String>>mapToObj(
        i -> () -> {
          try {
            provider.authorize(context);
            return "no error";
          } catch (ClientAuthorizationException e) {
            return e.getError().getErrorCode();
          }
        }).toList());

    assertThat(delegate.invocations()).isOne();
    assertThat(errorCodes).hasSize(8).allMatch(OAuth2ErrorCodes.INVALID_GRANT::equals);
  }

  @Test
  void givenFailuresAreNotCached_whenAuthorizeTwice_thenTwoFlowsAreRun() {
    final var delegate = delegate(context -> {
      throw invalidGrant();
    });
    final var provider = provider(delegate, TEN_SECONDS, Duration.ZERO);
    final var context = context("login", "ch4mp", "at", "rt");

    assertThatThrownBy(() -> provider.authorize(context))
        .isInstanceOf(ClientAuthorizationException.class);
    assertThatThrownBy(() -> provider.authorize(context))
        .isInstanceOf(ClientAuthorizationException.class);

    assertThat(delegate.invocations()).isEqualTo(2);
  }

  @Test
  void givenTheContextHasNoAuthorizedClient_whenAuthorize_thenTheDelegateIsCalledForEachRequest() {
    final var delegate = delegate(context -> null);
    final var provider = provider(delegate, TEN_SECONDS, TEN_SECONDS);
    final var context = OAuth2AuthorizationContext.withClientRegistration(registration("login"))
        .principal(new TestingAuthenticationToken("ch4mp", "secret")).build();

    provider.authorize(context);
    provider.authorize(context);

    assertThat(delegate.invocations()).isEqualTo(2);
  }

  @Test
  void givenAFlowDoesNotComplete_whenJoiningIt_thenTheRequestFailsWithServerError()
      throws Exception {
    final var gate = new CountDownLatch(1);
    final var delegate =
        delegate(gate, context -> authorizedClient("login", "ch4mp", "new-at", "new-rt"));
    final var provider = new SingleRefreshTokenFlowOAuth2AuthorizedClientProvider(delegate,
        Duration.ofSeconds(1), TEN_SECONDS, TEN_SECONDS);
    final var context = context("login", "ch4mp", "at", "rt");

    final var leaderStarted = new CountDownLatch(1);
    final var leader = Executors.newSingleThreadExecutor();
    try {
      leader.submit(() -> {
        leaderStarted.countDown();
        return provider.authorize(context);
      });
      assertThat(leaderStarted.await(5, TimeUnit.SECONDS)).isTrue();
      assertThat(delegate.started().await(5, TimeUnit.SECONDS)).isTrue();

      assertThatThrownBy(() -> provider.authorize(context))
          .isInstanceOf(ClientAuthorizationException.class)
          .extracting(e -> ((ClientAuthorizationException) e).getError().getErrorCode())
          .isEqualTo(OAuth2ErrorCodes.SERVER_ERROR);
    } finally {
      gate.countDown();
      leader.shutdownNow();
    }
  }

  private static SingleRefreshTokenFlowOAuth2AuthorizedClientProvider provider(
      OAuth2AuthorizedClientProvider delegate, Duration successCachingDuration,
      Duration errorCachingDuration) {
    return new SingleRefreshTokenFlowOAuth2AuthorizedClientProvider(delegate, TIMEOUT,
        successCachingDuration, errorCachingDuration);
  }

  private static ClientAuthorizationException invalidGrant() {
    return new ClientAuthorizationException(
        new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "Refresh token is already spent", null),
        "login");
  }

  /**
   * Runs all the given requests at once and waits for all of them to complete. The flow the leader
   * runs is held until all the requests had a chance to reach the provider.
   */
  private static <T> List<T> inParallel(CountDownLatch gate, List<Callable<T>> requests)
      throws Exception {
    final var start = new CountDownLatch(1);
    final var executor = Executors.newFixedThreadPool(requests.size());
    try {
      final var futures = requests.stream().map(request -> executor.submit(() -> {
        start.await();
        return request.call();
      })).toList();
      start.countDown();
      Thread.sleep(200);
      gate.countDown();

      final var results = new ArrayList<T>(requests.size());
      for (var future : futures) {
        results.add(future.get(TIMEOUT.toSeconds(), TimeUnit.SECONDS));
      }
      return results;
    } finally {
      executor.shutdownNow();
    }
  }

  private static CountingDelegate delegate(Refresh refresh) {
    return new CountingDelegate(null, refresh);
  }

  private static CountingDelegate delegate(CountDownLatch gate, Refresh refresh) {
    return new CountingDelegate(gate, refresh);
  }

  interface Refresh {
    OAuth2AuthorizedClient apply(OAuth2AuthorizationContext context);
  }

  /**
   * Counts how many {@code refresh_token} flows are actually run and, when given a gate, holds each
   * of them until the test opens it.
   */
  static final class CountingDelegate implements OAuth2AuthorizedClientProvider {
    private final AtomicInteger invocations = new AtomicInteger();
    private final CountDownLatch started = new CountDownLatch(1);
    private final CountDownLatch gate;
    private final Refresh refresh;

    CountingDelegate(CountDownLatch gate, Refresh refresh) {
      this.gate = gate;
      this.refresh = refresh;
    }

    int invocations() {
      return invocations.get();
    }

    CountDownLatch started() {
      return started;
    }

    @Override
    public OAuth2AuthorizedClient authorize(OAuth2AuthorizationContext context) {
      invocations.incrementAndGet();
      started.countDown();
      if (gate != null) {
        try {
          if (!gate.await(TIMEOUT.toSeconds(), TimeUnit.SECONDS)) {
            throw new IllegalStateException("The test never opened the gate");
          }
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          throw new IllegalStateException(e);
        }
      }
      return refresh.apply(context);
    }
  }
}
