package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.RefreshTokenOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.util.Assert;
import com.c4_soft.springaddons.security.oidc.starter.RefreshTokenFlowRegistry;
import com.c4_soft.springaddons.security.oidc.starter.RefreshTokenFlowRegistry.Flow;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties.SingleRefreshTokenFlowProperties;
import lombok.extern.slf4j.Slf4j;

/**
 * <p>
 * An {@link OAuth2AuthorizedClientProvider} decorating a
 * {@link RefreshTokenOAuth2AuthorizedClientProvider} so that concurrent requests which would send
 * the very same token request share a single {@code refresh_token} flow, instead of each firing its
 * own.
 * </p>
 * <p>
 * Most authorization servers rotate refresh tokens: the one which was used is revoked as soon as a
 * new one is issued. When a user-agent sends parallel requests while the access token in session is
 * expired, Spring Security fires one {@code refresh_token} flow per request, only one of them can
 * succeed, and all the other requests are answered with a {@code 401}. Two requests sent in less
 * time than a token request takes are enough for this to happen. See <a href=
 * "https://github.com/spring-projects/spring-security/issues/15145">spring-security#15145</a>.
 * </p>
 * <p>
 * Here, the first request to reach the provider runs the flow and the others wait for its result:
 * the authorization server sees a single token request and the refresh token is spent exactly once.
 * Requests from other sessions hold other refresh tokens, so their flows keep running in parallel.
 * The result of a flow is also shared for a short while after it completed, which covers the
 * requests which had loaded the authorized client from the session just before the refreshed one
 * was saved there.
 * </p>
 * <p>
 * This provider de-duplicates flows within a single JVM. In a horizontally scaled application, use
 * sticky sessions (or accept one flow per instance).
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @see RefreshTokenFlowRegistry
 */
@Slf4j
public final class SingleRefreshTokenFlowOAuth2AuthorizedClientProvider
    implements OAuth2AuthorizedClientProvider {

  private final OAuth2AuthorizedClientProvider delegate;
  private final Duration timeout;
  private final Duration successCachingDuration;
  private final Duration errorCachingDuration;
  private final RefreshTokenFlowRegistry<CompletableFuture<OAuth2AuthorizedClient>> flows;

  /**
   * @param delegate the provider actually running the {@code refresh_token} flow, usually a
   *        {@link RefreshTokenOAuth2AuthorizedClientProvider}
   * @param timeout how long a request waits for the flow it joined before giving up
   * @param successCachingDuration how long the result of a successful flow is shared with new
   *        requests still holding the authorized client it was run for
   * @param errorCachingDuration how long the failure of a flow is shared with new requests still
   *        holding the authorized client it was run for
   */
  public SingleRefreshTokenFlowOAuth2AuthorizedClientProvider(
      OAuth2AuthorizedClientProvider delegate, Duration timeout, Duration successCachingDuration,
      Duration errorCachingDuration) {
    Assert.notNull(delegate, "delegate cannot be null");
    Assert.notNull(timeout, "timeout cannot be null");
    Assert.notNull(successCachingDuration, "successCachingDuration cannot be null");
    Assert.notNull(errorCachingDuration, "errorCachingDuration cannot be null");
    this.delegate = delegate;
    this.timeout = timeout;
    this.successCachingDuration = successCachingDuration;
    this.errorCachingDuration = errorCachingDuration;
    this.flows = new RefreshTokenFlowRegistry<>(timeout);
  }

  public SingleRefreshTokenFlowOAuth2AuthorizedClientProvider(
      OAuth2AuthorizedClientProvider delegate, SingleRefreshTokenFlowProperties properties) {
    this(delegate, properties.getTimeout(), properties.getSuccessCachingDuration(),
        properties.getErrorCachingDuration());
  }

  @Override
  public OAuth2AuthorizedClient authorize(OAuth2AuthorizationContext context) {
    Assert.notNull(context, "context cannot be null");
    final var authorizedClient = context.getAuthorizedClient();
    if (authorizedClient == null || authorizedClient.getRefreshToken() == null) {
      // The refresh_token grant can't apply: there is nothing to de-duplicate
      return delegate.authorize(context);
    }

    final var key = RefreshTokenFlowRegistry.flowKey(context);
    final var lease = flows.acquire(key, flow -> new CompletableFuture<>());

    return lease.leader() ? lead(key, lease.flow(), context) : join(lease.flow(), context);
  }

  private OAuth2AuthorizedClient lead(String key,
      Flow<CompletableFuture<OAuth2AuthorizedClient>> flow, OAuth2AuthorizationContext context) {
    final var result = flow.getPayload();
    try {
      final var refreshed = delegate.authorize(context);
      if (refreshed == null) {
        // The delegate declined to refresh: there is no outcome worth sharing
        flows.release(key, flow);
      } else {
        flow.terminated(successCachingDuration);
      }
      result.complete(refreshed);
      return refreshed;

    } catch (Throwable e) {
      if (e instanceof OAuth2AuthorizationException) {
        flow.terminated(errorCachingDuration);
      } else {
        flows.release(key, flow);
      }
      result.completeExceptionally(e);
      throw e;
    }
  }

  private OAuth2AuthorizedClient join(Flow<CompletableFuture<OAuth2AuthorizedClient>> flow,
      OAuth2AuthorizationContext context) {
    log.debug("Joining a concurrent refresh_token flow for {} and registration {}",
        context.getPrincipal().getName(),
        context.getClientRegistration().getRegistrationId());
    try {
      return flow.getPayload().get(timeout.toMillis(), TimeUnit.MILLISECONDS);

    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw serverError(context, "Interrupted while waiting for a concurrent refresh_token flow", e);

    } catch (TimeoutException e) {
      throw serverError(context, "Timed out waiting for a concurrent refresh_token flow", e);

    } catch (ExecutionException e) {
      final var cause = e.getCause();
      if (cause instanceof Error error) {
        throw error;
      }
      throw copyOf(cause, context);
    }
  }

  /**
   * Re-throwing the very exception instance the leader failed with would report that other request's
   * stack-trace. A copy keeps the original as its cause and makes it clear which request actually
   * ran the flow.
   */
  private static RuntimeException copyOf(Throwable cause, OAuth2AuthorizationContext context) {
    if (cause instanceof ClientAuthorizationException e) {
      return new ClientAuthorizationException(e.getError(), e.getClientRegistrationId(), e);
    }
    if (cause instanceof OAuth2AuthorizationException e) {
      return new OAuth2AuthorizationException(e.getError(), e);
    }
    if (cause instanceof RuntimeException e) {
      return e;
    }
    return serverError(context, "A concurrent refresh_token flow failed", cause);
  }

  private static ClientAuthorizationException serverError(OAuth2AuthorizationContext context,
      String message, Throwable cause) {
    // server_error, not invalid_grant: the authorized client must be kept in session, the refresh
    // token it holds was not proven invalid.
    return new ClientAuthorizationException(
        new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, message, null),
        context.getClientRegistration().getRegistrationId(), cause);
  }
}
