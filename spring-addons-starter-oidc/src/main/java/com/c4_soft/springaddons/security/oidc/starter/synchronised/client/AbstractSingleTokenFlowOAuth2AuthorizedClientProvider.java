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
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.util.Assert;
import com.c4_soft.springaddons.security.oidc.starter.TokenFlowRegistry;
import com.c4_soft.springaddons.security.oidc.starter.TokenFlowRegistry.Flow;
import lombok.extern.slf4j.Slf4j;

/**
 * <p>
 * Base for the {@link OAuth2AuthorizedClientProvider} decorators making concurrent requests which
 * would send the very same token request share a single flow: the first request to reach the
 * provider runs the flow and the others wait for its result.
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @see TokenFlowRegistry
 */
@Slf4j
abstract class AbstractSingleTokenFlowOAuth2AuthorizedClientProvider
    implements OAuth2AuthorizedClientProvider {

  private final OAuth2AuthorizedClientProvider delegate;
  private final Duration timeout;
  private final Duration successCachingDuration;
  private final Duration errorCachingDuration;
  private final TokenFlowRegistry<CompletableFuture<OAuth2AuthorizedClient>> flows;

  protected AbstractSingleTokenFlowOAuth2AuthorizedClientProvider(
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
    this.flows = new TokenFlowRegistry<>(timeout);
  }

  /**
   * @param context the authorization context to authorize
   * @return whether the grant handled by the delegate can apply to this context. When it can't,
   *         there is nothing to de-duplicate and the delegate is called directly.
   */
  protected abstract boolean isApplicable(OAuth2AuthorizationContext context);

  /**
   * @return the name of the flow, for logs and error messages
   */
  protected abstract String flowName();

  @Override
  public final OAuth2AuthorizedClient authorize(OAuth2AuthorizationContext context) {
    Assert.notNull(context, "context cannot be null");
    if (!isApplicable(context)) {
      return delegate.authorize(context);
    }

    final var key = TokenFlowRegistry.flowKey(context);
    final var lease = flows.acquire(key, flow -> new CompletableFuture<>());

    return lease.leader() ? lead(key, lease.flow(), context) : join(lease.flow(), context);
  }

  private OAuth2AuthorizedClient lead(String key,
      Flow<CompletableFuture<OAuth2AuthorizedClient>> flow, OAuth2AuthorizationContext context) {
    final var result = flow.getPayload();
    try {
      final var authorized = delegate.authorize(context);
      if (authorized == null) {
        // The delegate declined to send a token request: there is no outcome worth sharing
        flows.release(key, flow);
      } else {
        flow.terminated(successCachingDuration);
      }
      result.complete(authorized);
      return authorized;

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
    log.debug("Joining a concurrent {} flow for {} and registration {}", flowName(),
        context.getPrincipal().getName(),
        context.getClientRegistration().getRegistrationId());
    try {
      return flow.getPayload().get(timeout.toMillis(), TimeUnit.MILLISECONDS);

    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw serverError(context,
          "Interrupted while waiting for a concurrent %s flow".formatted(flowName()), e);

    } catch (TimeoutException e) {
      throw serverError(context,
          "Timed out waiting for a concurrent %s flow".formatted(flowName()), e);

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
  private RuntimeException copyOf(Throwable cause, OAuth2AuthorizationContext context) {
    if (cause instanceof ClientAuthorizationException e) {
      return new ClientAuthorizationException(e.getError(), e.getClientRegistrationId(), e);
    }
    if (cause instanceof OAuth2AuthorizationException e) {
      return new OAuth2AuthorizationException(e.getError(), e);
    }
    if (cause instanceof RuntimeException e) {
      return e;
    }
    return serverError(context, "A concurrent %s flow failed".formatted(flowName()), cause);
  }

  private static ClientAuthorizationException serverError(OAuth2AuthorizationContext context,
      String message, Throwable cause) {
    // server_error, not invalid_grant: the authorized client must be kept in its store, the token
    // it holds was not proven invalid.
    return new ClientAuthorizationException(
        new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, message, null),
        context.getClientRegistration().getRegistrationId(), cause);
  }
}
