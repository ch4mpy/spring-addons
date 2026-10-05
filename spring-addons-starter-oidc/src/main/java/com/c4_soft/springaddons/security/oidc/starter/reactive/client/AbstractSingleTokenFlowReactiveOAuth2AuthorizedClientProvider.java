package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import java.time.Duration;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.util.Assert;
import com.c4_soft.springaddons.security.oidc.starter.TokenFlowRegistry;
import com.c4_soft.springaddons.security.oidc.starter.TokenFlowRegistry.Flow;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * <p>
 * Base for the {@link ReactiveOAuth2AuthorizedClientProvider} decorators making concurrent requests
 * which would send the very same token request share a single flow: the first request to reach the
 * provider runs the flow and the others subscribe to its result.
 * </p>
 * <p>
 * Nothing blocks: requests joining a flow just subscribe to the {@link Mono} the leader shares.
 * Cancelling a request does not cancel the flow it joined, the other requests still get its result.
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @see TokenFlowRegistry
 */
@Slf4j
abstract class AbstractSingleTokenFlowReactiveOAuth2AuthorizedClientProvider
    implements ReactiveOAuth2AuthorizedClientProvider {

  private final ReactiveOAuth2AuthorizedClientProvider delegate;
  private final Duration timeout;
  private final Duration successCachingDuration;
  private final Duration errorCachingDuration;
  private final TokenFlowRegistry<Mono<OAuth2AuthorizedClient>> flows;

  protected AbstractSingleTokenFlowReactiveOAuth2AuthorizedClientProvider(
      ReactiveOAuth2AuthorizedClientProvider delegate, Duration timeout,
      Duration successCachingDuration, Duration errorCachingDuration) {
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
  public final Mono<OAuth2AuthorizedClient> authorize(OAuth2AuthorizationContext context) {
    Assert.notNull(context, "context cannot be null");
    if (!isApplicable(context)) {
      return delegate.authorize(context);
    }

    return Mono.defer(() -> {
      final var key = TokenFlowRegistry.flowKey(context);
      final var lease = flows.acquire(key, flow -> sharedFlow(key, flow, context));

      return lease.leader() ? lease.flow().getPayload() : join(lease.flow(), context);
    });
  }

  /**
   * Builds what the leader shares with the requests joining its flow: a {@link Mono#cache() cached}
   * {@link Mono} subscribing to the delegate only once, however many requests subscribe to it. The
   * side effects are placed upstream of {@code cache()} so that they run once per flow, when the
   * token request actually terminates.
   */
  private Mono<OAuth2AuthorizedClient> sharedFlow(String key, Flow<Mono<OAuth2AuthorizedClient>> flow,
      OAuth2AuthorizationContext context) {
    return Mono.defer(() -> delegate.authorize(context)).doOnSuccess(authorized -> {
      if (authorized == null) {
        // The delegate declined to send a token request: there is no outcome worth sharing
        flows.release(key, flow);
      } else {
        flow.terminated(successCachingDuration);
      }
    }).doOnError(e -> {
      if (e instanceof OAuth2AuthorizationException) {
        flow.terminated(errorCachingDuration);
      } else {
        flows.release(key, flow);
      }
    }).cache();
  }

  private Mono<OAuth2AuthorizedClient> join(Flow<Mono<OAuth2AuthorizedClient>> flow,
      OAuth2AuthorizationContext context) {
    log.debug("Joining a concurrent {} flow for {} and registration {}", flowName(),
        context.getPrincipal().getName(),
        context.getClientRegistration().getRegistrationId());
    return flow.getPayload()
        // Reporting the leader's exception as-is would report that other request's stack-trace
        .onErrorMap(AbstractSingleTokenFlowReactiveOAuth2AuthorizedClientProvider::copyOf)
        .timeout(timeout, Mono.error(() -> serverError(context,
            "Timed out waiting for a concurrent %s flow".formatted(flowName()), null)));
  }

  private static Throwable copyOf(Throwable cause) {
    if (cause instanceof ClientAuthorizationException e) {
      return new ClientAuthorizationException(e.getError(), e.getClientRegistrationId(), e);
    }
    if (cause instanceof OAuth2AuthorizationException e) {
      return new OAuth2AuthorizationException(e.getError(), e);
    }
    return cause;
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
