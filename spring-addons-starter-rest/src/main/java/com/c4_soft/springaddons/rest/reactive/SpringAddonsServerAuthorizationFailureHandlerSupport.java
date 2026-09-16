package com.c4_soft.springaddons.rest.reactive;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * <p>
 * Builds the {@link ReactiveOAuth2AuthorizationFailureHandler} to apply to the components
 * authorizing requests with an OAuth2 client registration ({@code WebClient} exchange filter
 * function).
 * </p>
 * <p>
 * Which store actually holds an authorized client depends on the
 * {@code ReactiveOAuth2AuthorizedClientManager} in the context: an exchange scoped manager saves it
 * to the {@link ServerOAuth2AuthorizedClientRepository} while a manager shared across requests
 * saves it to the {@link ReactiveOAuth2AuthorizedClientService}. Both can be in use at the same
 * time, for instance with `spring-addons-starter-oidc` auto-configuration when some registrations
 * use {@code authorization_code} and others use {@code client_credentials}. Rather than guessing
 * which one backs a given registration, the failure handler removes the authorized client from
 * every store in the context: removing from a store which does not hold it has no effect.
 * </p>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class SpringAddonsServerAuthorizationFailureHandlerSupport {

  private static final String SERVER_WEB_EXCHANGE_ATTR_NAME = ServerWebExchange.class.getName();

  /**
   * @param authorizedClientRepository the exchange scoped store, if any
   * @param authorizedClientService the store shared across requests, if any
   * @return a handler removing the failed authorized client from each of the provided stores, or
   *         empty if none was provided
   */
  public static Optional<ReactiveOAuth2AuthorizationFailureHandler> removeAuthorizedClientFailureHandler(
      Optional<ServerOAuth2AuthorizedClientRepository> authorizedClientRepository,
      Optional<ReactiveOAuth2AuthorizedClientService> authorizedClientService) {

    final List<ReactiveOAuth2AuthorizationFailureHandler> handlers = new ArrayList<>(2);
    authorizedClientRepository
        .map(SpringAddonsServerAuthorizationFailureHandlerSupport::repositoryFailureHandler)
        .ifPresent(handlers::add);
    authorizedClientService
        .map(SpringAddonsServerAuthorizationFailureHandlerSupport::serviceFailureHandler)
        .ifPresent(handlers::add);

    if (handlers.isEmpty()) {
      return Optional.empty();
    }
    if (handlers.size() == 1) {
      return Optional.of(handlers.get(0));
    }
    return Optional.of((exception, principal, attributes) -> Flux.fromIterable(handlers)
        .concatMap(handler -> handler.onAuthorizationFailure(exception, principal, attributes))
        .then());
  }

  /**
   * <p>
   * The repository is keyed by the current {@code ServerWebExchange}, which the OAuth2 client puts
   * in the failure attributes.
   * </p>
   * <p>
   * There is none when the request was issued outside of an exchange, which a manager shared across
   * requests allows (a scheduled task using a {@code client_credentials} registration, for
   * instance). The removal is then skipped: the authorized client can't be in a web session anyway.
   * </p>
   *
   * @param authorizedClientRepository the store to remove the failed authorized client from
   * @return the corresponding failure handler
   */
  public static ReactiveOAuth2AuthorizationFailureHandler repositoryFailureHandler(
      ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
    return new RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler(
        (clientRegistrationId, principal, attributes) -> {
          if (attributes.get(SERVER_WEB_EXCHANGE_ATTR_NAME) instanceof ServerWebExchange exchange) {
            return authorizedClientRepository.removeAuthorizedClient(clientRegistrationId,
                principal, exchange);
          }
          return Mono.empty();
        });
  }

  /**
   * @param authorizedClientService the store to remove the failed authorized client from
   * @return the corresponding failure handler
   */
  public static ReactiveOAuth2AuthorizationFailureHandler serviceFailureHandler(
      ReactiveOAuth2AuthorizedClientService authorizedClientService) {
    return new RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler(
        (clientRegistrationId, principal, attributes) -> authorizedClientService
            .removeAuthorizedClient(clientRegistrationId, principal.getName()));
  }
}
