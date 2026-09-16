package com.c4_soft.springaddons.rest.synchronised;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.springframework.security.oauth2.client.OAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.RemoveAuthorizedClientOAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * <p>
 * Builds the {@link OAuth2AuthorizationFailureHandler} to apply to the components authorizing
 * requests with an OAuth2 client registration ({@code RestClient} interceptor or {@code WebClient}
 * exchange filter function).
 * </p>
 * <p>
 * Which store actually holds an authorized client depends on the
 * {@code OAuth2AuthorizedClientManager} in the context: a request scoped manager saves it to the
 * {@link OAuth2AuthorizedClientRepository} while a manager shared across requests saves it to the
 * {@link OAuth2AuthorizedClientService}. Both can be in use at the same time, for instance with
 * `spring-addons-starter-oidc` auto-configuration when some registrations use
 * {@code authorization_code} and others use {@code client_credentials}. Rather than guessing which
 * one backs a given registration, the failure handler removes the authorized client from every
 * store in the context: removing from a store which does not hold it has no effect.
 * </p>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class SpringAddonsServletAuthorizationFailureHandlerSupport {

  private static final String HTTP_SERVLET_REQUEST_ATTR_NAME = HttpServletRequest.class.getName();

  private static final String HTTP_SERVLET_RESPONSE_ATTR_NAME = HttpServletResponse.class.getName();

  /**
   * @param authorizedClientRepository the request scoped store, if any
   * @param authorizedClientService the store shared across requests, if any
   * @return a handler removing the failed authorized client from each of the provided stores, or
   *         empty if none was provided
   */
  public static Optional<OAuth2AuthorizationFailureHandler> removeAuthorizedClientFailureHandler(
      Optional<OAuth2AuthorizedClientRepository> authorizedClientRepository,
      Optional<OAuth2AuthorizedClientService> authorizedClientService) {

    final List<OAuth2AuthorizationFailureHandler> handlers = new ArrayList<>(2);
    authorizedClientRepository
        .map(SpringAddonsServletAuthorizationFailureHandlerSupport::repositoryFailureHandler)
        .ifPresent(handlers::add);
    authorizedClientService
        .map(SpringAddonsServletAuthorizationFailureHandlerSupport::serviceFailureHandler)
        .ifPresent(handlers::add);

    if (handlers.isEmpty()) {
      return Optional.empty();
    }
    if (handlers.size() == 1) {
      return Optional.of(handlers.get(0));
    }
    return Optional.of((exception, principal, attributes) -> handlers
        .forEach(handler -> handler.onAuthorizationFailure(exception, principal, attributes)));
  }

  /**
   * <p>
   * The repository is keyed by the current {@code HttpServletRequest}, which the OAuth2 client puts
   * in the failure attributes.
   * </p>
   * <p>
   * There is none when the request was issued outside of a request context, which a manager shared
   * across requests allows (a scheduled task using a {@code client_credentials} registration, for
   * instance). The removal is then skipped: the authorized client can't be in an HTTP session
   * anyway.
   * </p>
   *
   * @param authorizedClientRepository the store to remove the failed authorized client from
   * @return the corresponding failure handler
   */
  public static OAuth2AuthorizationFailureHandler repositoryFailureHandler(
      OAuth2AuthorizedClientRepository authorizedClientRepository) {
    return new RemoveAuthorizedClientOAuth2AuthorizationFailureHandler(
        (clientRegistrationId, principal, attributes) -> {
          if (attributes
              .get(HTTP_SERVLET_REQUEST_ATTR_NAME) instanceof HttpServletRequest request) {
            authorizedClientRepository.removeAuthorizedClient(clientRegistrationId, principal,
                request, (HttpServletResponse) attributes.get(HTTP_SERVLET_RESPONSE_ATTR_NAME));
          }
        });
  }

  /**
   * @param authorizedClientService the store to remove the failed authorized client from
   * @return the corresponding failure handler
   */
  public static OAuth2AuthorizationFailureHandler serviceFailureHandler(
      OAuth2AuthorizedClientService authorizedClientService) {
    return new RemoveAuthorizedClientOAuth2AuthorizationFailureHandler(
        (clientRegistrationId, principal, attributes) -> authorizedClientService
            .removeAuthorizedClient(clientRegistrationId, principal.getName()));
  }
}
