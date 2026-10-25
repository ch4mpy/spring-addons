package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import java.util.Optional;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.OAuth2AuthorizationRequestRedirectWebFilter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.DelegatingServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.SecurityContextServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.WebSessionServerLogoutHandler;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import com.c4_soft.springaddons.security.oidc.starter.OAuth2ClientRefusal;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * <p>
 * When the error signal of the filter-chain is (or is caused by) a
 * {@link ClientAuthorizationException} (of any subclass and with any error code) for an
 * {@code authorization_code} registration, logs the session out
 * ({@link SecurityContextServerLogoutHandler} and {@link WebSessionServerLogoutHandler}: security
 * context removed, session invalidated) and answers {@code 401} through the
 * {@link ServerOAuth2ClientRefusalWriter}: no {@code Location} header, no authorization request
 * resolved nor saved.
 * </p>
 * <p>
 * Such exceptions are the error signal of
 * {@code ReactiveOAuth2AuthorizedClientManager#authorize()} when it runs inside a request handler
 * (Spring Cloud Gateway's {@code TokenRelay} filter, a {@code WebClient} with an OAuth2 filter
 * function...): a {@link ClientAuthorizationRequiredException} when there is no authorized client
 * for the registration, a plain {@link ClientAuthorizationException} when the authorization server
 * refuses the refresh ({@code invalid_grant}: SSO session or refresh token expired, the authorized
 * client has already been removed by the failure handler). Spring Security's
 * {@link OAuth2AuthorizationRequestRedirectWebFilter} answers the first with a redirection to the
 * authorization endpoint, which a single page or mobile application can't follow, and does not
 * handle the second (it is not an {@code AuthenticationException}, so it surfaces as a server
 * error). In both cases, the session keeps its {@code OAuth2AuthenticationToken}.
 * </p>
 * <p>
 * Errors for registrations with another grant type ({@code client_credentials} for instance) are
 * propagated, and so are errors signaled once the response is committed: logging the user in again
 * would not fix the first, and the second can't be answered with a status any more.
 * </p>
 * <p>
 * Inserted after the {@link OAuth2AuthorizationRequestRedirectWebFilter} (closer to the handler)
 * when {@code com.c4-soft.springaddons.oidc.client.client-authorization-required.enabled} is
 * {@code true}, so that the error never reaches that filter.
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Slf4j
public class ClientAuthorizationExceptionWebFilter implements WebFilter {
  // the security context first: saving an empty one changes the session ID, which must not happen
  // to an invalidated session
  private final ServerLogoutHandler logoutHandler = new DelegatingServerLogoutHandler(
      new SecurityContextServerLogoutHandler(), new WebSessionServerLogoutHandler());
  private final ReactiveClientRegistrationRepository clientRegistrationRepository;
  private final ServerOAuth2ClientRefusalWriter refusalWriter;

  public ClientAuthorizationExceptionWebFilter(
      ReactiveClientRegistrationRepository clientRegistrationRepository,
      ServerOAuth2ClientRefusalWriter refusalWriter) {
    this.clientRegistrationRepository = clientRegistrationRepository;
    this.refusalWriter = refusalWriter;
  }

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    return chain.filter(exchange).onErrorResume(error -> {
      final var authorizationException = clientAuthorizationException(error);
      if (authorizationException.isEmpty() || exchange.getResponse().isCommitted()) {
        return Mono.error(error);
      }
      return clientRegistrationRepository
          .findByRegistrationId(authorizationException.get().getClientRegistrationId())
          .filter(registration -> AuthorizationGrantType.AUTHORIZATION_CODE
              .equals(registration.getAuthorizationGrantType()))
          .flatMap(registration -> logoutAndRefuse(exchange, chain, authorizationException.get())
              .thenReturn(true))
          .switchIfEmpty(Mono.error(error)).then();
    });
  }

  private Mono<Void> logoutAndRefuse(ServerWebExchange exchange, WebFilterChain chain,
      ClientAuthorizationException ex) {
    log.debug(
        "Client must be authorized again for registration {} ({}) on {}: logging out and answering 401",
        ex.getClientRegistrationId(), ex.getError().getErrorCode(),
        exchange.getRequest().getPath());
    return ReactiveSecurityContextHolder.getContext()
        .flatMap(context -> Mono.justOrEmpty(context.getAuthentication())).map(Optional::of)
        .defaultIfEmpty(Optional.<Authentication>empty())
        .flatMap(authentication -> logoutHandler.logout(new WebFilterExchange(exchange, chain),
            authentication.orElse(null)))
        .then(refusalWriter.write(exchange, OAuth2ClientRefusal.authorizationRequired(ex)));
  }

  /**
   * @return the first {@link ClientAuthorizationException} in the cause chain of the error (a
   *         {@code retryWhen} or a circuit-breaker can wrap it)
   */
  static Optional<ClientAuthorizationException> clientAuthorizationException(Throwable error) {
    var current = error;
    while (current != null) {
      if (current instanceof ClientAuthorizationException authorizationException) {
        return Optional.of(authorizationException);
      }
      if (current.getCause() == current) {
        break;
      }
      current = current.getCause();
    }
    return Optional.empty();
  }
}
