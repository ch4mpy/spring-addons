package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import java.util.Optional;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.web.server.OAuth2AuthorizationRequestRedirectWebFilter;
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
 * When a {@link ClientAuthorizationException} (of any subclass and with any error code) is the
 * error signal of the filter-chain, logs the session out as {@code /logout} does
 * ({@link WebSessionServerLogoutHandler} and {@link SecurityContextServerLogoutHandler}: session
 * invalidated, security context cleared) and answers {@code 401} through the
 * {@link ServerOAuth2ClientRefusalWriter}: no {@code Location} header, no authorization request
 * resolved nor saved. The next request with the stale session cookie is anonymous.
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
 * Inserted after the {@link OAuth2AuthorizationRequestRedirectWebFilter} (closer to the handler)
 * when {@code com.c4-soft.springaddons.oidc.client.client-authorization-required.enabled} is
 * {@code true}, so that the error never reaches that filter.
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Slf4j
public class ClientAuthorizationExceptionWebFilter implements WebFilter {
  private final ServerLogoutHandler logoutHandler = new DelegatingServerLogoutHandler(
      new WebSessionServerLogoutHandler(), new SecurityContextServerLogoutHandler());
  private final ServerOAuth2ClientRefusalWriter refusalWriter;

  public ClientAuthorizationExceptionWebFilter(ServerOAuth2ClientRefusalWriter refusalWriter) {
    this.refusalWriter = refusalWriter;
  }

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    return chain.filter(exchange).onErrorResume(ClientAuthorizationException.class, ex -> {
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
    });
  }
}
