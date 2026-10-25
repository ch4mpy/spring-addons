package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import org.springframework.security.oauth2.client.web.server.OAuth2AuthorizationRequestRedirectWebFilter;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import com.c4_soft.springaddons.security.oidc.starter.OAuth2ClientRefusal;
import com.c4_soft.springaddons.security.oidc.starter.properties.InvalidRedirectionUriException;
import reactor.core.publisher.Mono;

/**
 * <p>
 * Answers {@code 400} (through the {@link ServerOAuth2ClientRefusalWriter}) to requests carrying a
 * post-login success or failure URI (header or query parameter) which does not match
 * {@code com.c4-soft.springaddons.oidc.client.post-login-allowed-uri-patterns}: the
 * {@link InvalidRedirectionUriException} error signal of the authorization request resolver is
 * turned into a response. Nothing was stored in session and no authorization request was resolved.
 * </p>
 * <p>
 * Inserted before the {@link OAuth2AuthorizationRequestRedirectWebFilter}, which lets this error
 * propagate.
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
public class InvalidPostLoginUriWebFilter implements WebFilter {
  private final ServerOAuth2ClientRefusalWriter refusalWriter;

  public InvalidPostLoginUriWebFilter(ServerOAuth2ClientRefusalWriter refusalWriter) {
    this.refusalWriter = refusalWriter;
  }

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    return chain.filter(exchange).onErrorResume(InvalidRedirectionUriException.class,
        ex -> refusalWriter.write(exchange, OAuth2ClientRefusal.invalidPostLoginUri(ex)));
  }
}
