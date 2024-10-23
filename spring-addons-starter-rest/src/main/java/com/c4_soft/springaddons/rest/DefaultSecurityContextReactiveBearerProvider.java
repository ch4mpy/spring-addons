package com.c4_soft.springaddons.rest;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.web.reactive.function.client.ClientRequest;
import reactor.core.publisher.Mono;

/**
 * <p>
 * Takes the bearer from any {@link AbstractOAuth2TokenAuthenticationToken} implementation in the
 * security context of an oauth2ResourceServer.
 * </p>
 * <p>
 * Auto-configured if
 * com.c4-soft.springaddons.rest.client.{rest-client-id}.authorization.oauth2.forward-bearer=true
 * and no other BearerProvider bean is exposed.
 * </p>
 */
public class DefaultSecurityContextReactiveBearerProvider implements ReactiveBearerProvider {

  @Override
  public Mono<String> getBearer(ClientRequest request) {
    final var auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth instanceof AbstractOAuth2TokenAuthenticationToken oauth) {
      return Mono.justOrEmpty(oauth.getToken().getTokenValue());
    }
    return Mono.empty();
  }

}
