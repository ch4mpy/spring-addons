package com.c4_soft.springaddons.rest;

import java.util.Optional;
import org.springframework.http.HttpRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;

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
public class DefaultSecurityContextBearerProvider implements BearerProvider {

  @Override
  public Optional<String> getBearer(HttpRequest request) {
    final var auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth instanceof AbstractOAuth2TokenAuthenticationToken oauth) {
      return Optional.ofNullable(oauth.getToken().getTokenValue());
    }
    return Optional.empty();
  }

}
