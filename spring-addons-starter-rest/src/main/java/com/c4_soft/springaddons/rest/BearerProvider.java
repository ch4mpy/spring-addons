package com.c4_soft.springaddons.rest;

import java.util.Optional;
import org.springframework.http.HttpRequest;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;

/**
 * <p>
 * Strategy to obtain a Bearer token from a {@link HttpRequest}.
 * </p>
 * <p>
 * {@link DefaultSecurityContextBearerProvider}, the default implementation, returns the value of
 * the token stored in the {@link AbstractOAuth2TokenAuthenticationToken} implementation in the
 * security context.
 * </p>
 */
public interface BearerProvider {

  Optional<String> getBearer(HttpRequest request);

}
