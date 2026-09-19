package com.c4_soft.springaddons.rest;

import java.util.Optional;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.util.StringUtils;

/**
 * Resolves the access token to forward from the {@link Authentication} of a resource server
 * ({@code forward-bearer: true}).
 * <p>
 * This class references resource server types: it is loaded only when Bearer forwarding is
 * configured, which requires the application to be a resource server.
 * </p>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public final class ForwardedBearerSupport {

  private ForwardedBearerSupport() {}

  /**
   * @param authentication the current authentication (can be null or anonymous)
   * @return the access token value if the authentication holds one: any
   *         {@link AbstractOAuth2TokenAuthenticationToken} (JwtAuthenticationToken,
   *         BearerTokenAuthentication for introspection, OAuthentication...) or an authentication
   *         whose principal is an {@link OAuth2Token}
   */
  public static Optional<String> bearerToken(@Nullable Authentication authentication) {
    if (authentication == null) {
      return Optional.empty();
    }
    if (authentication instanceof AbstractOAuth2TokenAuthenticationToken<?> tokenAuthentication) {
      return Optional.ofNullable(tokenAuthentication.getToken()).map(OAuth2Token::getTokenValue)
          .filter(StringUtils::hasText);
    }
    if (authentication.getPrincipal() instanceof OAuth2Token token) {
      return Optional.ofNullable(token.getTokenValue()).filter(StringUtils::hasText);
    }
    return Optional.empty();
  }
}
