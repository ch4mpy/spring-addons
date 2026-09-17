package com.c4_soft.springaddons.security.oidc.starter;

import java.time.Instant;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;

/**
 * Authorized clients and authorization contexts for the tests around the {@code refresh_token} flow.
 */
public class AuthorizedClientTestFixtures {

  public static OAuth2AuthorizationContext context(String registrationId, String principalName,
      String accessToken, String refreshToken) {
    return OAuth2AuthorizationContext
        .withAuthorizedClient(
            authorizedClient(registrationId, principalName, accessToken, refreshToken))
        .principal(new TestingAuthenticationToken(principalName, "secret")).build();
  }

  public static OAuth2AuthorizationContext contextWithScopes(OAuth2AuthorizationContext context,
      String... scopes) {
    return OAuth2AuthorizationContext.withAuthorizedClient(context.getAuthorizedClient())
        .principal(context.getPrincipal())
        .attribute(OAuth2AuthorizationContext.REQUEST_SCOPE_ATTRIBUTE_NAME, scopes).build();
  }

  public static OAuth2AuthorizedClient authorizedClient(String registrationId,
      String principalName, String accessToken, String refreshToken) {
    final var now = Instant.parse("2026-09-16T00:00:00Z");
    return new OAuth2AuthorizedClient(registration(registrationId), principalName,
        new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken, now,
            now.plusSeconds(300)),
        new OAuth2RefreshToken(refreshToken, now));
  }

  public static ClientRegistration registration(String registrationId) {
    return ClientRegistration.withRegistrationId(registrationId).clientId(registrationId)
        .clientSecret("secret")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .authorizationUri("https://localhost/auth").tokenUri("https://localhost/token")
        .redirectUri("https://localhost/login/oauth2/code/%s".formatted(registrationId)).build();
  }
}
