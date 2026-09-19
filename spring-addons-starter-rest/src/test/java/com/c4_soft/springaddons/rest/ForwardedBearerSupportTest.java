package com.c4_soft.springaddons.rest;

import static org.assertj.core.api.Assertions.assertThat;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;

class ForwardedBearerSupportTest {

  @Test
  void givenJwtAuthenticationToken_whenBearerToken_thenJwtValue() {
    final var jwt = Jwt.withTokenValue("a.b.c").header("alg", "none").subject("ch4mp").build();

    assertThat(ForwardedBearerSupport.bearerToken(new JwtAuthenticationToken(jwt)))
        .contains("a.b.c");
  }

  @Test
  void givenBearerTokenAuthenticationFromIntrospection_whenBearerToken_thenOpaqueTokenValue() {
    final var principal = new OAuth2IntrospectionAuthenticatedPrincipal(
        Map.of("sub", "ch4mp", "active", true), List.of(new SimpleGrantedAuthority("NICE")));
    final var accessToken = new OAuth2AccessToken(TokenType.BEARER, "opaque-token",
        Instant.now(), Instant.now().plusSeconds(60));

    assertThat(ForwardedBearerSupport
        .bearerToken(new BearerTokenAuthentication(principal, accessToken, List.of())))
            .contains("opaque-token");
  }

  @Test
  void givenAuthenticationWithOAuth2TokenPrincipal_whenBearerToken_thenTokenValue() {
    final var jwt = Jwt.withTokenValue("a.b.c").header("alg", "none").subject("ch4mp").build();

    assertThat(ForwardedBearerSupport.bearerToken(new TestingAuthenticationToken(jwt, null)))
        .contains("a.b.c");
  }

  @Test
  void givenAnonymousOrNullAuthentication_whenBearerToken_thenEmpty() {
    assertThat(ForwardedBearerSupport.bearerToken(null)).isEmpty();
    assertThat(ForwardedBearerSupport.bearerToken(new AnonymousAuthenticationToken("key",
        "anonymous", List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS"))))).isEmpty();
    assertThat(ForwardedBearerSupport.bearerToken(new TestingAuthenticationToken("ch4mp", "pwd")))
        .isEmpty();
  }
}
