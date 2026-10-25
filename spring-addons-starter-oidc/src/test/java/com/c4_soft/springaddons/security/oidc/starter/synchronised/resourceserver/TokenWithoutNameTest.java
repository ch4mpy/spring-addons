package com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerProperties;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.web.server.autoconfigure.ServerProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

/**
 * A bearer token with neither the username claim nor {@code sub} is refused with a {@code 401}
 * (an {@link InvalidBearerTokenException}), not a {@code 500} (issue #319). Such a token must be
 * refused (RFC 9068, section 2.2): only the status changes.
 */
class TokenWithoutNameTest {
  private static final String ISS = "https://localhost:8443/realms/test";
  private static final String OPS_PREFIX = "com.c4-soft.springaddons.oidc.ops[0].";

  private final WebApplicationContextRunner jwtRunner = new WebApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(ConfigurationPropertiesAutoConfiguration.class, SpringAddonsOidcProperties.class,
          SpringAddonsOidcResourceServerBeans.class, ServerProperties.class))
      .withPropertyValues(OPS_PREFIX + "iss=" + ISS,
          "com.c4-soft.springaddons.oidc.resourceserver.permit-all=/public");

  private final OpaqueTokenIntrospector introspector = mock(OpaqueTokenIntrospector.class);

  private final WebApplicationContextRunner introspectionRunner = new WebApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(ConfigurationPropertiesAutoConfiguration.class, SpringAddonsOidcProperties.class,
          OAuth2ResourceServerProperties.class, SpringAddonsOidcResourceServerBeans.class,
          ServerProperties.class))
      .withBean(OpaqueTokenIntrospector.class, () -> introspector)
      .withPropertyValues(OPS_PREFIX + "iss=" + ISS,
          "com.c4-soft.springaddons.oidc.resourceserver.permit-all=/public",
          "spring.security.oauth2.resourceserver.opaquetoken.introspection-uri=" + ISS
              + "/protocol/openid-connect/token/introspect");

  // --- converter level ---

  @Test
  void givenJwtWithoutUsernameClaimNorSub_whenConvert_thenInvalidBearerTokenException() {
    jwtRunner.run(context -> {
      final var converter = context.getBean(JwtAbstractAuthenticationTokenConverter.class);

      assertThatThrownBy(() -> converter.convert(jwt(Map.of("iss", ISS))))
          .isInstanceOf(InvalidBearerTokenException.class)
          .isInstanceOf(AuthenticationException.class).hasMessageContaining("sub")
          .hasMessageNotContaining(ISS);
    });
  }

  @Test
  void givenJwtWithSubOnly_whenConvert_thenNameIsSub() {
    jwtRunner.run(context -> {
      final var converter = context.getBean(JwtAbstractAuthenticationTokenConverter.class);

      assertThat(converter.convert(jwt(Map.of("iss", ISS, "sub", "ch4mp"))).getName())
          .isEqualTo("ch4mp");
    });
  }

  @Test
  void givenUsernameClaimConfigured_whenConvert_thenNameIsUsernameClaimOrElseSub() {
    jwtRunner.withPropertyValues(OPS_PREFIX + "username-claim=preferred_username")
        .run(context -> {
          final var converter = context.getBean(JwtAbstractAuthenticationTokenConverter.class);

          assertThat(converter
              .convert(jwt(Map.of("iss", ISS, "sub", "123", "preferred_username", "ch4mp")))
              .getName()).isEqualTo("ch4mp");
          assertThat(converter.convert(jwt(Map.of("iss", ISS, "sub", "123"))).getName())
              .isEqualTo("123");
          assertThatThrownBy(() -> converter.convert(jwt(Map.of("iss", ISS))))
              .isInstanceOf(InvalidBearerTokenException.class)
              .hasMessageContaining("preferred_username");
        });
  }

  @Test
  void givenIntrospectionResultWithoutUsernameClaimNorSub_whenConvert_thenInvalidBearerTokenException() {
    introspectionRunner.run(context -> {
      final var converter = context.getBean(OpaqueTokenAuthenticationConverter.class);

      assertThatThrownBy(() -> converter.convert("opaque", principal(Map.of("iss", ISS))))
          .isInstanceOf(InvalidBearerTokenException.class)
          .isInstanceOf(AuthenticationException.class);
      assertThat(converter.convert("opaque", principal(Map.of("iss", ISS, "sub", "ch4mp")))
          .getName()).isEqualTo("ch4mp");
    });
  }

  // --- filter chain level: 401 through the entry point, on a permit-all path too ---

  @Test
  void givenJwtWithoutUsernameClaimNorSub_whenRequestPermitAllPath_then401InvalidToken() {
    jwtRunner.withBean(SpringAddonsJwtDecoderFactory.class,
        () -> (jwkSetUri, issuer, audience) -> token -> jwt(Map.of("iss", ISS))).run(context -> {
          final var response = perform(context, "Bearer " + plainJwt(ISS));

          assertThat(response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
          assertThat(response.getHeader(HttpHeaders.WWW_AUTHENTICATE)).startsWith("Bearer")
              .contains("invalid_token");
        });
  }

  @Test
  void givenJwtWithSub_whenRequestPermitAllPath_thenPassesThrough() {
    jwtRunner.withBean(SpringAddonsJwtDecoderFactory.class,
        () -> (jwkSetUri, issuer, audience) -> token -> jwt(Map.of("iss", ISS, "sub", "ch4mp")))
        .run(context -> {
          final var response = perform(context, "Bearer " + plainJwt(ISS));

          assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
        });
  }

  @Test
  void givenIntrospectionResultWithoutUsernameClaimNorSub_whenRequestPermitAllPath_then401InvalidToken() {
    when(introspector.introspect(anyString())).thenReturn(principal(Map.of("iss", ISS)));
    introspectionRunner.run(context -> {
      final var response = perform(context, "Bearer opaque");

      assertThat(response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
      assertThat(response.getHeader(HttpHeaders.WWW_AUTHENTICATE)).startsWith("Bearer")
          .contains("invalid_token");
    });
  }

  private static MockHttpServletResponse perform(
      org.springframework.context.ApplicationContext context, String authorization)
      throws Exception {
    final var filterChain = new FilterChainProxy(context.getBean(SecurityFilterChain.class));
    final var request = new MockHttpServletRequest("GET", "/public");
    request.addHeader(HttpHeaders.AUTHORIZATION, authorization);
    final var response = new MockHttpServletResponse();
    filterChain.doFilter(request, response, new MockFilterChain());
    return response;
  }

  private static Jwt jwt(Map<String, Object> claims) {
    return Jwt.withTokenValue("test").header("alg", "none").claims(c -> c.putAll(claims)).build();
  }

  private static OAuth2IntrospectionAuthenticatedPrincipal principal(
      Map<String, Object> attributes) {
    return new OAuth2IntrospectionAuthenticatedPrincipal(attributes, List.of());
  }

  /** The authentication manager resolver parses the bearer string to read its issuer */
  private static String plainJwt(String issuer) {
    return new PlainJWT(new JWTClaimsSet.Builder().issuer(issuer).build()).serialize();
  }
}
