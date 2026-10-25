package com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver;

import static com.c4_soft.springaddons.security.oidc.starter.ResourceServerTestFixtures.INTROSPECTION_URI_PROPERTY;
import static com.c4_soft.springaddons.security.oidc.starter.ResourceServerTestFixtures.ISSUER;
import static com.c4_soft.springaddons.security.oidc.starter.ResourceServerTestFixtures.ISSUER_PROPERTY;
import static com.c4_soft.springaddons.security.oidc.starter.ResourceServerTestFixtures.PERMIT_ALL_PUBLIC_PROPERTY;
import static com.c4_soft.springaddons.security.oidc.starter.ResourceServerTestFixtures.USERNAME_CLAIM_PROPERTY;
import static com.c4_soft.springaddons.security.oidc.starter.ResourceServerTestFixtures.introspectionPrincipal;
import static com.c4_soft.springaddons.security.oidc.starter.ResourceServerTestFixtures.jwt;
import static com.c4_soft.springaddons.security.oidc.starter.ResourceServerTestFixtures.plainJwt;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;

/**
 * A bearer token with neither the username claim nor {@code sub} is refused with a {@code 401}
 * (an {@link InvalidBearerTokenException}), not a {@code 500} (issue #319). Such a token must be
 * refused (RFC 9068, section 2.2): only the status changes.
 */
class TokenWithoutNameTest {

  private final WebApplicationContextRunner jwtRunner = new WebApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(ConfigurationPropertiesAutoConfiguration.class,
          SpringAddonsOidcProperties.class, SpringAddonsOidcResourceServerBeans.class,
          ServerProperties.class))
      .withPropertyValues(ISSUER_PROPERTY, USERNAME_CLAIM_PROPERTY, PERMIT_ALL_PUBLIC_PROPERTY);

  private final OpaqueTokenIntrospector introspector = mock(OpaqueTokenIntrospector.class);

  private final WebApplicationContextRunner introspectionRunner = jwtRunner
      .withConfiguration(AutoConfigurations.of(OAuth2ResourceServerProperties.class))
      .withBean(OpaqueTokenIntrospector.class, () -> introspector)
      .withPropertyValues(INTROSPECTION_URI_PROPERTY);

  // --- converter level: the default converters delegate to PrincipalNameResolver, with the
  // configured username claim ---

  @Test
  void givenJwtConverter_whenConvert_thenNameIsResolvedByPrincipalNameResolver() {
    jwtRunner.run(context -> {
      final var converter = context.getBean(JwtAbstractAuthenticationTokenConverter.class);

      assertThatThrownBy(() -> converter.convert(jwt(Map.of("iss", ISSUER))))
          .isInstanceOf(InvalidBearerTokenException.class);
      assertThat(converter
          .convert(jwt(Map.of("iss", ISSUER, "sub", "123", "preferred_username", "ch4mp")))
          .getName()).isEqualTo("ch4mp");
    });
  }

  @Test
  void givenIntrospectionConverter_whenConvert_thenNameIsResolvedByPrincipalNameResolver() {
    introspectionRunner.run(context -> {
      final var converter = context.getBean(OpaqueTokenAuthenticationConverter.class);

      assertThatThrownBy(
          () -> converter.convert("opaque", introspectionPrincipal(Map.of("iss", ISSUER))))
              .isInstanceOf(InvalidBearerTokenException.class);
      assertThat(converter.convert("opaque",
          introspectionPrincipal(Map.of("iss", ISSUER, "sub", "123", "preferred_username", "ch4mp")))
          .getName()).isEqualTo("ch4mp");
    });
  }

  // --- filter chain level: 401 through the entry point, on a permit-all path too ---

  @Test
  void givenJwtWithoutUsernameClaimNorSub_whenRequestPermitAllPath_then401InvalidToken() {
    jwtRunner.withBean(SpringAddonsJwtDecoderFactory.class,
        () -> (jwkSetUri, issuer, audience) -> token -> jwt(Map.of("iss", ISSUER)))
        .run(context -> {
          final var response = perform(context, "Bearer " + plainJwt(ISSUER));

          assertThat(response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
          assertThat(response.getHeader(HttpHeaders.WWW_AUTHENTICATE)).startsWith("Bearer")
              .contains("error=\"invalid_token\"")
              .contains("error_description=\"No principal name in the token: the username claim, or sub when it is absent, has no value\"")
              .doesNotContain("preferred_username");
        });
  }

  @Test
  void givenJwtWithSub_whenRequestPermitAllPath_thenPassesThrough() {
    jwtRunner.withBean(SpringAddonsJwtDecoderFactory.class,
        () -> (jwkSetUri, issuer, audience) -> token -> jwt(Map.of("iss", ISSUER, "sub", "ch4mp")))
        .run(context -> {
          final var response = perform(context, "Bearer " + plainJwt(ISSUER));

          assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
        });
  }

  @Test
  void givenIntrospectionResultWithoutUsernameClaimNorSub_whenRequestPermitAllPath_then401InvalidToken() {
    when(introspector.introspect(anyString()))
        .thenReturn(introspectionPrincipal(Map.of("iss", ISSUER)));
    introspectionRunner.run(context -> {
      final var response = perform(context, "Bearer opaque");

      assertThat(response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
      assertThat(response.getHeader(HttpHeaders.WWW_AUTHENTICATE)).startsWith("Bearer")
          .contains("error=\"invalid_token\"")
          .contains("error_description=\"No principal name in the token: the username claim, or sub when it is absent, has no value\"")
          .doesNotContain("preferred_username");
    });
  }

  /** The security filter chain alone, in front of a chain which answers 200 to anything */
  private static MockHttpServletResponse perform(ApplicationContext context, String authorization)
      throws Exception {
    final var filterChain = new FilterChainProxy(context.getBean(SecurityFilterChain.class));
    final var request = new MockHttpServletRequest("GET", "/public");
    request.addHeader(HttpHeaders.AUTHORIZATION, authorization);
    final var response = new MockHttpServletResponse();
    filterChain.doFilter(request, response, new MockFilterChain());
    return response;
  }
}
