package com.c4_soft.springaddons.security.oidc.starter.reactive.resourceserver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
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
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.boot.web.server.autoconfigure.ServerProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.test.web.reactive.server.WebTestClient;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import reactor.core.publisher.Mono;

/**
 * A bearer token with neither the username claim nor {@code sub} is refused with a {@code 401}
 * (an {@link InvalidBearerTokenException} error signal), not a {@code 500} (issue #319). Such a
 * token must be refused (RFC 9068, section 2.2): only the status changes.
 */
class ReactiveTokenWithoutNameTest {
  private static final String ISS = "https://localhost:8443/realms/test";
  private static final String OPS_PREFIX = "com.c4-soft.springaddons.oidc.ops[0].";

  private final ReactiveWebApplicationContextRunner jwtRunner =
      new ReactiveWebApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(ConfigurationPropertiesAutoConfiguration.class, SpringAddonsOidcProperties.class,
              ReactiveSpringAddonsOidcResourceServerBeans.class, ServerProperties.class))
          .withPropertyValues(OPS_PREFIX + "iss=" + ISS,
              "com.c4-soft.springaddons.oidc.resourceserver.permit-all=/public");

  private final ReactiveOpaqueTokenIntrospector introspector =
      mock(ReactiveOpaqueTokenIntrospector.class);

  private final ReactiveWebApplicationContextRunner introspectionRunner =
      new ReactiveWebApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(ConfigurationPropertiesAutoConfiguration.class, SpringAddonsOidcProperties.class,
              OAuth2ResourceServerProperties.class,
              ReactiveSpringAddonsOidcResourceServerBeans.class, ServerProperties.class))
          .withBean(ReactiveOpaqueTokenIntrospector.class, () -> introspector)
          .withPropertyValues(OPS_PREFIX + "iss=" + ISS,
              "com.c4-soft.springaddons.oidc.resourceserver.permit-all=/public",
              "spring.security.oauth2.resourceserver.opaquetoken.introspection-uri=" + ISS
                  + "/protocol/openid-connect/token/introspect");

  // --- converter level: an error signal, nothing thrown by convert() ---

  @Test
  void givenJwtWithoutUsernameClaimNorSub_whenConvert_thenInvalidBearerTokenExceptionSignal() {
    jwtRunner.run(context -> {
      final var converter = context.getBean(ReactiveJwtAbstractAuthenticationTokenConverter.class);
      final var jwt = jwt(Map.of("iss", ISS));

      assertThatCode(() -> converter.convert(jwt)).doesNotThrowAnyException();
      assertThatThrownBy(() -> converter.convert(jwt).block())
          .isInstanceOf(InvalidBearerTokenException.class)
          .isInstanceOf(AuthenticationException.class).hasMessageContaining("sub")
          .hasMessageNotContaining(ISS);
    });
  }

  @Test
  void givenJwtWithSubOnly_whenConvert_thenNameIsSub() {
    jwtRunner.run(context -> {
      final var converter = context.getBean(ReactiveJwtAbstractAuthenticationTokenConverter.class);

      assertThat(converter.convert(jwt(Map.of("iss", ISS, "sub", "ch4mp"))).block().getName())
          .isEqualTo("ch4mp");
    });
  }

  @Test
  void givenUsernameClaimConfigured_whenConvert_thenNameIsUsernameClaimOrElseSub() {
    jwtRunner.withPropertyValues(OPS_PREFIX + "username-claim=preferred_username")
        .run(context -> {
          final var converter =
              context.getBean(ReactiveJwtAbstractAuthenticationTokenConverter.class);

          assertThat(converter
              .convert(jwt(Map.of("iss", ISS, "sub", "123", "preferred_username", "ch4mp")))
              .block().getName()).isEqualTo("ch4mp");
          assertThat(converter.convert(jwt(Map.of("iss", ISS, "sub", "123"))).block().getName())
              .isEqualTo("123");
          assertThatThrownBy(() -> converter.convert(jwt(Map.of("iss", ISS))).block())
              .isInstanceOf(InvalidBearerTokenException.class)
              .hasMessageContaining("preferred_username");
        });
  }

  @Test
  void givenIntrospectionResultWithoutUsernameClaimNorSub_whenConvert_thenInvalidBearerTokenExceptionSignal() {
    introspectionRunner.run(context -> {
      final var converter = context.getBean(ReactiveOpaqueTokenAuthenticationConverter.class);

      assertThatCode(() -> converter.convert("opaque", principal(Map.of("iss", ISS))))
          .doesNotThrowAnyException();
      assertThatThrownBy(() -> converter.convert("opaque", principal(Map.of("iss", ISS))).block())
          .isInstanceOf(InvalidBearerTokenException.class)
          .isInstanceOf(AuthenticationException.class);
      assertThat(converter.convert("opaque", principal(Map.of("iss", ISS, "sub", "ch4mp")))
          .block().getName()).isEqualTo("ch4mp");
    });
  }

  // --- filter chain level: 401 through the entry point, on a permit-all path too ---

  @Test
  void givenJwtWithoutUsernameClaimNorSub_whenRequestPermitAllPath_then401InvalidToken() {
    jwtRunner.withBean(SpringAddonsReactiveJwtDecoderFactory.class,
        () -> (jwkSetUri, issuer, audience) -> token -> Mono.just(jwt(Map.of("iss", ISS))))
        .run(context -> {
          client(context).get().uri("/public")
              .header(HttpHeaders.AUTHORIZATION, "Bearer " + plainJwt(ISS)).exchange()
              .expectStatus().isUnauthorized().expectHeader()
              .valueMatches(HttpHeaders.WWW_AUTHENTICATE, "Bearer .*invalid_token.*");
        });
  }

  @Test
  void givenJwtWithSub_whenRequestPermitAllPath_thenPassesThrough() {
    jwtRunner
        .withBean(SpringAddonsReactiveJwtDecoderFactory.class,
            () -> (jwkSetUri, issuer, audience) -> token -> Mono
                .just(jwt(Map.of("iss", ISS, "sub", "ch4mp"))))
        .run(context -> {
          client(context).get().uri("/public")
              .header(HttpHeaders.AUTHORIZATION, "Bearer " + plainJwt(ISS)).exchange()
              .expectStatus().isOk();
        });
  }

  @Test
  void givenIntrospectionResultWithoutUsernameClaimNorSub_whenRequestPermitAllPath_then401InvalidToken() {
    when(introspector.introspect(anyString()))
        .thenReturn(Mono.just(principal(Map.of("iss", ISS))));
    introspectionRunner.run(context -> {
      client(context).get().uri("/public").header(HttpHeaders.AUTHORIZATION, "Bearer opaque")
          .exchange().expectStatus().isUnauthorized().expectHeader()
          .valueMatches(HttpHeaders.WWW_AUTHENTICATE, "Bearer .*invalid_token.*");
    });
  }

  /** The security filter chain in front of a handler which answers 200 to anything */
  private static WebTestClient client(ApplicationContext context) {
    return WebTestClient.bindToWebHandler(exchange -> exchange.getResponse().setComplete())
        .webFilter(new WebFilterChainProxy(context.getBean(SecurityWebFilterChain.class)))
        .build();
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
