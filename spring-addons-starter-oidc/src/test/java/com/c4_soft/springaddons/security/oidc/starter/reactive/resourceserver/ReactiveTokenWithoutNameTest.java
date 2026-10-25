package com.c4_soft.springaddons.security.oidc.starter.reactive.resourceserver;

import static com.c4_soft.springaddons.security.oidc.starter.ResourceServerTestFixtures.INTROSPECTION_URI_PROPERTY;
import static com.c4_soft.springaddons.security.oidc.starter.ResourceServerTestFixtures.ISSUER;
import static com.c4_soft.springaddons.security.oidc.starter.ResourceServerTestFixtures.ISSUER_PROPERTY;
import static com.c4_soft.springaddons.security.oidc.starter.ResourceServerTestFixtures.PERMIT_ALL_PUBLIC_PROPERTY;
import static com.c4_soft.springaddons.security.oidc.starter.ResourceServerTestFixtures.USERNAME_CLAIM_PROPERTY;
import static com.c4_soft.springaddons.security.oidc.starter.ResourceServerTestFixtures.introspectionPrincipal;
import static com.c4_soft.springaddons.security.oidc.starter.ResourceServerTestFixtures.jwt;
import static com.c4_soft.springaddons.security.oidc.starter.ResourceServerTestFixtures.plainJwt;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerProperties;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.boot.web.server.autoconfigure.ServerProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.test.web.reactive.server.WebTestClient;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import reactor.core.publisher.Mono;

/**
 * A bearer token with neither the username claim nor {@code sub} is refused with a {@code 401}
 * (an {@link InvalidBearerTokenException} error signal), not a {@code 500} (issue #319). Such a
 * token must be refused (RFC 9068, section 2.2): only the status changes.
 */
class ReactiveTokenWithoutNameTest {

  private final ReactiveWebApplicationContextRunner jwtRunner =
      new ReactiveWebApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(ConfigurationPropertiesAutoConfiguration.class,
              SpringAddonsOidcProperties.class, ReactiveSpringAddonsOidcResourceServerBeans.class,
              ServerProperties.class))
          .withPropertyValues(ISSUER_PROPERTY, USERNAME_CLAIM_PROPERTY,
              PERMIT_ALL_PUBLIC_PROPERTY);

  private final ReactiveOpaqueTokenIntrospector introspector =
      mock(ReactiveOpaqueTokenIntrospector.class);

  private final ReactiveWebApplicationContextRunner introspectionRunner = jwtRunner
      .withConfiguration(AutoConfigurations.of(OAuth2ResourceServerProperties.class))
      .withBean(ReactiveOpaqueTokenIntrospector.class, () -> introspector)
      .withPropertyValues(INTROSPECTION_URI_PROPERTY);

  // --- converter level: the default converters delegate to PrincipalNameResolver, with the
  // configured username claim; a refused token is an error signal, nothing thrown by convert() ---

  @Test
  void givenJwtConverter_whenConvert_thenNameIsResolvedByPrincipalNameResolver() {
    jwtRunner.run(context -> {
      final var converter = context.getBean(ReactiveJwtAbstractAuthenticationTokenConverter.class);
      final var jwt = jwt(Map.of("iss", ISSUER));

      assertThatCode(() -> converter.convert(jwt)).doesNotThrowAnyException();
      assertThatThrownBy(() -> converter.convert(jwt).block())
          .isInstanceOf(InvalidBearerTokenException.class);
      assertThat(converter
          .convert(jwt(Map.of("iss", ISSUER, "sub", "123", "preferred_username", "ch4mp")))
          .block().getName()).isEqualTo("ch4mp");
    });
  }

  @Test
  void givenIntrospectionConverter_whenConvert_thenNameIsResolvedByPrincipalNameResolver() {
    introspectionRunner.run(context -> {
      final var converter = context.getBean(ReactiveOpaqueTokenAuthenticationConverter.class);
      final var principal = introspectionPrincipal(Map.of("iss", ISSUER));

      assertThatCode(() -> converter.convert("opaque", principal)).doesNotThrowAnyException();
      assertThatThrownBy(() -> converter.convert("opaque", principal).block())
          .isInstanceOf(InvalidBearerTokenException.class);
      assertThat(converter.convert("opaque",
          introspectionPrincipal(Map.of("iss", ISSUER, "sub", "123", "preferred_username", "ch4mp")))
          .block().getName()).isEqualTo("ch4mp");
    });
  }

  // --- filter chain level: 401 through the entry point, on a permit-all path too ---

  @Test
  void givenJwtWithoutUsernameClaimNorSub_whenRequestPermitAllPath_then401InvalidToken() {
    jwtRunner.withBean(SpringAddonsReactiveJwtDecoderFactory.class,
        () -> (jwkSetUri, issuer, audience, typ) -> token -> Mono.just(jwt(Map.of("iss", ISSUER))))
        .run(context -> {
          client(context).get().uri("/public")
              .header(HttpHeaders.AUTHORIZATION, "Bearer " + plainJwt(ISSUER)).exchange()
              .expectStatus().isUnauthorized().expectHeader()
              .valueMatches(HttpHeaders.WWW_AUTHENTICATE,
                  "Bearer error=\"invalid_token\", error_description=\"No principal name in the token: the username claim, or sub when it is absent, has no value\".*");
        });
  }

  @Test
  void givenJwtWithSub_whenRequestPermitAllPath_thenPassesThrough() {
    jwtRunner
        .withBean(SpringAddonsReactiveJwtDecoderFactory.class,
            () -> (jwkSetUri, issuer, audience, typ) -> token -> Mono
                .just(jwt(Map.of("iss", ISSUER, "sub", "ch4mp"))))
        .run(context -> {
          client(context).get().uri("/public")
              .header(HttpHeaders.AUTHORIZATION, "Bearer " + plainJwt(ISSUER)).exchange()
              .expectStatus().isOk();
        });
  }

  @Test
  void givenIntrospectionResultWithoutUsernameClaimNorSub_whenRequestPermitAllPath_then401InvalidToken() {
    when(introspector.introspect(anyString()))
        .thenReturn(Mono.just(introspectionPrincipal(Map.of("iss", ISSUER))));
    introspectionRunner.run(context -> {
      client(context).get().uri("/public").header(HttpHeaders.AUTHORIZATION, "Bearer opaque")
          .exchange().expectStatus().isUnauthorized().expectHeader()
          .valueMatches(HttpHeaders.WWW_AUTHENTICATE,
              "Bearer error=\"invalid_token\", error_description=\"No principal name in the token: the username claim, or sub when it is absent, has no value\".*");
    });
  }

  /** The security filter chain alone, in front of a handler which answers 200 to anything */
  private static WebTestClient client(ApplicationContext context) {
    return WebTestClient.bindToWebHandler(exchange -> exchange.getResponse().setComplete())
        .webFilter(new WebFilterChainProxy(context.getBean(SecurityWebFilterChain.class)))
        .build();
  }
}
