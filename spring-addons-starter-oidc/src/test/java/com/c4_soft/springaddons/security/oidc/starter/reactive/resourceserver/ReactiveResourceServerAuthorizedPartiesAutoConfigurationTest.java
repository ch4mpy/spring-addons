package com.c4_soft.springaddons.security.oidc.starter.reactive.resourceserver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.net.URI;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.boot.web.server.autoconfigure.ServerProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import com.c4_soft.springaddons.security.oidc.starter.TestJwkSet;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.nimbusds.jwt.JWTClaimsSet;

/**
 * From the {@code ops[0].authorized-parties} property down to the authentication manager resolver
 * and the filter chain, with tokens signed by {@link TestJwkSet} (issue #329).
 */
class ReactiveResourceServerAuthorizedPartiesAutoConfigurationTest {

  private static final URI ISSUER = URI.create("https://op/realm");
  private static final String AUTHORIZED_PARTIES_PROPERTY =
      "com.c4-soft.springaddons.oidc.ops[0].authorized-parties=gateway, bruno";
  private static TestJwkSet jwks;

  @BeforeAll
  static void startJwkSetServer() throws Exception {
    jwks = new TestJwkSet();
  }

  @AfterAll
  static void stopJwkSetServer() {
    jwks.close();
  }

  @Test
  void givenNoAuthorizedPartiesProperty_whenAuthenticate_thenAnyAzpIsAccepted() {
    runner().run(context -> {
      final var manager = manager(context);

      assertThat(manager.authenticate(bearer(Map.of("azp", "intruder"))).block().isAuthenticated())
          .isTrue();
      assertThat(manager.authenticate(bearer(Map.of())).block().isAuthenticated()).isTrue();
    });
  }

  @Test
  void givenAuthorizedParties_whenAuthenticate_thenOnlyListedAzpIsAccepted() {
    runner().withPropertyValues(AUTHORIZED_PARTIES_PROPERTY).run(context -> {
      final var manager = manager(context);

      assertThat(manager.authenticate(bearer(Map.of("azp", "gateway"))).block().isAuthenticated())
          .isTrue();
      assertThat(manager.authenticate(bearer(Map.of("azp", "bruno"))).block().isAuthenticated())
          .isTrue();
      assertThatThrownBy(() -> manager.authenticate(bearer(Map.of("azp", "intruder"))).block())
          .isInstanceOf(InvalidBearerTokenException.class);
    });
  }

  @Test
  void givenAuthorizedParties_whenTokenHasNoAzp_thenClientIdIsChecked() {
    runner().withPropertyValues(AUTHORIZED_PARTIES_PROPERTY).run(context -> {
      final var manager = manager(context);

      assertThat(
          manager.authenticate(bearer(Map.of("client_id", "gateway"))).block().isAuthenticated())
              .isTrue();
      assertThatThrownBy(
          () -> manager.authenticate(bearer(Map.of("client_id", "intruder"))).block())
              .isInstanceOf(InvalidBearerTokenException.class);
      assertThatThrownBy(() -> manager.authenticate(bearer(Map.of())).block())
          .isInstanceOf(InvalidBearerTokenException.class);
      assertThatThrownBy(() -> manager
          .authenticate(bearer(Map.of("azp", "intruder", "client_id", "gateway"))).block())
              .isInstanceOf(InvalidBearerTokenException.class);
    });
  }

  @Test
  void givenCustomDecoderFactory_whenAuthenticate_thenAuthorizedPartiesAreStillChecked() {
    runner().withPropertyValues(AUTHORIZED_PARTIES_PROPERTY)
        .withBean(SpringAddonsReactiveJwtDecoderFactory.class,
            () -> (jwkSetUri, issuer, audience, typ) -> NimbusReactiveJwtDecoder
                .withJwkSetUri(jwkSetUri.orElseThrow().toString()).build())
        .run(context -> {
          final var manager = manager(context);

          assertThat(
              manager.authenticate(bearer(Map.of("azp", "gateway"))).block().isAuthenticated())
                  .isTrue();
          assertThatThrownBy(() -> manager.authenticate(bearer(Map.of("azp", "intruder"))).block())
              .isInstanceOf(InvalidBearerTokenException.class);
        });
  }

  @Test
  void givenAzpNotListed_whenRequest_then401InvalidToken() {
    runner().withPropertyValues(AUTHORIZED_PARTIES_PROPERTY).run(context -> {
      client(context).get().uri("/greet")
          .header(HttpHeaders.AUTHORIZATION, "Bearer " + token(Map.of("azp", "intruder")))
          .exchange().expectStatus().isUnauthorized().expectHeader()
          .valueMatches(HttpHeaders.WWW_AUTHENTICATE,
              "Bearer error=\"invalid_token\", error_description=\"An error occurred while attempting to decode the Jwt: The token was not issued to an authorized party of this resource server\"(?!.*intruder).*");
    });
  }

  @Test
  void givenAzpListed_whenRequest_thenPassesThrough() {
    runner().withPropertyValues(AUTHORIZED_PARTIES_PROPERTY).run(context -> {
      client(context).get().uri("/greet")
          .header(HttpHeaders.AUTHORIZATION, "Bearer " + token(Map.of("azp", "gateway")))
          .exchange().expectStatus().isOk();
    });
  }

  private static ReactiveWebApplicationContextRunner runner() {
    return new ReactiveWebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(ConfigurationPropertiesAutoConfiguration.class,
            SpringAddonsOidcProperties.class, ReactiveSpringAddonsOidcResourceServerBeans.class,
            ServerProperties.class))
        .withPropertyValues("com.c4-soft.springaddons.oidc.ops[0].iss=" + ISSUER,
            "com.c4-soft.springaddons.oidc.ops[0].jwk-set-uri=" + jwks.jwkSetUri(),
            "com.c4-soft.springaddons.oidc.ops[0].aud=bff");
  }

  @SuppressWarnings("unchecked")
  private static ReactiveAuthenticationManager manager(ApplicationContext context) {
    final ServerWebExchange exchange =
        MockServerWebExchange.from(MockServerHttpRequest.get("/").build());
    return ((ReactiveAuthenticationManagerResolver<ServerWebExchange>) context
        .getBeanProvider(ResolvableType
            .forClassWithGenerics(ReactiveAuthenticationManagerResolver.class,
                ServerWebExchange.class))
        .getObject()).resolve(exchange).block();
  }

  private static String token(Map<String, String> claims) throws Exception {
    final var builder = new JWTClaimsSet.Builder(TestJwkSet.claims(ISSUER.toString(), "bff"));
    claims.forEach(builder::claim);
    return jwks.sign(null, builder.build());
  }

  private static Authentication bearer(Map<String, String> claims) throws Exception {
    return new BearerTokenAuthenticationToken(token(claims));
  }

  /** The security filter chain alone, in front of a handler which answers 200 to anything */
  private static WebTestClient client(ApplicationContext context) {
    return WebTestClient.bindToWebHandler(exchange -> exchange.getResponse().setComplete())
        .webFilter(new WebFilterChainProxy(context.getBean(SecurityWebFilterChain.class)))
        .build();
  }
}
