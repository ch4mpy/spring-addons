package com.c4_soft.springaddons.security.oidc.starter.reactive.resourceserver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.net.URI;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.core.ResolvableType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.web.server.ServerWebExchange;
import com.c4_soft.springaddons.security.oidc.starter.TestJwkSet;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;

/**
 * From the {@code ops[0].typ} property down to the decoder built by the auto-configured
 * authentication manager resolver, with tokens signed by {@link TestJwkSet}.
 */
class ReactiveResourceServerTypAutoConfigurationTest {

  private static final URI ISSUER = URI.create("https://op/realm");
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
  void givenNoTypProperty_whenAuthenticate_thenJwtAndAtJwtAreAccepted() {
    runner().run(context -> {
      final var manager = resolver(context).resolve(exchange()).block();

      assertThat(manager.authenticate(bearer("JWT")).block().isAuthenticated()).isTrue();
      assertThat(manager.authenticate(bearer("at+jwt")).block().isAuthenticated()).isTrue();
      assertThat(manager.authenticate(bearer("application/at+jwt")).block().isAuthenticated())
          .isTrue();
      assertThat(manager.authenticate(bearer(null)).block().isAuthenticated()).isTrue();
      assertThatThrownBy(() -> manager.authenticate(bearer("secevent+jwt")).block())
          .isInstanceOf(InvalidBearerTokenException.class);
    });
  }

  @Test
  void givenTypIsAtJwt_whenAuthenticate_thenOnlyAtJwtIsAccepted() {
    runner().withPropertyValues("com.c4-soft.springaddons.oidc.ops[0].typ=at+jwt")
        .run(context -> {
          final var manager = resolver(context).resolve(exchange()).block();

          assertThat(manager.authenticate(bearer("at+jwt")).block().isAuthenticated()).isTrue();
          assertThat(manager.authenticate(bearer("application/at+jwt")).block().isAuthenticated())
              .isTrue();
          assertThatThrownBy(() -> manager.authenticate(bearer("JWT")).block())
              .isInstanceOf(InvalidBearerTokenException.class);
          assertThatThrownBy(() -> manager.authenticate(bearer(null)).block())
              .isInstanceOf(InvalidBearerTokenException.class);
        });
  }

  @Test
  void givenEmptyTypProperty_whenAuthenticate_thenDefaultApplies() {
    runner().withPropertyValues("com.c4-soft.springaddons.oidc.ops[0].typ=").run(context -> {
      final var manager = resolver(context).resolve(exchange()).block();

      assertThat(manager.authenticate(bearer("JWT")).block().isAuthenticated()).isTrue();
      assertThat(manager.authenticate(bearer("at+jwt")).block().isAuthenticated()).isTrue();
      assertThat(manager.authenticate(bearer(null)).block().isAuthenticated()).isTrue();
      assertThatThrownBy(() -> manager.authenticate(bearer("secevent+jwt")).block())
          .isInstanceOf(InvalidBearerTokenException.class);
    });
  }

  @Test
  void givenFactorySubclassOverridingCreate_whenAuthenticate_thenItIsCalledWithConfiguredTyp() {
    final var factory = new TypRecordingFactory();
    runner().withPropertyValues("com.c4-soft.springaddons.oidc.ops[0].typ=at+jwt")
        .withBean(SpringAddonsReactiveJwtDecoderFactory.class, () -> factory).run(context -> {
          final var manager = resolver(context).resolve(exchange()).block();

          assertThat(manager.authenticate(bearer("at+jwt")).block().isAuthenticated()).isTrue();
          assertThat(factory.typ).containsExactly("at+jwt");
          assertThatThrownBy(() -> manager.authenticate(bearer("JWT")).block())
              .isInstanceOf(InvalidBearerTokenException.class);
        });
  }

  static class TypRecordingFactory extends DefaultSpringAddonsReactiveJwtDecoderFactory {
    volatile List<String> typ;

    @Override
    public NimbusReactiveJwtDecoder create(Optional<URI> jwkSetUri, Optional<URI> issuer,
        Optional<String> audience, List<String> typ) {
      this.typ = typ;
      return super.create(jwkSetUri, issuer, audience, typ);
    }
  }

  private static ReactiveWebApplicationContextRunner runner() {
    return new ReactiveWebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(ConfigurationPropertiesAutoConfiguration.class,
            SpringAddonsOidcProperties.class,
            ReactiveSpringAddonsOidcResourceServerBeans.class, ServerProperties.class))
        .withPropertyValues("com.c4-soft.springaddons.oidc.ops[0].iss=" + ISSUER,
            "com.c4-soft.springaddons.oidc.ops[0].jwk-set-uri=" + jwks.jwkSetUri(),
            "com.c4-soft.springaddons.oidc.ops[0].aud=bff");
  }

  @SuppressWarnings("unchecked")
  private static ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver(
      org.springframework.context.ApplicationContext context) {
    return (ReactiveAuthenticationManagerResolver<ServerWebExchange>) context.getBeanProvider(
        ResolvableType.forClassWithGenerics(ReactiveAuthenticationManagerResolver.class,
            ServerWebExchange.class))
        .getObject();
  }

  private static ServerWebExchange exchange() {
    return MockServerWebExchange.from(MockServerHttpRequest.get("/").build());
  }

  private static Authentication bearer(String typ) throws Exception {
    return new BearerTokenAuthenticationToken(
        jwks.sign(typ, TestJwkSet.claims(ISSUER.toString(), "bff")));
  }
}
