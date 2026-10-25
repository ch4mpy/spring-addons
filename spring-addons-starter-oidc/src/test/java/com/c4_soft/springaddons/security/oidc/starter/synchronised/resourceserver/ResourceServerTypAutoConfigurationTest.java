package com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver;

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
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.web.server.autoconfigure.ServerProperties;
import org.springframework.core.ResolvableType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import com.c4_soft.springaddons.security.oidc.starter.TestJwkSet;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import jakarta.servlet.http.HttpServletRequest;

/**
 * From the {@code ops[0].typ} property down to the decoder built by the auto-configured
 * authentication manager resolver, with tokens signed by {@link TestJwkSet}.
 */
class ResourceServerTypAutoConfigurationTest {

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
      final var manager = resolver(context).resolve(new MockHttpServletRequest());

      assertThat(manager.authenticate(bearer("JWT")).isAuthenticated()).isTrue();
      assertThat(manager.authenticate(bearer("at+jwt")).isAuthenticated()).isTrue();
      assertThat(manager.authenticate(bearer("application/at+jwt")).isAuthenticated()).isTrue();
      assertThat(manager.authenticate(bearer(null)).isAuthenticated()).isTrue();
      assertThatThrownBy(() -> manager.authenticate(bearer("secevent+jwt")))
          .isInstanceOf(InvalidBearerTokenException.class);
    });
  }

  @Test
  void givenTypIsAtJwt_whenAuthenticate_thenOnlyAtJwtIsAccepted() {
    runner().withPropertyValues("com.c4-soft.springaddons.oidc.ops[0].typ=at+jwt")
        .run(context -> {
          final var manager = resolver(context).resolve(new MockHttpServletRequest());

          assertThat(manager.authenticate(bearer("at+jwt")).isAuthenticated()).isTrue();
          assertThat(manager.authenticate(bearer("application/at+jwt")).isAuthenticated())
              .isTrue();
          assertThatThrownBy(() -> manager.authenticate(bearer("JWT")))
              .isInstanceOf(InvalidBearerTokenException.class);
          assertThatThrownBy(() -> manager.authenticate(bearer(null)))
              .isInstanceOf(InvalidBearerTokenException.class);
        });
  }

  @Test
  void givenEmptyTypProperty_whenAuthenticate_thenDefaultApplies() {
    runner().withPropertyValues("com.c4-soft.springaddons.oidc.ops[0].typ=").run(context -> {
      final var manager = resolver(context).resolve(new MockHttpServletRequest());

      assertThat(manager.authenticate(bearer("JWT")).isAuthenticated()).isTrue();
      assertThat(manager.authenticate(bearer("at+jwt")).isAuthenticated()).isTrue();
      assertThat(manager.authenticate(bearer(null)).isAuthenticated()).isTrue();
      assertThatThrownBy(() -> manager.authenticate(bearer("secevent+jwt")))
          .isInstanceOf(InvalidBearerTokenException.class);
    });
  }

  @Test
  void givenFactorySubclassOverridingCreate_whenAuthenticate_thenItIsCalledWithConfiguredTyp() {
    final var factory = new TypRecordingFactory();
    runner().withPropertyValues("com.c4-soft.springaddons.oidc.ops[0].typ=at+jwt")
        .withBean(SpringAddonsJwtDecoderFactory.class, () -> factory).run(context -> {
          final var manager = resolver(context).resolve(new MockHttpServletRequest());

          assertThat(manager.authenticate(bearer("at+jwt")).isAuthenticated()).isTrue();
          assertThat(factory.typ).containsExactly("at+jwt");
          assertThatThrownBy(() -> manager.authenticate(bearer("JWT")))
              .isInstanceOf(InvalidBearerTokenException.class);
        });
  }

  static class TypRecordingFactory extends DefaultSpringAddonsJwtDecoderFactory {
    volatile List<String> typ;

    @Override
    public NimbusJwtDecoder create(Optional<URI> jwkSetUri, Optional<URI> issuer,
        Optional<String> audience, List<String> typ) {
      this.typ = typ;
      return super.create(jwkSetUri, issuer, audience, typ);
    }
  }

  private static WebApplicationContextRunner runner() {
    return new WebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(ConfigurationPropertiesAutoConfiguration.class,
            SpringAddonsOidcProperties.class,
            SpringAddonsOidcResourceServerBeans.class, ServerProperties.class))
        .withPropertyValues("com.c4-soft.springaddons.oidc.ops[0].iss=" + ISSUER,
            "com.c4-soft.springaddons.oidc.ops[0].jwk-set-uri=" + jwks.jwkSetUri(),
            "com.c4-soft.springaddons.oidc.ops[0].aud=bff");
  }

  @SuppressWarnings("unchecked")
  private static AuthenticationManagerResolver<HttpServletRequest> resolver(
      org.springframework.context.ApplicationContext context) {
    return (AuthenticationManagerResolver<HttpServletRequest>) context.getBeanProvider(
        ResolvableType.forClassWithGenerics(AuthenticationManagerResolver.class,
            HttpServletRequest.class))
        .getObject();
  }

  private static Authentication bearer(String typ) throws Exception {
    return new BearerTokenAuthenticationToken(
        jwks.sign(typ, TestJwkSet.claims(ISSUER.toString(), "bff")));
  }
}
