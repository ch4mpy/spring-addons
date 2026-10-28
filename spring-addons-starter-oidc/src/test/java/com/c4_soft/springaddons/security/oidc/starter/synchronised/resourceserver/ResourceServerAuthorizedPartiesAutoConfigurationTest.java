package com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.net.URI;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.web.server.autoconfigure.ServerProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import com.c4_soft.springaddons.security.oidc.starter.TestJwkSet;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.nimbusds.jwt.JWTClaimsSet;
import jakarta.servlet.http.HttpServletRequest;

/**
 * From the {@code ops[0].authorized-parties} property down to the authentication manager resolver
 * and the filter chain, with tokens signed by {@link TestJwkSet} (issue #329).
 */
class ResourceServerAuthorizedPartiesAutoConfigurationTest {

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

      assertThat(manager.authenticate(bearer(Map.of("azp", "intruder"))).isAuthenticated())
          .isTrue();
      assertThat(manager.authenticate(bearer(Map.of())).isAuthenticated()).isTrue();
    });
  }

  @Test
  void givenAuthorizedParties_whenAuthenticate_thenOnlyListedAzpIsAccepted() {
    runner().withPropertyValues(AUTHORIZED_PARTIES_PROPERTY).run(context -> {
      final var manager = manager(context);

      assertThat(manager.authenticate(bearer(Map.of("azp", "gateway"))).isAuthenticated())
          .isTrue();
      assertThat(manager.authenticate(bearer(Map.of("azp", "bruno"))).isAuthenticated()).isTrue();
      assertThatThrownBy(() -> manager.authenticate(bearer(Map.of("azp", "intruder"))))
          .isInstanceOf(InvalidBearerTokenException.class);
    });
  }

  @Test
  void givenAuthorizedParties_whenTokenHasNoAzp_thenClientIdIsChecked() {
    runner().withPropertyValues(AUTHORIZED_PARTIES_PROPERTY).run(context -> {
      final var manager = manager(context);

      assertThat(manager.authenticate(bearer(Map.of("client_id", "gateway"))).isAuthenticated())
          .isTrue();
      assertThatThrownBy(() -> manager.authenticate(bearer(Map.of("client_id", "intruder"))))
          .isInstanceOf(InvalidBearerTokenException.class);
      assertThatThrownBy(() -> manager.authenticate(bearer(Map.of())))
          .isInstanceOf(InvalidBearerTokenException.class);
      assertThatThrownBy(() -> manager
          .authenticate(bearer(Map.of("azp", "intruder", "client_id", "gateway"))))
              .isInstanceOf(InvalidBearerTokenException.class);
    });
  }

  @Test
  void givenCustomDecoderFactory_whenAuthenticate_thenAuthorizedPartiesAreStillChecked() {
    runner().withPropertyValues(AUTHORIZED_PARTIES_PROPERTY)
        .withBean(SpringAddonsJwtDecoderFactory.class,
            () -> (jwkSetUri, issuer, audience, typ) -> NimbusJwtDecoder
                .withJwkSetUri(jwkSetUri.orElseThrow().toString()).build())
        .run(context -> {
          final var manager = manager(context);

          assertThat(manager.authenticate(bearer(Map.of("azp", "gateway"))).isAuthenticated())
              .isTrue();
          assertThatThrownBy(() -> manager.authenticate(bearer(Map.of("azp", "intruder"))))
              .isInstanceOf(InvalidBearerTokenException.class);
        });
  }

  @Test
  void givenAzpNotListed_whenRequest_then401InvalidToken() {
    runner().withPropertyValues(AUTHORIZED_PARTIES_PROPERTY).run(context -> {
      final var response = perform(context, token(Map.of("azp", "intruder")));

      assertThat(response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
      assertThat(response.getHeader(HttpHeaders.WWW_AUTHENTICATE)).startsWith("Bearer")
          .contains("error=\"invalid_token\"")
          .contains("error_description=\"An error occurred while attempting to decode the Jwt: "
              + "The token was not issued to an authorized party of this resource server\"")
          .doesNotContain("intruder");
    });
  }

  @Test
  void givenAzpListed_whenRequest_thenPassesThrough() {
    runner().withPropertyValues(AUTHORIZED_PARTIES_PROPERTY).run(context -> {
      final var response = perform(context, token(Map.of("azp", "gateway")));

      assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
    });
  }

  private static WebApplicationContextRunner runner() {
    return new WebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(ConfigurationPropertiesAutoConfiguration.class,
            SpringAddonsOidcProperties.class, SpringAddonsOidcResourceServerBeans.class,
            ServerProperties.class))
        .withPropertyValues("com.c4-soft.springaddons.oidc.ops[0].iss=" + ISSUER,
            "com.c4-soft.springaddons.oidc.ops[0].jwk-set-uri=" + jwks.jwkSetUri(),
            "com.c4-soft.springaddons.oidc.ops[0].aud=bff");
  }

  @SuppressWarnings("unchecked")
  private static AuthenticationManager manager(ApplicationContext context) {
    return ((AuthenticationManagerResolver<HttpServletRequest>) context
        .getBeanProvider(ResolvableType.forClassWithGenerics(AuthenticationManagerResolver.class,
            HttpServletRequest.class))
        .getObject()).resolve(new MockHttpServletRequest());
  }

  private static String token(Map<String, String> claims) throws Exception {
    final var builder = new JWTClaimsSet.Builder(TestJwkSet.claims(ISSUER.toString(), "bff"));
    claims.forEach(builder::claim);
    return jwks.sign(null, builder.build());
  }

  private static Authentication bearer(Map<String, String> claims) throws Exception {
    return new BearerTokenAuthenticationToken(token(claims));
  }

  private static MockHttpServletResponse perform(ApplicationContext context, String token)
      throws Exception {
    final var filterChain = new FilterChainProxy(context.getBean(SecurityFilterChain.class));
    final var request = new MockHttpServletRequest("GET", "/greet");
    request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);
    final var response = new MockHttpServletResponse();
    filterChain.doFilter(request, response, new MockFilterChain());
    return response;
  }
}
