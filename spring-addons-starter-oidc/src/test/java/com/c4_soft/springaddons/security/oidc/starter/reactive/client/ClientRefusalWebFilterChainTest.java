package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.test.context.assertj.AssertableReactiveWebApplicationContext;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.autoconfigure.web.reactive.WebFluxProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.WebFilter;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import reactor.core.publisher.Mono;

/**
 * Reactive twin of {@code ClientRefusalFilterChainTest}: the auto-configured client filter-chain,
 * with handlers erroring with what {@code ReactiveOAuth2AuthorizedClientManager#authorize()} errors
 * with when the client must be authorized again.
 */
class ClientRefusalWebFilterChainTest {
  private static final ClientRegistration REGISTRATION = ClientRegistration.withRegistrationId("reg")
      .clientId("client-id").clientSecret("secret")
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
      .authorizationUri("https://op/authorize").tokenUri("https://op/token").build();

  private final ReactiveWebApplicationContextRunner runner =
      new ReactiveWebApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(
              ConfigurationPropertiesAutoConfiguration.class, SpringAddonsOidcProperties.class,
              OAuth2ClientProperties.class, ServerProperties.class, WebFluxProperties.class,
              ReactiveSpringAddonsOidcClientWithLoginBeans.class))
          .withBean(ReactiveClientRegistrationRepository.class,
              () -> new InMemoryReactiveClientRegistrationRepository(REGISTRATION))
          .withPropertyValues("com.c4-soft.springaddons.oidc.client.security-matchers=/**",
              "spring.security.oauth2.client.registration.reg.client-id=client-id");

  @RestController
  static class ErroringController {
    @GetMapping("/bff/api/no-authorized-client")
    Mono<String> noAuthorizedClient() {
      return Mono.error(new ClientAuthorizationRequiredException("reg"));
    }

    @GetMapping("/bff/api/refused-refresh")
    Mono<String> refusedRefresh() {
      return Mono.error(new ClientAuthorizationException(
          new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT), "reg"));
    }
  }

  /**
   * Puts an authentication in the Reactor context before the security chain runs: its
   * {@code ReactorContextWebFilter} keeps a context which is already there (this is how
   * spring-security-test's {@code mockUser()} works too).
   */
  private static final WebFilter LOGGED_IN = (exchange, chain) -> chain.filter(exchange)
      .contextWrite(ReactiveSecurityContextHolder
          .withAuthentication(new TestingAuthenticationToken("ch4mp", "", "ROLE_USER")));

  private static WebTestClient loggedInClient(AssertableReactiveWebApplicationContext context) {
    return WebTestClient.bindToController(new ErroringController())
        .webFilter(LOGGED_IN, context.getBean(WebFilterChainProxy.class)).build();
  }

  private static WebTestClient anonymousClient(AssertableReactiveWebApplicationContext context) {
    return WebTestClient.bindToController(new ErroringController())
        .webFilter(context.getBean(WebFilterChainProxy.class)).build();
  }

  @Test
  void givenEnabledAndNoAuthorizedClient_whenGetProtectedRoute_thenUnauthorizedWithoutLocation() {
    runner
        .withPropertyValues(
            "com.c4-soft.springaddons.oidc.client.client-authorization-required.enabled=true")
        .run(context -> {
          assertThat(context).hasNotFailed();

          loggedInClient(context).get().uri("/bff/api/no-authorized-client").exchange()
              .expectStatus().isUnauthorized().expectHeader().doesNotExist(HttpHeaders.LOCATION);
        });
  }

  @Test
  void givenEnabledAndRefusedRefresh_whenGetProtectedRoute_thenUnauthorizedWithoutLocation() {
    runner
        .withPropertyValues(
            "com.c4-soft.springaddons.oidc.client.client-authorization-required.enabled=true")
        .run(context -> {
          assertThat(context).hasNotFailed();

          loggedInClient(context).get().uri("/bff/api/refused-refresh").exchange()
              .expectStatus().isUnauthorized().expectHeader().doesNotExist(HttpHeaders.LOCATION);
        });
  }

  @Test
  void givenDisabledAndNoAuthorizedClient_whenGetProtectedRoute_thenRedirectedToAuthorizationEndpoint() {
    runner.run(context -> {
      assertThat(context).hasNotFailed();

      // Spring Security's behavior, kept by default
      final var location = loggedInClient(context).get().uri("/bff/api/no-authorized-client")
          .exchange().expectStatus().isFound().returnResult(Void.class).getResponseHeaders()
          .getFirst(HttpHeaders.LOCATION);

      assertThat(location).startsWith("https://op/authorize?");
    });
  }

  @Test
  void givenPostLoginUriNotAllowed_whenInitiateLogin_thenBadRequestWithoutLocation() {
    runner.run(context -> {
      assertThat(context).hasNotFailed();

      anonymousClient(context).get().uri("/oauth2/authorization/reg")
          .header(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_HEADER,
              "https://evil.com/ui/account")
          .exchange().expectStatus().isBadRequest().expectHeader()
          .doesNotExist(HttpHeaders.LOCATION);
    });
  }

  @Test
  void givenPostLoginUriAllowed_whenInitiateLogin_thenRedirectedToAuthorizationEndpoint() {
    runner.run(context -> {
      assertThat(context).hasNotFailed();

      final var location = anonymousClient(context).get().uri("/oauth2/authorization/reg")
          .header(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_HEADER,
              "/ui/account")
          .exchange().expectStatus().isFound().returnResult(Void.class).getResponseHeaders()
          .getFirst(HttpHeaders.LOCATION);

      assertThat(location).startsWith("https://op/authorize?");
    });
  }
}
