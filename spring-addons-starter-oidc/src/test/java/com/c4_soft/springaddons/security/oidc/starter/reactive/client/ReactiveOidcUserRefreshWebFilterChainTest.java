package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import static org.assertj.core.api.Assertions.assertThat;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientProperties;
import org.springframework.boot.test.context.assertj.AssertableReactiveWebApplicationContext;
import org.springframework.boot.test.context.runner.ContextConsumer;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.boot.web.server.autoconfigure.ServerProperties;
import org.springframework.boot.webflux.autoconfigure.WebFluxProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebSession;
import com.c4_soft.springaddons.security.oidc.starter.TestJwkSet;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import reactor.core.publisher.Mono;

/**
 * Reactive twin of {@code OidcUserRefreshFilterChainTest}: the auto-configured client filter-chain,
 * authorized client manager and provider, with a controller authorizing the client of an
 * {@code oauth2Login} session whose access token expired, as Spring Cloud Gateway's
 * {@code TokenRelay=} filter does. The OpenID Provider is a local server signing the refreshed ID
 * tokens.
 */
class ReactiveOidcUserRefreshWebFilterChainTest {
  private static final String ISSUER = "https://localhost:8443/realms/test";
  private static final String CLIENT_ID = "client-id";

  private final Instant loginTime = Instant.now().minusSeconds(600);
  private final AtomicReference<WebSession> session = new AtomicReference<>();

  @Test
  void givenOAuth2LoginSession_whenTheTokenIsRefreshed_thenTheSessionHoldsTheRefreshedOidcUserAndMappedAuthorities()
      throws Exception {
    try (var op = new TestJwkSet()) {
      final var refreshedIdToken =
          op.sign(null, TestJwkSet.claims(ISSUER, CLIENT_ID, Map.of("roles", List.of("NEW"))));

      runner(op, refreshedIdToken).run(context -> {
        assertThat(context).hasNotFailed();

        client(context).get().uri("/bff/api/greetings/me").exchange().expectStatus().isOk()
            .expectBody(String.class).isEqualTo("new-at");

        final var login = (OAuth2AuthenticationToken) ((SecurityContext) session.get()
            .getAttribute(WebSessionServerSecurityContextRepository.DEFAULT_SPRING_SECURITY_CONTEXT_ATTR_NAME))
                .getAuthentication();
        assertThat(((OidcUser) login.getPrincipal()).getIdToken().getTokenValue())
            .isEqualTo(refreshedIdToken);
        assertThat(login.getAuthorities()).extracting(GrantedAuthority::getAuthority)
            .contains("NEW").doesNotContain("OLD");
      });
    }
  }

  @Test
  void givenEnabledAndTheRefreshedIdTokenIsRefused_whenTheTokenIsRefreshed_thenUnauthorizedAndLoggedOut()
      throws Exception {
    try (var op = new TestJwkSet()) {
      assertRelayIsUnauthorizedAndLogsOut(runner(op, refusedIdToken(op)));
    }
  }

  @Test
  void givenEnabledAndTheOidcUserServiceRefusesTheRefreshedUser_whenTheTokenIsRefreshed_thenUnauthorizedAndLoggedOut()
      throws Exception {
    try (var op = new TestJwkSet()) {
      final var refreshedIdToken = op.sign(null, TestJwkSet.claims(ISSUER, CLIENT_ID));

      // The OpenID user service wins over the OAuth2 one, and may depend on the manager
      assertRelayIsUnauthorizedAndLogsOut(
          runner(op, refreshedIdToken).withBean(DisablingOidcUserService.class)
              .withBean(DisablingOAuth2UserService.class),
          context -> {
            assertThat(context.getBean(DisablingOidcUserService.class).calls).hasValue(1);
            assertThat(context.getBean(DisablingOAuth2UserService.class).calls).hasValue(0);
          });
    }
  }

  @Test
  void givenEnabledAndTheOAuth2UserServiceRefusesTheRefreshedUser_whenTheTokenIsRefreshed_thenUnauthorizedAndLoggedOut()
      throws Exception {
    try (var op = new TestJwkSet()) {
      final var refreshedIdToken = op.sign(null, TestJwkSet.claims(ISSUER, CLIENT_ID));
      final var userService = new DisablingOAuth2UserService();

      assertRelayIsUnauthorizedAndLogsOut(runner(op, refreshedIdToken)
          .withBean(DisablingOAuth2UserService.class, () -> userService));

      assertThat(userService.calls).hasValue(1);
    }
  }

  @Test
  void givenDisabledAndTheRefreshedIdTokenIsRefused_whenTheTokenIsRefreshed_thenServerErrorAndTheAuthorizedClientIsRemoved()
      throws Exception {
    try (var op = new TestJwkSet()) {
      runner(op, refusedIdToken(op)).run(context -> {
        assertThat(context).hasNotFailed();

        client(context).get().uri("/bff/api/greetings/me").exchange().expectStatus()
            .is5xxServerError().expectHeader().doesNotExist(HttpHeaders.LOCATION);

        assertThat(session.get().isExpired()).isFalse();
        assertThat(session.get().getAttributes().values())
            .noneMatch(value -> value instanceof Map<?, ?> clients && clients.containsKey("reg"));
      });
    }
  }

  private void assertRelayIsUnauthorizedAndLogsOut(ReactiveWebApplicationContextRunner runner) {
    assertRelayIsUnauthorizedAndLogsOut(runner, context -> {
    });
  }

  private void assertRelayIsUnauthorizedAndLogsOut(ReactiveWebApplicationContextRunner runner,
      ContextConsumer<AssertableReactiveWebApplicationContext> andThen) {
    runner
        .withPropertyValues(
            "com.c4-soft.springaddons.oidc.client.client-authorization-required.enabled=true")
        .run(context -> {
          assertThat(context).hasNotFailed();

          client(context).get().uri("/bff/api/greetings/me").exchange().expectStatus()
              .isUnauthorized().expectHeader().doesNotExist(HttpHeaders.LOCATION);

          assertThat(session.get().isExpired()).isTrue();
          andThen.accept(context);
        });
  }

  /**
   * The user service of an application refusing a user disabled since the login, which calls an API
   * with the authorized client manager (it can't be resolved when the manager is created)
   */
  static class DisablingOidcUserService
      implements ReactiveOAuth2UserService<OidcUserRequest, OidcUser> {
    final AtomicInteger calls = new AtomicInteger();

    DisablingOidcUserService(ReactiveOAuth2AuthorizedClientManager authorizedClientManager) {}

    @Override
    public Mono<OidcUser> loadUser(OidcUserRequest userRequest) {
      calls.incrementAndGet();
      return Mono.error(new DisabledException("User is disabled"));
    }
  }

  /**
   * The user info service of an application (the OpenID user service delegates to it) refusing a
   * user disabled since the login
   */
  static class DisablingOAuth2UserService
      implements ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> {
    final AtomicInteger calls = new AtomicInteger();

    @Override
    public Mono<OAuth2User> loadUser(OAuth2UserRequest userRequest) {
      calls.incrementAndGet();
      return Mono.error(new DisabledException("User is disabled"));
    }
  }

  private static ReactiveWebApplicationContextRunner runner(TestJwkSet op,
      String refreshedIdToken) {
    final var tokenUri = op.serveJson("/token", """
        {
          "access_token": "new-at",
          "token_type": "Bearer",
          "expires_in": 300,
          "refresh_token": "new-rt",
          "scope": "openid",
          "id_token": "%s"
        }
        """.formatted(refreshedIdToken));
    final var registration = ClientRegistration.withRegistrationId("reg").clientId(CLIENT_ID)
        .clientSecret("secret").authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .scope("openid").redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .authorizationUri(ISSUER + "/authorize").tokenUri(tokenUri.toString())
        .userInfoUri(op.serveJson("/userinfo", "{\"sub\": \"ch4mp\"}").toString())
        .userNameAttributeName("sub").jwkSetUri(op.jwkSetUri().toString()).issuerUri(ISSUER)
        .build();

    return new ReactiveWebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(ConfigurationPropertiesAutoConfiguration.class,
            SpringAddonsOidcProperties.class, OAuth2ClientProperties.class,
            ServerProperties.class, WebFluxProperties.class,
            ReactiveSpringAddonsOidcClientWithLoginBeans.class,
            ReactiveSpringAddonsOAuth2AuthorizedClientBeans.class))
        .withBean(ReactiveClientRegistrationRepository.class,
            () -> new InMemoryReactiveClientRegistrationRepository(registration))
        .withPropertyValues("com.c4-soft.springaddons.oidc.client.security-matchers=/**",
            "com.c4-soft.springaddons.oidc.ops[0].iss=" + ISSUER,
            "com.c4-soft.springaddons.oidc.ops[0].authorities[0].path=$.roles",
            "spring.security.oauth2.client.registration.reg.client-id=" + CLIENT_ID);
  }

  /**
   * @return an ID token Spring Security refuses after a refresh: its nonce isn't the login one
   */
  private static String refusedIdToken(TestJwkSet op) throws Exception {
    return op.sign(null,
        TestJwkSet.claims(ISSUER, CLIENT_ID, Map.of("nonce", "not-the-login-nonce")));
  }

  /**
   * @return the OAuth2AuthenticationToken built by {@code oauth2Login}
   */
  private OAuth2AuthenticationToken oauth2Login() {
    final var idToken = OidcIdToken.withTokenValue("login-id-token").issuer(ISSUER)
        .subject("ch4mp").audience(List.of(CLIENT_ID)).issuedAt(loginTime)
        .expiresAt(loginTime.plusSeconds(300)).claim("nonce", "login-nonce")
        .claim("roles", List.of("OLD")).build();
    final var authorities = AuthorityUtils.createAuthorityList("OLD");
    return new OAuth2AuthenticationToken(new DefaultOidcUser(authorities, idToken), authorities,
        "reg");
  }

  /**
   * A client whose requests run in a started session holding an expired authorized client, with the
   * {@code oauth2Login} authentication in the Reactor context (the security chain's
   * {@code ReactorContextWebFilter} keeps a context which is already there)
   */
  private WebTestClient client(AssertableReactiveWebApplicationContext context) {
    final var authorizedClientRepository =
        context.getBean(ServerOAuth2AuthorizedClientRepository.class);
    final var login = oauth2Login();
    final WebFilter loggedInSession = (exchange, chain) -> exchange.getSession()
        .doOnNext(webSession -> {
          webSession.start();
          session.set(webSession);
        })
        .then(authorizedClientRepository.saveAuthorizedClient(expiredAuthorizedClient(context),
            login, exchange))
        .then(chain.filter(exchange))
        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(login));
    return WebTestClient
        .bindToController(
            new TokenRelayController(context.getBean(ReactiveOAuth2AuthorizedClientManager.class)))
        .webFilter(loggedInSession, context.getBean(WebFilterChainProxy.class)).build();
  }

  private OAuth2AuthorizedClient expiredAuthorizedClient(
      AssertableReactiveWebApplicationContext context) {
    final var registration = context.getBean(ReactiveClientRegistrationRepository.class)
        .findByRegistrationId("reg").block();
    return new OAuth2AuthorizedClient(registration, "ch4mp",
        new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "login-at", loginTime,
            loginTime.plusSeconds(300)),
        new OAuth2RefreshToken("login-rt", loginTime));
  }

  /**
   * Authorizes the client of the logged-in user, as Spring Cloud Gateway's {@code TokenRelay=}
   * filter does, and answers its access token
   */
  @RestController
  static class TokenRelayController {
    private final ReactiveOAuth2AuthorizedClientManager authorizedClientManager;

    TokenRelayController(ReactiveOAuth2AuthorizedClientManager authorizedClientManager) {
      this.authorizedClientManager = authorizedClientManager;
    }

    @GetMapping("/bff/api/greetings/me")
    Mono<String> relay(ServerWebExchange exchange) {
      return ReactiveSecurityContextHolder.getContext().map(SecurityContext::getAuthentication)
          .flatMap(authentication -> authorizedClientManager.authorize(OAuth2AuthorizeRequest
              .withClientRegistrationId("reg").principal(authentication)
              .attribute(ServerWebExchange.class.getName(), exchange).build()))
          .map(authorizedClient -> authorizedClient.getAccessToken().getTokenValue());
    }
  }
}
