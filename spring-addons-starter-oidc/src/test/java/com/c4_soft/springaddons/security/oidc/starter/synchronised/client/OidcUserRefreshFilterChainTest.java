package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.test.context.assertj.AssertableWebApplicationContext;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import com.c4_soft.springaddons.security.oidc.starter.TestJwkSet;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import jakarta.servlet.Filter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * The auto-configured client filter-chain, authorized client manager and provider, with a servlet
 * authorizing the client of an {@code oauth2Login} session whose access token expired, as Spring
 * Cloud Gateway's {@code TokenRelay=} filter does. The OpenID Provider is a local server signing the
 * refreshed ID tokens.
 */
class OidcUserRefreshFilterChainTest {
  private static final String ISSUER = "https://localhost:8443/realms/test";
  private static final String CLIENT_ID = "client-id";

  private final Instant loginTime = Instant.now().minusSeconds(600);

  @AfterEach
  void clearContexts() {
    SecurityContextHolder.clearContext();
    RequestContextHolder.resetRequestAttributes();
  }

  @Test
  void givenOAuth2LoginSession_whenTheTokenIsRefreshed_thenTheSessionHoldsTheRefreshedOidcUserAndAuthorities()
      throws Exception {
    try (var op = new TestJwkSet()) {
      final var refreshedIdToken =
          op.sign(null, TestJwkSet.claims(ISSUER, CLIENT_ID, Map.of("roles", List.of("NEW"))));

      runner(op, refreshedIdToken).run(context -> {
        assertThat(context).hasNotFailed();
        final var session = oauth2LoginSession();
        final var request = get(session);
        final var response = new MockHttpServletResponse();

        relay(context, request, response);

        assertThat(response.getStatus()).isEqualTo(200);
        final var login = loginAuthentication(request);
        assertThat(((OidcUser) login.getPrincipal()).getIdToken().getTokenValue())
            .isEqualTo(refreshedIdToken);
        assertThat(login.getAuthorities()).extracting(GrantedAuthority::getAuthority)
            .contains("NEW").doesNotContain("OLD");
        assertThat(authorizedClient(context, request).getAccessToken().getTokenValue())
            .isEqualTo("new-at");
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
  void givenEnabledAndTheUserServiceRefusesTheRefreshedUser_whenTheTokenIsRefreshed_thenUnauthorizedAndLoggedOut()
      throws Exception {
    try (var op = new TestJwkSet()) {
      final var refreshedIdToken = op.sign(null, TestJwkSet.claims(ISSUER, CLIENT_ID));

      final var userService = new DisablingOidcUserService();

      assertRelayIsUnauthorizedAndLogsOut(runner(op, refreshedIdToken).withBean(
          DisablingOidcUserService.class, () -> userService));

      assertThat(userService.calls).hasValue(1);
    }
  }

  /**
   * The user service of an application refusing a user disabled since the login
   */
  static class DisablingOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {
    final AtomicInteger calls = new AtomicInteger();

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) {
      calls.incrementAndGet();
      throw new DisabledException("User is disabled");
    }
  }

  @Test
  void givenDisabledAndTheRefreshedIdTokenIsRefused_whenTheTokenIsRefreshed_thenTheAuthorizedClientIsRemovedAndNoEntryPoint()
      throws Exception {
    try (var op = new TestJwkSet()) {
      runner(op, refusedIdToken(op)).run(context -> {
        assertThat(context).hasNotFailed();
        final var session = oauth2LoginSession();
        final var request = get(session);
        final var response = new MockHttpServletResponse();

        assertThatThrownBy(() -> relay(context, request, response))
            .isInstanceOf(ServletException.class).cause()
            .isInstanceOfSatisfying(ClientAuthorizationException.class, e -> assertThat(
                e.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeader(HttpHeaders.LOCATION)).isNull();
        assertThat(session.isInvalid()).isFalse();
        assertThat(authorizedClient(context, request)).isNull();
      });
    }
  }

  private static WebApplicationContextRunner runner(TestJwkSet op, String refreshedIdToken) {
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
        .jwkSetUri(op.jwkSetUri().toString()).issuerUri(ISSUER).build();

    return new WebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(ConfigurationPropertiesAutoConfiguration.class,
            SpringAddonsOidcProperties.class, OAuth2ClientProperties.class,
            ServerProperties.class, SpringAddonsOidcClientWithLoginBeans.class,
            SpringAddonsOAuth2AuthorizedClientBeans.class))
        .withBean(ClientRegistrationRepository.class,
            () -> new InMemoryClientRegistrationRepository(registration))
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
   * @return a session holding the OAuth2AuthenticationToken built by {@code oauth2Login}
   */
  private MockHttpSession oauth2LoginSession() {
    final var idToken = OidcIdToken.withTokenValue("login-id-token").issuer(ISSUER)
        .subject("ch4mp").audience(List.of(CLIENT_ID)).issuedAt(loginTime)
        .expiresAt(loginTime.plusSeconds(300)).claim("nonce", "login-nonce")
        .claim("roles", List.of("OLD")).build();
    final var authorities = AuthorityUtils.createAuthorityList("OLD");
    final var session = new MockHttpSession();
    session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
        new SecurityContextImpl(new OAuth2AuthenticationToken(
            new DefaultOidcUser(authorities, idToken), authorities, "reg")));
    return session;
  }

  private void assertRelayIsUnauthorizedAndLogsOut(WebApplicationContextRunner runner) {
    runner
        .withPropertyValues(
            "com.c4-soft.springaddons.oidc.client.client-authorization-required.enabled=true")
        .run(context -> {
          assertThat(context).hasNotFailed();
          final var session = oauth2LoginSession();
          final var request = get(session);
          final var response = new MockHttpServletResponse();

          relay(context, request, response);

          assertThat(response.getStatus()).isEqualTo(401);
          assertThat(response.getHeader(HttpHeaders.LOCATION)).isNull();
          assertThat(session.isInvalid()).isTrue();
        });
  }

  /**
   * Saves an expired authorized client in the session of the request, then runs the client
   * filter-chain with a {@link #tokenRelay(OAuth2AuthorizedClientManager) TokenRelay} handler
   */
  private void relay(AssertableWebApplicationContext context, MockHttpServletRequest request,
      MockHttpServletResponse response) throws Exception {
    saveExpiredAuthorizedClient(context, request, response);
    context.getBean("springSecurityFilterChain", Filter.class).doFilter(request, response,
        tokenRelay(context.getBean(OAuth2AuthorizedClientManager.class)));
  }

  private void saveExpiredAuthorizedClient(AssertableWebApplicationContext context,
      MockHttpServletRequest request, MockHttpServletResponse response) {
    final var registration =
        context.getBean(ClientRegistrationRepository.class).findByRegistrationId("reg");
    final var authorizedClient = new OAuth2AuthorizedClient(registration, "ch4mp",
        new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "login-at", loginTime,
            loginTime.plusSeconds(300)),
        new OAuth2RefreshToken("login-rt", loginTime));
    context.getBean(OAuth2AuthorizedClientRepository.class).saveAuthorizedClient(authorizedClient,
        loginAuthentication(request), request, response);
  }

  private static OAuth2AuthorizedClient authorizedClient(AssertableWebApplicationContext context,
      MockHttpServletRequest request) {
    return context.getBean(OAuth2AuthorizedClientRepository.class).loadAuthorizedClient("reg",
        loginAuthentication(request), request);
  }

  private static OAuth2AuthenticationToken loginAuthentication(MockHttpServletRequest request) {
    return (OAuth2AuthenticationToken) ((SecurityContext) request.getSession()
        .getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY))
            .getAuthentication();
  }

  /**
   * What a handler running {@code OAuth2AuthorizedClientManager#authorize()} does under the
   * {@code DispatcherServlet}: request attributes exposed, exceptions wrapped in a
   * {@link ServletException}
   */
  private static MockFilterChain tokenRelay(OAuth2AuthorizedClientManager authorizedClientManager) {
    return new MockFilterChain(new HttpServlet() {
      private static final long serialVersionUID = 1L;

      @Override
      protected void service(HttpServletRequest req, HttpServletResponse resp)
          throws ServletException {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(req, resp));
        try {
          authorizedClientManager.authorize(OAuth2AuthorizeRequest.withClientRegistrationId("reg")
              .principal(SecurityContextHolder.getContext().getAuthentication())
              .attribute(HttpServletRequest.class.getName(), req)
              .attribute(HttpServletResponse.class.getName(), resp).build());
        } catch (RuntimeException e) {
          throw new ServletException("Request processing failed: " + e, e);
        } finally {
          RequestContextHolder.resetRequestAttributes();
        }
      }
    });
  }

  private static MockHttpServletRequest get(MockHttpSession session) {
    final var request = new MockHttpServletRequest("GET", "/bff/api/greetings/me");
    request.setServletPath("/bff/api/greetings/me");
    request.setSession(session);
    return request;
  }
}
