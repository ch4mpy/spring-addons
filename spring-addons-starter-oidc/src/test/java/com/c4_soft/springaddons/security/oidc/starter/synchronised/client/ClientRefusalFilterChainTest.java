package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import static org.assertj.core.api.Assertions.assertThat;
import java.io.IOException;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientProperties;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.web.server.autoconfigure.ServerProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import jakarta.servlet.Filter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * The auto-configured client filter-chain ({@code springSecurityFilterChain}), with a servlet
 * failing like the {@code DispatcherServlet} does when a handler throws what
 * {@code OAuth2AuthorizedClientManager#authorize()} throws when the client must be authorized again
 * (a gateway {@code TokenRelay} filter, for instance).
 */
class ClientRefusalFilterChainTest {
  private static final ClientRegistration REGISTRATION = ClientRegistration.withRegistrationId("reg")
      .clientId("client-id").clientSecret("secret")
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
      .authorizationUri("https://op/authorize").tokenUri("https://op/token").build();

  /**
   * Another authorization_code registration, needing its own consent
   */
  private static final ClientRegistration GITHUB = ClientRegistration.withRegistrationId("github")
      .clientId("client-id").clientSecret("secret")
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
      .authorizationUri("https://github/authorize").tokenUri("https://github/token").build();

  private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(ConfigurationPropertiesAutoConfiguration.class,
          SpringAddonsOidcProperties.class, OAuth2ClientProperties.class, ServerProperties.class,
          SpringAddonsOidcClientWithLoginBeans.class))
      .withBean(ClientRegistrationRepository.class,
          () -> new InMemoryClientRegistrationRepository(REGISTRATION, GITHUB))
      .withPropertyValues("com.c4-soft.springaddons.oidc.client.security-matchers=/**",
          "spring.security.oauth2.client.registration.reg.client-id=client-id",
          "spring.security.oauth2.client.registration.github.client-id=client-id");

  /**
   * @return a session holding an OAuth2AuthenticationToken for the given registration, as after
   *         {@code oauth2Login}
   */
  private static MockHttpSession oauth2LoginSession(String registrationId) {
    final var authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
    final var session = new MockHttpSession();
    session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
        new SecurityContextImpl(new OAuth2AuthenticationToken(
            new DefaultOAuth2User(authorities, Map.of("sub", "ch4mp"), "sub"), authorities,
            registrationId)));
    return session;
  }

  @Test
  void givenEnabledAndOAuth2LoginAndRefreshRefusedForTheLoginRegistration_whenGetProtectedRoute_thenUnauthorizedAndLoggedOut() {
    runner
        .withPropertyValues(
            "com.c4-soft.springaddons.oidc.client.client-authorization-required.enabled=true")
        .run(context -> {
          assertThat(context).hasNotFailed();
          final var session = oauth2LoginSession("reg");
          final var request = get("/bff/api/greetings/me", session);
          final var response = new MockHttpServletResponse();

          context.getBean("springSecurityFilterChain", Filter.class).doFilter(request, response,
              handlerThrowing(new ClientAuthorizationException(
                  new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT), "reg")));

          assertThat(response.getStatus()).isEqualTo(401);
          assertThat(response.getHeader(HttpHeaders.LOCATION)).isNull();
          assertThat(session.isInvalid()).isTrue();
        });
  }

  @Test
  void givenEnabledAndOAuth2LoginAndRefreshRefusedForAnotherRegistration_whenGetProtectedRoute_thenIncrementalAuthorizationAndSessionKept() {
    runner
        .withPropertyValues(
            "com.c4-soft.springaddons.oidc.client.client-authorization-required.enabled=true")
        .run(context -> {
          assertThat(context).hasNotFailed();
          final var session = oauth2LoginSession("reg");
          final var request = get("/bff/api/github/repos", session);
          final var response = new MockHttpServletResponse();

          context.getBean("springSecurityFilterChain", Filter.class).doFilter(request, response,
              handlerThrowing(new ClientAuthorizationException(
                  new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT), "github")));

          // the redirect filter initiates the authorization of the other registration
          assertThat(response.getStatus()).isEqualTo(302);
          assertThat(response.getHeader(HttpHeaders.LOCATION))
              .startsWith("https://github/authorize?");
          assertThat(session.isInvalid()).isFalse();
        });
  }

  @AfterEach
  void clearSecurityContext() {
    SecurityContextHolder.clearContext();
  }

  /**
   * What the {@code DispatcherServlet} does with an exception thrown by a handler: wrapped in a
   * {@link ServletException}
   */
  private static MockFilterChain handlerThrowing(RuntimeException exception) {
    return new MockFilterChain(new HttpServlet() {
      private static final long serialVersionUID = 1L;

      @Override
      protected void service(HttpServletRequest req, HttpServletResponse resp)
          throws ServletException, IOException {
        throw new ServletException("Request processing failed: " + exception, exception);
      }
    });
  }

  /**
   * @return a session holding an authentication, as after {@code oauth2Login}
   */
  private static MockHttpSession loggedInSession() {
    final var session = new MockHttpSession();
    session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
        new SecurityContextImpl(new TestingAuthenticationToken("ch4mp", "", "ROLE_USER")));
    return session;
  }

  private static MockHttpServletRequest get(String path, MockHttpSession session) {
    final var request = new MockHttpServletRequest("GET", path);
    request.setServletPath(path);
    request.setSession(session);
    return request;
  }

  @Test
  void givenEnabledAndNoAuthorizedClient_whenGetProtectedRoute_thenUnauthorizedAndLoggedOut() {
    runner
        .withPropertyValues(
            "com.c4-soft.springaddons.oidc.client.client-authorization-required.enabled=true")
        .run(context -> {
          assertThat(context).hasNotFailed();
          final var session = loggedInSession();
          final var request = get("/bff/api/greetings/me", session);
          final var response = new MockHttpServletResponse();

          context.getBean("springSecurityFilterChain", Filter.class).doFilter(request, response,
              handlerThrowing(new ClientAuthorizationRequiredException("reg")));

          assertThat(response.getStatus()).isEqualTo(401);
          assertThat(response.getHeader(HttpHeaders.LOCATION)).isNull();
          assertThat(session.isInvalid()).isTrue();
          assertThat(request.getSession(false)).isNull();
        });
  }

  @Test
  void givenEnabledAndRefusedRefresh_whenGetProtectedRoute_thenUnauthorizedAndLoggedOut() {
    runner
        .withPropertyValues(
            "com.c4-soft.springaddons.oidc.client.client-authorization-required.enabled=true")
        .run(context -> {
          assertThat(context).hasNotFailed();
          final var session = loggedInSession();
          final var request = get("/bff/api/greetings/me", session);
          final var response = new MockHttpServletResponse();

          context.getBean("springSecurityFilterChain", Filter.class).doFilter(request, response,
              handlerThrowing(new ClientAuthorizationException(
                  new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT), "reg")));

          assertThat(response.getStatus()).isEqualTo(401);
          assertThat(response.getHeader(HttpHeaders.LOCATION)).isNull();
          assertThat(session.isInvalid()).isTrue();
        });
  }

  @Test
  void givenDisabledAndNoAuthorizedClient_whenGetProtectedRoute_thenRedirectedToAuthorizationEndpointAndSessionKept() {
    runner.run(context -> {
      assertThat(context).hasNotFailed();
      final var session = loggedInSession();
      final var request = get("/bff/api/greetings/me", session);
      final var response = new MockHttpServletResponse();

      // Spring Security's behavior, kept by default
      context.getBean("springSecurityFilterChain", Filter.class).doFilter(request, response,
          handlerThrowing(new ClientAuthorizationRequiredException("reg")));

      assertThat(response.getStatus()).isEqualTo(302);
      assertThat(response.getHeader(HttpHeaders.LOCATION)).startsWith("https://op/authorize?");
      assertThat(session.isInvalid()).isFalse();
    });
  }

  @Test
  void givenPostLoginUriNotAllowed_whenInitiateLogin_thenBadRequestWithoutLocationNorSession() {
    runner.run(context -> {
      assertThat(context).hasNotFailed();
      final var request = get("/oauth2/authorization/reg", null);
      request.addHeader(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_HEADER,
          "https://evil.com/ui/account");
      final var response = new MockHttpServletResponse();
      final var chain = new MockFilterChain();

      context.getBean("springSecurityFilterChain", Filter.class).doFilter(request, response,
          chain);

      assertThat(response.getStatus()).isEqualTo(400);
      assertThat(response.getHeader(HttpHeaders.LOCATION)).isNull();
      assertThat(request.getSession(false)).isNull();
      assertThat(chain.getRequest()).isNull();
    });
  }

  @Test
  void givenPostLoginUriAllowed_whenInitiateLogin_thenRedirectedToAuthorizationEndpointAndUriStoredInSession() {
    runner.run(context -> {
      assertThat(context).hasNotFailed();
      final var request = get("/oauth2/authorization/reg", null);
      request.addHeader(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_HEADER,
          "/ui/account");
      final var response = new MockHttpServletResponse();

      context.getBean("springSecurityFilterChain", Filter.class).doFilter(request, response,
          new MockFilterChain());

      assertThat(response.getStatus()).isEqualTo(302);
      assertThat(response.getHeader(HttpHeaders.LOCATION)).startsWith("https://op/authorize?");
      assertThat(request.getSession(false)).isNotNull();
      assertThat(request.getSession(false).getAttribute(
          SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE))
              .isEqualTo("/ui/account");
    });
  }
}
