package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import com.c4_soft.springaddons.security.oidc.starter.OAuth2ClientRefusal;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpSession;

class ClientAuthorizationExceptionFilterTest {
  /**
   * "reg" is the registration users log in with, "github" another authorization_code one (needing
   * its own consent), "cc" a client_credentials one
   */
  static final InMemoryClientRegistrationRepository REGISTRATIONS =
      new InMemoryClientRegistrationRepository(
          ClientRegistration.withRegistrationId("reg").clientId("client-id")
              .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
              .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
              .authorizationUri("https://op/authorize").tokenUri("https://op/token").build(),
          ClientRegistration.withRegistrationId("github").clientId("client-id")
              .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
              .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
              .authorizationUri("https://github/authorize").tokenUri("https://github/token")
              .build(),
          ClientRegistration.withRegistrationId("cc").clientId("machine")
              .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
              .tokenUri("https://op/token").build());

  private final List<OAuth2ClientRefusal> refusals = new ArrayList<>();
  private final ClientAuthorizationExceptionFilter filter =
      new ClientAuthorizationExceptionFilter(REGISTRATIONS, (request, response, refusal) -> {
        refusals.add(refusal);
        response.setStatus(refusal.status().value());
      });

  @AfterEach
  void clearSecurityContext() {
    SecurityContextHolder.clearContext();
  }

  /**
   * A request with a session holding an authentication, as after {@code oauth2Login}
   */
  private static MockHttpServletRequest loggedInRequest() {
    final var request = new MockHttpServletRequest("GET", "/bff/api/greetings/me");
    final var session = new MockHttpSession();
    request.setSession(session);
    final var context = SecurityContextHolder.createEmptyContext();
    context.setAuthentication(new TestingAuthenticationToken("ch4mp", "", "ROLE_USER"));
    SecurityContextHolder.setContext(context);
    session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);
    return request;
  }

  /**
   * A request with a session holding an {@link OAuth2AuthenticationToken} for the given
   * registration, as after {@code oauth2Login}
   */
  private static MockHttpServletRequest oauth2LoginRequest(String registrationId) {
    final var request = new MockHttpServletRequest("GET", "/bff/api/greetings/me");
    final var session = new MockHttpSession();
    request.setSession(session);
    final var authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
    final var context = SecurityContextHolder.createEmptyContext();
    context.setAuthentication(new OAuth2AuthenticationToken(
        new DefaultOAuth2User(authorities, Map.of("sub", "ch4mp"), "sub"), authorities,
        registrationId));
    SecurityContextHolder.setContext(context);
    session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);
    return request;
  }

  private static FilterChain throwing(Exception exception) {
    return (request, response) -> {
      if (exception instanceof ServletException servletException) {
        throw servletException;
      }
      if (exception instanceof IOException ioException) {
        throw ioException;
      }
      throw (RuntimeException) exception;
    };
  }

  @Test
  void givenChainThrowsClientAuthorizationRequiredExceptionWrappedInServletException_whenFilter_thenLoggedOutAndUnauthorized()
      throws Exception {
    final var request = loggedInRequest();
    final var session = (MockHttpSession) request.getSession(false);
    final var response = new MockHttpServletResponse();
    // what the DispatcherServlet does with an exception thrown by a handler
    final var chain = throwing(new ServletException("Request processing failed",
        new ClientAuthorizationRequiredException("reg")));

    filter.doFilter(request, response, chain);

    assertThat(response.getStatus()).isEqualTo(401);
    assertThat(response.getHeader(HttpHeaders.LOCATION)).isNull();
    assertThat(session.isInvalid()).isTrue();
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    assertThat(refusals).singleElement().satisfies(refusal -> {
      assertThat(refusal.kind()).isEqualTo(OAuth2ClientRefusal.Kind.AUTHORIZATION_REQUIRED);
      assertThat(refusal.cause()).isInstanceOf(ClientAuthorizationRequiredException.class);
    });
  }

  @Test
  void givenChainThrowsClientAuthorizationExceptionForRefusedRefresh_whenFilter_thenLoggedOutAndUnauthorized()
      throws Exception {
    final var request = loggedInRequest();
    final var session = (MockHttpSession) request.getSession(false);
    final var response = new MockHttpServletResponse();
    // what RefreshTokenOAuth2AuthorizedClientProvider throws on invalid_grant
    final var chain = throwing(new ClientAuthorizationException(
        new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT), "reg"));

    filter.doFilter(request, response, chain);

    assertThat(response.getStatus()).isEqualTo(401);
    assertThat(response.getHeader(HttpHeaders.LOCATION)).isNull();
    assertThat(session.isInvalid()).isTrue();
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    assertThat(refusals).singleElement().satisfies(refusal -> {
      assertThat(refusal.kind()).isEqualTo(OAuth2ClientRefusal.Kind.AUTHORIZATION_REQUIRED);
      assertThat(((ClientAuthorizationException) refusal.cause()).getError().getErrorCode())
          .isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
    });
  }

  @Test
  void givenAsyncDispatchThrowsClientAuthorizationException_whenFilter_thenLoggedOutAndUnauthorized()
      throws Exception {
    final var request = loggedInRequest();
    // an async handler result (a WebClient Mono, a Callable...) completed with the exception
    request.setDispatcherType(DispatcherType.ASYNC);
    final var session = (MockHttpSession) request.getSession(false);
    final var response = new MockHttpServletResponse();

    filter.doFilter(request, response, throwing(new ClientAuthorizationException(
        new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT), "reg")));

    assertThat(response.getStatus()).isEqualTo(401);
    assertThat(session.isInvalid()).isTrue();
  }

  @Test
  void givenSessionAlreadyInvalidatedByAConcurrentRequest_whenFilter_thenStillUnauthorized()
      throws Exception {
    final var request = new MockHttpServletRequest("GET", "/bff/api/greetings/me");
    final var session = mock(HttpSession.class);
    doThrow(new IllegalStateException("Session already invalidated")).when(session).invalidate();
    request.setSession(session);
    final var response = new MockHttpServletResponse();

    filter.doFilter(request, response, throwing(new ClientAuthorizationException(
        new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT), "reg")));

    assertThat(response.getStatus()).isEqualTo(401);
    assertThat(refusals).hasSize(1);
  }

  @Test
  void givenOAuth2LoginWithTheFailingRegistration_whenFilter_thenLoggedOutAndUnauthorized()
      throws Exception {
    final var request = oauth2LoginRequest("reg");
    final var session = (MockHttpSession) request.getSession(false);
    final var response = new MockHttpServletResponse();

    filter.doFilter(request, response, throwing(new ClientAuthorizationException(
        new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT), "reg")));

    assertThat(response.getStatus()).isEqualTo(401);
    assertThat(session.isInvalid()).isTrue();
  }

  @Test
  void givenOAuth2LoginAndAnotherRegistrationMissing_whenFilter_thenAuthorizationRequiredForItAndSessionKept() {
    final var request = oauth2LoginRequest("reg");
    final var session = (MockHttpSession) request.getSession(false);

    // for the redirect filter upstream: incremental authorization
    assertThatThrownBy(() -> filter.doFilter(request, new MockHttpServletResponse(),
        throwing(new ServletException("Request processing failed",
            new ClientAuthorizationRequiredException("github")))))
                .isInstanceOfSatisfying(ClientAuthorizationRequiredException.class,
                    ex -> assertThat(ex.getClientRegistrationId()).isEqualTo("github"));

    assertThat(session.isInvalid()).isFalse();
    assertThat(refusals).isEmpty();
  }

  @Test
  void givenOAuth2LoginAndRefreshRefusedForAnotherRegistration_whenFilter_thenAuthorizationRequiredForItAndSessionKept() {
    final var request = oauth2LoginRequest("reg");
    final var session = (MockHttpSession) request.getSession(false);

    // the plain exception is handled like its subclass, not left to become a 500
    assertThatThrownBy(() -> filter.doFilter(request, new MockHttpServletResponse(),
        throwing(new ClientAuthorizationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT),
            "github"))))
                .isInstanceOfSatisfying(ClientAuthorizationRequiredException.class,
                    ex -> assertThat(ex.getClientRegistrationId()).isEqualTo("github"));

    assertThat(session.isInvalid()).isFalse();
    assertThat(refusals).isEmpty();
  }

  @Test
  void givenClientCredentialsRegistration_whenFilter_thenRethrownAndSessionKept() {
    final var request = loggedInRequest();
    final var session = (MockHttpSession) request.getSession(false);
    final var response = new MockHttpServletResponse();
    // a server-side credential failure: the user logging in again would not fix it
    final var exception =
        new ClientAuthorizationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT), "cc");

    assertThatThrownBy(() -> filter.doFilter(request, response, throwing(exception)))
        .isSameAs(exception);

    assertThat(session.isInvalid()).isFalse();
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
    assertThat(refusals).isEmpty();
  }

  @Test
  void givenUnknownRegistration_whenFilter_thenRethrownAndSessionKept() {
    final var request = loggedInRequest();
    final var session = (MockHttpSession) request.getSession(false);
    final var exception = new ClientAuthorizationRequiredException("unknown");

    assertThatThrownBy(
        () -> filter.doFilter(request, new MockHttpServletResponse(), throwing(exception)))
            .isSameAs(exception);

    assertThat(session.isInvalid()).isFalse();
    assertThat(refusals).isEmpty();
  }

  @Test
  void givenResponseAlreadyCommitted_whenFilter_thenRethrownAndSessionKept() {
    final var request = loggedInRequest();
    final var session = (MockHttpSession) request.getSession(false);
    final var response = new MockHttpServletResponse();
    response.setCommitted(true);
    final var exception = new ClientAuthorizationRequiredException("reg");

    assertThatThrownBy(() -> filter.doFilter(request, response, throwing(exception)))
        .isSameAs(exception);

    assertThat(session.isInvalid()).isFalse();
    assertThat(refusals).isEmpty();
  }

  @Test
  void givenChainThrowsAnotherRuntimeException_whenFilter_thenRethrownAndSessionKept() {
    final var request = loggedInRequest();
    final var session = (MockHttpSession) request.getSession(false);
    final var response = new MockHttpServletResponse();
    final var exception = new IllegalStateException("something else");

    assertThatThrownBy(() -> filter.doFilter(request, response, throwing(exception)))
        .isSameAs(exception);

    assertThat(session.isInvalid()).isFalse();
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
    assertThat(refusals).isEmpty();
  }

  @Test
  void givenChainThrowsServletExceptionWithAnotherCause_whenFilter_thenRethrownAndSessionKept() {
    final var request = loggedInRequest();
    final var session = (MockHttpSession) request.getSession(false);
    final var response = new MockHttpServletResponse();
    final var exception =
        new ServletException("Request processing failed", new IllegalStateException());

    assertThatThrownBy(() -> filter.doFilter(request, response, throwing(exception)))
        .isSameAs(exception);

    assertThat(session.isInvalid()).isFalse();
    assertThat(refusals).isEmpty();
  }

  @Test
  void givenChainThrowsIOException_whenFilter_thenRethrown() {
    final var request = loggedInRequest();
    final var response = new MockHttpServletResponse();
    final var exception = new IOException("broken pipe");

    assertThatThrownBy(() -> filter.doFilter(request, response, throwing(exception)))
        .isSameAs(exception);

    assertThat(refusals).isEmpty();
  }

  @Test
  void givenChainSucceeds_whenFilter_thenResponseAndSessionUntouched() throws Exception {
    final var request = loggedInRequest();
    final var session = (MockHttpSession) request.getSession(false);
    final var response = new MockHttpServletResponse();
    final var chain = new MockFilterChain();

    filter.doFilter(request, response, chain);

    assertThat(chain.getRequest()).isSameAs(request);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(session.isInvalid()).isFalse();
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
    assertThat(refusals).isEmpty();
  }
}
