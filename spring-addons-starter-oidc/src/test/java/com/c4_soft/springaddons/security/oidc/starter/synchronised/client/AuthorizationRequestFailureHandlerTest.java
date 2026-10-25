package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import static org.assertj.core.api.Assertions.assertThat;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import com.c4_soft.springaddons.security.oidc.starter.OAuth2ClientRefusal;
import com.c4_soft.springaddons.security.oidc.starter.properties.InvalidPostLoginUriException;
import com.c4_soft.springaddons.security.oidc.starter.properties.InvalidRedirectionUriException;

class AuthorizationRequestFailureHandlerTest {
  private final List<OAuth2ClientRefusal> refusals = new ArrayList<>();
  private final AuthorizationRequestFailureHandler handler =
      new AuthorizationRequestFailureHandler((request, response, refusal) -> {
        refusals.add(refusal);
        response.setStatus(refusal.status().value());
      });

  /**
   * What OAuth2AuthorizationRequestRedirectFilter hands to its failure handler: the resolver's
   * exception wrapped in an AuthenticationException
   */
  private static AuthenticationException wrapped(Throwable cause) {
    return new AuthenticationException(cause.getMessage(), cause) {
      private static final long serialVersionUID = 1L;
    };
  }

  @Test
  void givenInvalidPostLoginUri_whenOnAuthenticationFailure_thenBadRequestThroughTheWriter()
      throws Exception {
    final var response = new MockHttpServletResponse();

    handler.onAuthenticationFailure(new MockHttpServletRequest(), response,
        wrapped(new InvalidPostLoginUriException("https://evil.com")));

    assertThat(response.getStatus()).isEqualTo(400);
    assertThat(response.getHeader(HttpHeaders.LOCATION)).isNull();
    assertThat(refusals).singleElement().satisfies(
        refusal -> assertThat(refusal.kind()).isEqualTo(OAuth2ClientRefusal.Kind.INVALID_POST_LOGIN_URI));
  }

  @Test
  void givenInvalidPostLoginUriWrappedByADecoratingResolver_whenOnAuthenticationFailure_thenBadRequest()
      throws Exception {
    final var response = new MockHttpServletResponse();

    handler.onAuthenticationFailure(new MockHttpServletRequest(), response, wrapped(
        new IllegalStateException("decorator", new InvalidPostLoginUriException("https://evil.com"))));

    assertThat(response.getStatus()).isEqualTo(400);
    assertThat(refusals).hasSize(1);
  }

  @Test
  void givenAnotherResolverException_whenOnAuthenticationFailure_thenSpringDefaultInternalServerError()
      throws Exception {
    final var response = new MockHttpServletResponse();

    // a plain InvalidRedirectionUriException is not a post-login URI refusal
    handler.onAuthenticationFailure(new MockHttpServletRequest(), response,
        wrapped(new InvalidRedirectionUriException("https://evil.com")));

    assertThat(response.getStatus()).isEqualTo(500);
    assertThat(refusals).isEmpty();
  }

  @Test
  void givenSpringSecurityOnTheClasspath_whenLoadingTheInvalidClientRegistrationIdExceptionName_thenItExists()
      throws Exception {
    // the class is package-private in Spring Security, matched by name to keep its WARN log level
    assertThat(Class.forName(AuthorizationRequestFailureHandler.INVALID_CLIENT_REGISTRATION_ID_EXCEPTION))
        .isAssignableTo(IllegalArgumentException.class);
  }
}
