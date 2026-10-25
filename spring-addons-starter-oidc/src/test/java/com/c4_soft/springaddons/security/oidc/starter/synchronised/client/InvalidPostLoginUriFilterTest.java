package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import static org.assertj.core.api.Assertions.assertThat;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import com.c4_soft.springaddons.security.oidc.starter.OAuth2ClientRefusal;
import com.c4_soft.springaddons.security.oidc.starter.properties.InvalidRedirectionUriException;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;

class InvalidPostLoginUriFilterTest {
  private final List<OAuth2ClientRefusal> refusals = new ArrayList<>();
  private final InvalidPostLoginUriFilter filter;

  InvalidPostLoginUriFilterTest() {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.setPostLoginAllowedUriPatterns(List.of(Pattern.compile("^/(?!/).*$")));
    filter = new InvalidPostLoginUriFilter(properties, (request, response, refusal) -> {
      refusals.add(refusal);
      response.setStatus(refusal.status().value());
    });
  }

  private static MockHttpServletRequest loginRequest() {
    return new MockHttpServletRequest("GET", "/oauth2/authorization/reg");
  }

  @Test
  void givenPostLoginSuccessUriHeaderIsNotAllowed_whenFilter_thenBadRequestWithoutSessionNorChain()
      throws Exception {
    final var request = loginRequest();
    request.addHeader(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_HEADER,
        "https://evil.com/ui/account");
    final var response = new MockHttpServletResponse();
    final var chain = new MockFilterChain();

    filter.doFilter(request, response, chain);

    assertThat(response.getStatus()).isEqualTo(400);
    assertThat(response.getHeader(HttpHeaders.LOCATION)).isNull();
    assertThat(chain.getRequest()).isNull();
    assertThat(request.getSession(false)).isNull();
    assertThat(refusals).singleElement().satisfies(refusal -> {
      assertThat(refusal.kind()).isEqualTo(OAuth2ClientRefusal.Kind.INVALID_POST_LOGIN_URI);
      assertThat(refusal.cause()).isInstanceOf(InvalidRedirectionUriException.class)
          .hasMessageContaining("https://evil.com/ui/account");
    });
  }

  @Test
  void givenPostLoginFailureUriParamIsSchemeRelative_whenFilter_thenBadRequest()
      throws Exception {
    final var request = loginRequest();
    request.addParameter(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_PARAM,
        "//evil.com/ui/error");
    final var response = new MockHttpServletResponse();
    final var chain = new MockFilterChain();

    filter.doFilter(request, response, chain);

    assertThat(response.getStatus()).isEqualTo(400);
    assertThat(chain.getRequest()).isNull();
    assertThat(request.getSession(false)).isNull();
  }

  @Test
  void givenValidSuccessUriAndInvalidFailureUri_whenFilter_thenBadRequest() throws Exception {
    final var request = loginRequest();
    request.addHeader(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_HEADER,
        "/ui/account");
    request.addHeader(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_HEADER,
        "https://evil.com/ui/error");
    final var response = new MockHttpServletResponse();
    final var chain = new MockFilterChain();

    filter.doFilter(request, response, chain);

    assertThat(response.getStatus()).isEqualTo(400);
    assertThat(chain.getRequest()).isNull();
  }

  @Test
  void givenAllowedPostLoginUris_whenFilter_thenChainProceeds() throws Exception {
    final var request = loginRequest();
    request.addHeader(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_HEADER,
        "/ui/account");
    request.addParameter(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_PARAM,
        "/ui/error");
    final var response = new MockHttpServletResponse();
    final var chain = new MockFilterChain();

    filter.doFilter(request, response, chain);

    assertThat(chain.getRequest()).isSameAs(request);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(refusals).isEmpty();
  }

  @Test
  void givenAllowedHeaderAndRefusedParam_whenFilter_thenHeaderWinsAndChainProceeds()
      throws Exception {
    final var request = loginRequest();
    request.addHeader(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_HEADER,
        "/ui/account");
    request.addParameter(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_PARAM,
        "https://evil.com/ui/account");
    final var response = new MockHttpServletResponse();
    final var chain = new MockFilterChain();

    filter.doFilter(request, response, chain);

    assertThat(chain.getRequest()).isSameAs(request);
    assertThat(refusals).isEmpty();
  }

  @Test
  void givenNoPostLoginUri_whenFilter_thenChainProceeds() throws Exception {
    final var request = new MockHttpServletRequest("GET", "/bff/api/greetings/me");
    final var response = new MockHttpServletResponse();
    final var chain = new MockFilterChain();

    filter.doFilter(request, response, chain);

    assertThat(chain.getRequest()).isSameAs(request);
    assertThat(request.getSession(false)).isNull();
    assertThat(refusals).isEmpty();
  }
}
