package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import static org.assertj.core.api.Assertions.assertThat;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import jakarta.servlet.http.HttpServletRequest;

class InvalidSessionPermitAllPassThroughFilterTest {
  private final InvalidSessionPermitAllPassThroughFilter filter =
      new InvalidSessionPermitAllPassThroughFilter(List.of("/login/**", "/me/**"));

  private static MockHttpServletRequest request(String contextPath, String path,
      boolean isRequestedSessionIdValid) {
    final var request = new MockHttpServletRequest("GET", contextPath + path);
    request.setContextPath(contextPath);
    request.setRequestedSessionId("0123456789ABCDEF0123456789ABCDEF");
    request.setRequestedSessionIdValid(isRequestedSessionIdValid);
    return request;
  }

  @Test
  void givenInvalidSessionOnPermitAllRoute_whenFilter_thenNewSessionAndChainProceedsWithoutRequestedSessionId()
      throws Exception {
    final var request = request("/gateway", "/me", false);
    final var chain = new MockFilterChain();

    filter.doFilter(request, new MockHttpServletResponse(), chain);

    assertThat(request.getSession(false)).isNotNull();
    final var forwarded = (HttpServletRequest) chain.getRequest();
    assertThat(forwarded).isNotNull();
    assertThat(forwarded.getRequestedSessionId()).isNull();
    assertThat(forwarded.isRequestedSessionIdValid()).isFalse();
  }

  @Test
  void givenInvalidSessionOnProtectedRoute_whenFilter_thenRequestIsForwardedUntouched()
      throws Exception {
    final var request = request("/gateway", "/api/greet", false);
    final var chain = new MockFilterChain();

    filter.doFilter(request, new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isSameAs(request);
    assertThat(request.getSession(false)).isNull();
  }

  @Test
  void givenValidSessionOnPermitAllRoute_whenFilter_thenRequestIsForwardedUntouched()
      throws Exception {
    final var request = request("", "/me", true);
    final var chain = new MockFilterChain();

    filter.doFilter(request, new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isSameAs(request);
  }

  @Test
  void givenNoSessionCookieOnPermitAllRoute_whenFilter_thenRequestIsForwardedUntouched()
      throws Exception {
    final var request = new MockHttpServletRequest("GET", "/me");
    final var chain = new MockFilterChain();

    filter.doFilter(request, new MockHttpServletResponse(), chain);

    assertThat(chain.getRequest()).isSameAs(request);
    assertThat(request.getSession(false)).isNull();
  }
}
