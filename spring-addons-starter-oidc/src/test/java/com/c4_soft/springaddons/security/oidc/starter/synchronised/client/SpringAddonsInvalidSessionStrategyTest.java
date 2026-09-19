package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import static org.assertj.core.api.Assertions.assertThat;
import java.net.URI;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;

class SpringAddonsInvalidSessionStrategyTest {

  @Test
  void givenNoClientUriAndNoLocation_whenInvalidSession_thenRedirectedToRequestedUriWithContextPathKept()
      throws Exception {
    final var request = new MockHttpServletRequest("GET", "/bff/api/me");
    request.setContextPath("/bff");
    request.setQueryString("page=2");
    final var response = new MockHttpServletResponse();

    new SpringAddonsInvalidSessionStrategy(new SpringAddonsOidcClientProperties())
        .onInvalidSessionDetected(request, response);

    assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
    assertThat(response.getHeader(HttpHeaders.LOCATION)).isEqualTo("/bff/api/me?page=2");
  }

  @Test
  void givenClientUriWithPath_whenInvalidSession_thenContextPathIsReplacedWithClientUriPath()
      throws Exception {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.setClientUri(Optional.of(URI.create("https://app.example.com/bff")));
    final var request = new MockHttpServletRequest("GET", "/bff/api/me");
    request.setContextPath("/bff");
    final var response = new MockHttpServletResponse();

    new SpringAddonsInvalidSessionStrategy(properties).onInvalidSessionDetected(request, response);

    assertThat(response.getHeader(HttpHeaders.LOCATION))
        .isEqualTo("https://app.example.com/bff/api/me");
  }

  @Test
  void givenLocationIsConfigured_whenInvalidSession_thenRedirectedToIt() throws Exception {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.getInvalidSession().setLocation(Optional.of(URI.create("/ui/expired")));
    properties.getInvalidSession().setStatus(HttpStatus.UNAUTHORIZED);
    final var request = new MockHttpServletRequest("GET", "/api/me");
    final var response = new MockHttpServletResponse();

    new SpringAddonsInvalidSessionStrategy(properties).onInvalidSessionDetected(request, response);

    assertThat(response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
    assertThat(response.getHeader(HttpHeaders.LOCATION)).isEqualTo("/ui/expired");
    assertThat(response.getContentAsString()).isEqualTo("Invalid session. Please authenticate.");
  }

  @Test
  void whenInvalidSession_thenNewSessionIsCreatedSoThatTheUserAgentDropsTheInvalidCookie()
      throws Exception {
    final var request = new MockHttpServletRequest("GET", "/api/me");
    final var response = new MockHttpServletResponse();

    new SpringAddonsInvalidSessionStrategy(new SpringAddonsOidcClientProperties())
        .onInvalidSessionDetected(request, response);

    assertThat(request.getSession(false)).isNotNull();
  }
}
