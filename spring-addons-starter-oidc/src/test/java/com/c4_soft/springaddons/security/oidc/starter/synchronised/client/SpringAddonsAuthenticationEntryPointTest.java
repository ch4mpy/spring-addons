package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import static org.assertj.core.api.Assertions.assertThat;
import java.net.URI;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;

class SpringAddonsAuthenticationEntryPointTest {

  @Test
  void givenNoClientUriNorLoginUri_whenCommence_thenLocationIsLogin() throws Exception {
    assertThat(commence(new SpringAddonsOidcClientProperties())).isEqualTo("/login");
  }

  @Test
  void givenClientUriWithoutPath_whenCommence_thenLocationIsClientUriLogin() throws Exception {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.setClientUri(Optional.of(URI.create("https://app.example.com")));

    assertThat(commence(properties)).isEqualTo("https://app.example.com/login");
  }

  @Test
  void givenClientUriWithPath_whenCommence_thenClientUriPathIsNotDuplicated() throws Exception {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.setClientUri(Optional.of(URI.create("https://app.example.com/bff")));

    assertThat(commence(properties)).isEqualTo("https://app.example.com/bff/login");
  }

  @Test
  void givenLoginUri_whenCommence_thenLocationIsLoginUri() throws Exception {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.setClientUri(Optional.of(URI.create("https://app.example.com/bff")));
    properties.setLoginUri(Optional.of(URI.create("https://app.example.com/ui/login")));

    assertThat(commence(properties)).isEqualTo("https://app.example.com/ui/login");
  }

  private static String commence(SpringAddonsOidcClientProperties properties) throws Exception {
    final var response = new MockHttpServletResponse();
    new SpringAddonsAuthenticationEntryPoint(properties).commence(
        new MockHttpServletRequest("GET", "/api/me"), response,
        new InsufficientAuthenticationException("test"));
    assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
    return response.getHeader(HttpHeaders.LOCATION);
  }
}
