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

  @Test
  void givenContextPathAndNoClientUri_whenCommence_thenLocationIsContextPathLogin()
      throws Exception {
    assertThat(commence(new SpringAddonsOidcClientProperties(), "/gateway"))
        .isEqualTo("/gateway/login");
  }

  @Test
  void givenContextPathAndClientUriWithoutPath_whenCommence_thenContextPathIsKept()
      throws Exception {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.setClientUri(Optional.of(URI.create("https://host")));

    assertThat(commence(properties, "/gateway")).isEqualTo("https://host/gateway/login");
  }

  @Test
  void givenContextPathAndClientUriEndingWithIt_whenCommence_thenContextPathIsNotDuplicated()
      throws Exception {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.setClientUri(Optional.of(URI.create("https://host/gateway/")));

    assertThat(commence(properties, "/gateway")).isEqualTo("https://host/gateway/login");
  }

  @Test
  void givenContextPathAndUnauthorizedStatus_whenCommence_thenRealmAndBodyKeepContextPath()
      throws Exception {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.setClientUri(Optional.of(URI.create("https://host")));
    properties.getOauth2Redirections().setAuthenticationEntryPoint(HttpStatus.UNAUTHORIZED);
    final var request = new MockHttpServletRequest("GET", "/gateway/bff/events");
    request.setContextPath("/gateway");
    final var response = new MockHttpServletResponse();

    new SpringAddonsAuthenticationEntryPoint(properties).commence(request, response,
        new InsufficientAuthenticationException("test"));

    assertThat(response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
    assertThat(response.getHeader(HttpHeaders.WWW_AUTHENTICATE))
        .isEqualTo("OAuth realm=https://host/gateway/login");
    assertThat(response.getContentAsString())
        .isEqualTo("Unauthorized. Please authenticate at https://host/gateway/login");
  }

  private static String commence(SpringAddonsOidcClientProperties properties) throws Exception {
    return commence(properties, "");
  }

  private static String commence(SpringAddonsOidcClientProperties properties, String contextPath)
      throws Exception {
    final var request = new MockHttpServletRequest("GET", contextPath + "/api/me");
    request.setContextPath(contextPath);
    final var response = new MockHttpServletResponse();
    new SpringAddonsAuthenticationEntryPoint(properties).commence(request, response,
        new InsufficientAuthenticationException("test"));
    assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
    return response.getHeader(HttpHeaders.LOCATION);
  }
}
