package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import static org.assertj.core.api.Assertions.assertThat;
import java.net.URI;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;

class SpringAddonsServerAuthenticationEntryPointTest {

  @Test
  void givenNoClientUriNorLoginUri_whenCommence_thenLocationIsLogin() {
    assertThat(location(commence(new SpringAddonsOidcClientProperties(), ""))).isEqualTo("/login");
  }

  @Test
  void givenClientUriWithPath_whenCommence_thenClientUriPathIsNotDuplicated() {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.setClientUri(Optional.of(URI.create("https://app.example.com/bff")));

    assertThat(location(commence(properties, ""))).isEqualTo("https://app.example.com/bff/login");
  }

  @Test
  void givenLoginUri_whenCommence_thenLocationIsLoginUri() {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.setClientUri(Optional.of(URI.create("https://app.example.com/bff")));
    properties.setLoginUri(Optional.of(URI.create("https://app.example.com/ui/login")));

    assertThat(location(commence(properties, "/gateway")))
        .isEqualTo("https://app.example.com/ui/login");
  }

  @Test
  void givenBasePathAndNoClientUri_whenCommence_thenLocationIsBasePathLogin() {
    assertThat(location(commence(new SpringAddonsOidcClientProperties(), "/gateway")))
        .isEqualTo("/gateway/login");
  }

  @Test
  void givenBasePathAndClientUriWithoutPath_whenCommence_thenBasePathIsKept() {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.setClientUri(Optional.of(URI.create("https://host")));

    assertThat(location(commence(properties, "/gateway"))).isEqualTo("https://host/gateway/login");
  }

  @Test
  void givenBasePathAndClientUriEndingWithIt_whenCommence_thenBasePathIsNotDuplicated() {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.setClientUri(Optional.of(URI.create("https://host/gateway/")));

    assertThat(location(commence(properties, "/gateway"))).isEqualTo("https://host/gateway/login");
  }

  @Test
  void givenBasePathAndUnauthorizedStatus_whenCommence_thenRealmAndBodyKeepBasePath() {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.setClientUri(Optional.of(URI.create("https://host")));
    properties.getOauth2Redirections().setAuthenticationEntryPoint(HttpStatus.UNAUTHORIZED);

    final var exchange = commence(properties, "/gateway");

    assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    assertThat(exchange.getResponse().getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
        .isEqualTo("OAuth realm=https://host/gateway/login");
    assertThat(exchange.getResponse().getBodyAsString().block())
        .isEqualTo("Unauthorized. Please authenticate at https://host/gateway/login");
  }

  private static MockServerWebExchange commence(SpringAddonsOidcClientProperties properties,
      String basePath) {
    final var exchange = MockServerWebExchange
        .from(MockServerHttpRequest.get(basePath + "/api/me").contextPath(basePath));
    new SpringAddonsServerAuthenticationEntryPoint(properties)
        .commence(exchange, new InsufficientAuthenticationException("test")).block();
    return exchange;
  }

  private static String location(MockServerWebExchange exchange) {
    return exchange.getResponse().getHeaders().getFirst(HttpHeaders.LOCATION);
  }
}
