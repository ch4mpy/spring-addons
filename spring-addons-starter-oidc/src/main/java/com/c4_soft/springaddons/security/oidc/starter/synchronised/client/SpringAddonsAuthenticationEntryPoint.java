package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.io.IOException;
import java.net.URI;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.util.UriComponentsBuilder;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SpringAddonsAuthenticationEntryPoint implements AuthenticationEntryPoint {
  private final SpringAddonsOidcClientProperties clientProperties;

  public SpringAddonsAuthenticationEntryPoint(SpringAddonsOidcClientProperties addonsProperties) {
    this.clientProperties = addonsProperties;
  }

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException authException) throws IOException, ServletException {
    final var location = clientProperties.getLoginUri()
        .orElseGet(() -> clientProperties.getClientUri()
            .map(clientUri -> UriComponentsBuilder.fromUri(clientUri)
                .pathSegment(clientUri.getPath(), "login").build().toUri())
            .orElse(URI.create("/login")))
        .toString();
    log.debug("Status: {}, location: {}",
        clientProperties.getOauth2Redirections().getAuthenticationEntryPoint().value(), location);

    response
        .setStatus(clientProperties.getOauth2Redirections().getAuthenticationEntryPoint().value());
    response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "OAuth realm=%s".formatted(location));
    response.setHeader(HttpHeaders.LOCATION, location.toString());

    if (clientProperties.getOauth2Redirections().getAuthenticationEntryPoint().is4xxClientError()
        || clientProperties.getOauth2Redirections().getAuthenticationEntryPoint()
            .is5xxServerError()) {
      response.getOutputStream().write(
          "Unauthorized. Please authenticate at %s".formatted(location.toString()).getBytes());
    }

    response.flushBuffer();
  }
}
