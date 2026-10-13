package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.io.IOException;
import java.net.URI;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import com.c4_soft.springaddons.security.oidc.starter.ContextPathRebasing;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

/**
 * Answers unauthorized requests with the status configured with
 * {@code com.c4-soft.springaddons.oidc.client.oauth2-redirections.authentication-entry-point} and,
 * as {@code Location}, the {@code login-uri} or, by default, the {@code /login} path of the
 * application, rebased on {@code client-uri} if defined (see {@link ContextPathRebasing}).
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Slf4j
public class SpringAddonsAuthenticationEntryPoint implements AuthenticationEntryPoint {
  private final SpringAddonsOidcClientProperties clientProperties;

  public SpringAddonsAuthenticationEntryPoint(SpringAddonsOidcClientProperties addonsProperties) {
    this.clientProperties = addonsProperties;
  }

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException authException) throws IOException, ServletException {
    final var location = clientProperties.getLoginUri().map(URI::toString)
        .orElseGet(() -> ContextPathRebasing.rebase(clientProperties.getClientUri(),
            request.getContextPath(), request.getContextPath() + "/login").build().toString());
    log.debug("Status: {}, location: {}",
        clientProperties.getOauth2Redirections().getAuthenticationEntryPoint().value(), location);

    response
        .setStatus(clientProperties.getOauth2Redirections().getAuthenticationEntryPoint().value());
    response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "OAuth realm=%s".formatted(location));
    response.setHeader(HttpHeaders.LOCATION, location);

    if (clientProperties.getOauth2Redirections().getAuthenticationEntryPoint().is4xxClientError()
        || clientProperties.getOauth2Redirections().getAuthenticationEntryPoint()
            .is5xxServerError()) {
      response.getOutputStream()
          .write("Unauthorized. Please authenticate at %s".formatted(location).getBytes());
    }

    response.flushBuffer();
  }
}
