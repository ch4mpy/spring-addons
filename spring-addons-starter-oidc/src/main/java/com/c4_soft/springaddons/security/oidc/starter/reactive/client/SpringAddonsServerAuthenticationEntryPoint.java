package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import java.net.URI;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.web.server.ServerWebExchange;
import com.c4_soft.springaddons.security.oidc.starter.ContextPathRebasing;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Answers unauthorized requests with the status configured with
 * {@code com.c4-soft.springaddons.oidc.client.oauth2-redirections.authentication-entry-point} and,
 * as {@code Location}, the {@code login-uri} or, by default, the {@code /login} path of the
 * application, rebased on {@code client-uri} if defined (see {@link ContextPathRebasing}).
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Slf4j
public class SpringAddonsServerAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {
  private final SpringAddonsOidcClientProperties clientProperties;

  public SpringAddonsServerAuthenticationEntryPoint(
      SpringAddonsOidcClientProperties addonsProperties) {
    this.clientProperties = addonsProperties;
  }

  @Override
  public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
    final var contextPath = exchange.getRequest().getPath().contextPath().value();
    final var location = clientProperties.getLoginUri().map(URI::toString)
        .orElseGet(() -> ContextPathRebasing
            .rebase(clientProperties.getClientUri(), contextPath, contextPath + "/login").build()
            .toString());
    log.debug("Status: {}, location: {}",
        clientProperties.getOauth2Redirections().getAuthenticationEntryPoint().value(), location);

    final var response = exchange.getResponse();
    response.setStatusCode(clientProperties.getOauth2Redirections().getAuthenticationEntryPoint());
    response.getHeaders().set(HttpHeaders.WWW_AUTHENTICATE, "OAuth realm=%s".formatted(location));
    response.getHeaders().add(HttpHeaders.LOCATION, location);

    if (clientProperties.getOauth2Redirections().getAuthenticationEntryPoint().is4xxClientError()
        || clientProperties.getOauth2Redirections().getAuthenticationEntryPoint()
            .is5xxServerError()) {
      final var buffer = response.bufferFactory()
          .wrap("Unauthorized. Please authenticate at %s".formatted(location).getBytes());
      return response.writeWith(Flux.just(buffer));
    }

    return response.setComplete();
  }
}
