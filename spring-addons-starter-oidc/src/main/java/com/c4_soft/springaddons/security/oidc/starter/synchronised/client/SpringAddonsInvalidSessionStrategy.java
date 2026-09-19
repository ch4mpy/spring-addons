package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.io.IOException;
import java.net.URI;
import org.springframework.http.HttpHeaders;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SimpleRedirectInvalidSessionStrategy;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

/**
 * <p>
 * Answers requests holding an invalid (expired) session ID with the status configured with
 * {@code com.c4-soft.springaddons.oidc.client.invalid-session.status} and, as {@code Location}, the
 * URI configured with {@code invalid-session.location} or, by default, the requested one (rebased
 * on {@code client-uri} if defined).
 * </p>
 * <p>
 * Like {@link SimpleRedirectInvalidSessionStrategy}, a new session is created before answering.
 * Without it, the user-agent would keep sending the invalid session cookie and, with a redirection
 * to the requested URI, would loop.
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Slf4j
public class SpringAddonsInvalidSessionStrategy implements InvalidSessionStrategy {
  private final SpringAddonsOidcClientProperties clientProperties;

  public SpringAddonsInvalidSessionStrategy(SpringAddonsOidcClientProperties clientProperties) {
    this.clientProperties = clientProperties;
  }

  @Override
  public void onInvalidSessionDetected(HttpServletRequest request, HttpServletResponse response)
      throws IOException, ServletException {
    final var status = clientProperties.getInvalidSession().getStatus();
    final var location = clientProperties.getInvalidSession().getLocation().map(URI::toString)
        .orElseGet(() -> requestedUri(request));

    // Replaces the invalid session cookie so that the user-agent does not present it again
    request.getSession();

    log.debug("Invalid session. Returning with status {} and {} as location", status.value(),
        location);
    response.setStatus(status.value());
    response.setHeader(HttpHeaders.LOCATION, location);
    if (status.is4xxClientError() || status.is5xxServerError()) {
      response.getOutputStream().write("Invalid session. Please authenticate.".getBytes());
    }
    response.flushBuffer();
  }

  /**
   * @return the requested URI, rebased on {@code client-uri} if it is defined. The context path is
   *         part of the request URI: it is kept as is when there is no {@code client-uri}, and
   *         replaced with the {@code client-uri} path otherwise.
   */
  private String requestedUri(HttpServletRequest request) {
    final var requestUri = request.getRequestURI();
    final var clientUri = clientProperties.getClientUri();
    if (clientUri.isEmpty()) {
      return StringUtils.hasText(request.getQueryString())
          ? requestUri + "?" + request.getQueryString()
          : requestUri;
    }
    final var contextPath = request.getContextPath();
    final var pathInContext = StringUtils.hasText(contextPath) && requestUri.startsWith(contextPath)
        ? requestUri.substring(contextPath.length())
        : requestUri;
    return UriComponentsBuilder.fromUri(clientUri.get()).path(pathInContext)
        .query(request.getQueryString()).build().toString();
  }
}
