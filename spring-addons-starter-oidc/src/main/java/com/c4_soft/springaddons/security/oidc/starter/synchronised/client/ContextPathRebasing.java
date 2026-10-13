package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.net.URI;
import java.util.Optional;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Builds URIs within the servlet application, rebased on {@code client-uri} if it is defined. The
 * context path is kept when there is no {@code client-uri} or when the {@code client-uri} path does
 * not end with it (a {@code client-uri} with scheme and authority only, for instance), and it is
 * not repeated when the {@code client-uri} path already ends with it.
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
final class ContextPathRebasing {
  private ContextPathRebasing() {}

  /**
   * @param clientUri the {@code client-uri} property
   * @param request the current request (for its context path)
   * @param pathWithContextPath a path starting with the request context path
   * @param query a query string (may be null)
   * @return {@code pathWithContextPath} (and {@code query}), rebased on {@code clientUri} if any
   */
  static String rebase(Optional<URI> clientUri, HttpServletRequest request,
      String pathWithContextPath, String query) {
    if (clientUri.isEmpty()) {
      return StringUtils.hasText(query) ? pathWithContextPath + "?" + query : pathWithContextPath;
    }
    final var contextPath = request.getContextPath();
    final var clientUriPath = StringUtils.trimTrailingCharacter(
        Optional.ofNullable(clientUri.get().getPath()).orElse(""), '/');
    final var isContextPathInClientUri = StringUtils.hasText(contextPath)
        && clientUriPath.endsWith(contextPath) && pathWithContextPath.startsWith(contextPath);
    final var path = isContextPathInClientUri ? pathWithContextPath.substring(contextPath.length())
        : pathWithContextPath;
    return UriComponentsBuilder.fromUri(clientUri.get()).path(path).query(query).build()
        .toString();
  }
}
