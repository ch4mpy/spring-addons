package com.c4_soft.springaddons.security.oidc.starter;

import java.net.URI;
import java.util.Optional;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Builds URIs within the application, rebased on {@code client-uri} if it is defined. The context
 * path ({@code server.servlet.context-path} or {@code spring.webflux.base-path}) is kept when there
 * is no {@code client-uri} or when the {@code client-uri} path does not end with it (a
 * {@code client-uri} with scheme and authority only, for instance), and it is not repeated when the
 * {@code client-uri} path already ends with it.
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
public final class ContextPathRebasing {
  private ContextPathRebasing() {}

  /**
   * @param clientUri the {@code client-uri} property
   * @param contextPath the request context path (empty if none)
   * @param pathWithContextPath a path within the application, starting with the context path
   * @return a builder for {@code pathWithContextPath}, rebased on {@code clientUri} if any. The
   *         query and fragment are left to the caller.
   */
  public static UriComponentsBuilder rebase(Optional<URI> clientUri, String contextPath,
      String pathWithContextPath) {
    if (clientUri.isEmpty()) {
      return UriComponentsBuilder.fromPath(pathWithContextPath);
    }
    final var clientUriPath = StringUtils.trimTrailingCharacter(
        Optional.ofNullable(clientUri.get().getPath()).orElse(""), '/');
    final var isContextPathInClientUri = StringUtils.hasText(contextPath)
        && clientUriPath.endsWith(contextPath) && pathWithContextPath.startsWith(contextPath);
    final var path = isContextPathInClientUri ? pathWithContextPath.substring(contextPath.length())
        : pathWithContextPath;
    return UriComponentsBuilder.fromUri(clientUri.get()).path(path);
  }
}
