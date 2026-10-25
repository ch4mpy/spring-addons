package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import java.util.Optional;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.util.StringUtils;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;

/**
 * The post-login URIs a request carries, as a header or, failing that, as a query parameter (the
 * header wins). Used by {@link SpringAddonsServerOAuth2AuthorizationRequestResolver}, which stores
 * them in session.
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
final class PostLoginUris {

  private PostLoginUris() {}

  static Optional<String> success(ServerHttpRequest request) {
    return headerOrParam(request,
        SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_HEADER,
        SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_PARAM);
  }

  static Optional<String> failure(ServerHttpRequest request) {
    return headerOrParam(request,
        SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_HEADER,
        SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_PARAM);
  }

  private static Optional<String> headerOrParam(ServerHttpRequest request, String headerName,
      String paramName) {
    final var header = request.getHeaders().getFirst(headerName);
    if (StringUtils.hasText(header)) {
      return Optional.of(header);
    }
    return Optional.ofNullable(request.getQueryParams().getFirst(paramName))
        .filter(StringUtils::hasText);
  }
}
