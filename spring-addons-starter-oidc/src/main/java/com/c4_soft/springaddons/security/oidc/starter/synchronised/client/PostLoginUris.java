package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.util.Optional;
import org.springframework.util.StringUtils;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import jakarta.servlet.http.HttpServletRequest;

/**
 * The post-login URIs a request carries, as a header or, failing that, as a request parameter (the
 * header wins). Used by {@link SpringAddonsOAuth2AuthorizationRequestResolver}, which stores them
 * in session.
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
final class PostLoginUris {

  private PostLoginUris() {}

  static Optional<String> success(HttpServletRequest request) {
    return headerOrParam(request,
        SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_HEADER,
        SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_PARAM);
  }

  static Optional<String> failure(HttpServletRequest request) {
    return headerOrParam(request,
        SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_HEADER,
        SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_PARAM);
  }

  private static Optional<String> headerOrParam(HttpServletRequest request, String headerName,
      String paramName) {
    final var header = request.getHeader(headerName);
    if (StringUtils.hasText(header)) {
      return Optional.of(header);
    }
    final var params = request.getParameterValues(paramName);
    if (params == null || params.length < 1 || !StringUtils.hasText(params[0])) {
      return Optional.empty();
    }
    return Optional.of(params[0]);
  }
}
