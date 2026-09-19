package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.io.IOException;
import java.util.Optional;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.util.StringUtils;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * A redirect strategy that might not actually redirect: the HTTP status is taken from
 * com.c4-soft.springaddons.oidc.client.oauth2-redirect-status property. User-agents will auto
 * redirect only if the status is in 3xx range. This gives single page and mobile applications a
 * chance to intercept the redirection and choose to follow the redirection (or not), with which
 * agent and potentially by clearing some headers.
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@RequiredArgsConstructor
public class SpringAddonsOauth2RedirectStrategy implements RedirectStrategy {

  @Getter
  private final HttpStatus defaultStatus;

  @Override
  public void sendRedirect(HttpServletRequest request, HttpServletResponse response,
      String location) throws IOException {
    final var status = toStatus(
        request.getHeader(SpringAddonsOidcClientProperties.RESPONSE_STATUS_HEADER))
            .or(() -> toStatus(
                request.getParameter(SpringAddonsOidcClientProperties.RESPONSE_STATUS_PARAM)))
            .orElse(defaultStatus);
    response.setStatus(status.value());

    response.setHeader(HttpHeaders.LOCATION, location);
  }

  /**
   * @param value a status code like "202" or a status name like "ACCEPTED"
   * @return the matching status, or empty if the value is blank or is not a known HTTP status (a
   *         user-agent can't turn a redirection into a 500 with a malformed header)
   */
  static Optional<HttpStatus> toStatus(String value) {
    if (!StringUtils.hasText(value)) {
      return Optional.empty();
    }
    try {
      return Optional.of(HttpStatus.valueOf(Integer.parseInt(value.trim())));
    } catch (NumberFormatException e) {
      try {
        return Optional.of(HttpStatus.valueOf(value.trim().toUpperCase()));
      } catch (IllegalArgumentException notAStatusName) {
        return Optional.empty();
      }
    } catch (IllegalArgumentException notAStatusCode) {
      return Optional.empty();
    }
  }
}
