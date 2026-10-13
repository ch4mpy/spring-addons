package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.io.IOException;
import java.util.List;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

/**
 * <p>
 * To be inserted before the {@link SessionManagementFilter}: when a request matching one of the
 * {@code invalid-session.pass-through-patterns} holds an invalid (expired) session ID, a new
 * session is created and the request proceeds as if it had no session cookie. The
 * {@link SessionManagementFilter} would otherwise hand it to the {@link InvalidSessionStrategy},
 * which answers without calling the rest of the filter chain.
 * </p>
 * <p>
 * Inserted when {@code com.c4-soft.springaddons.oidc.client.invalid-session.pass-through-patterns}
 * is not empty.
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Slf4j
public class InvalidSessionPassThroughFilter extends OncePerRequestFilter {
  private final RequestMatcher passThroughMatcher;

  public InvalidSessionPassThroughFilter(List<String> passThroughPatterns) {
    this.passThroughMatcher = new OrRequestMatcher(
        passThroughPatterns.stream().map(PathPatternRequestMatcher::pathPattern)
            .map(RequestMatcher.class::cast).toList());
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    if (request.getRequestedSessionId() == null || request.isRequestedSessionIdValid()
        || !passThroughMatcher.matches(request)) {
      filterChain.doFilter(request, response);
      return;
    }

    // Replaces the invalid session cookie so that the user-agent does not present it again
    request.getSession();

    log.debug("Invalid session on pass-through route {}. Proceeding with a new session",
        request.getRequestURI());
    filterChain.doFilter(new WithoutRequestedSessionIdRequest(request), response);
  }

  /**
   * Hides the invalid requested session ID from the downstream filters (and from the
   * {@link SessionManagementFilter} in particular).
   */
  static class WithoutRequestedSessionIdRequest extends HttpServletRequestWrapper {
    WithoutRequestedSessionIdRequest(HttpServletRequest request) {
      super(request);
    }

    @Override
    public String getRequestedSessionId() {
      return null;
    }

    @Override
    public boolean isRequestedSessionIdValid() {
      return false;
    }

    @Override
    public boolean isRequestedSessionIdFromCookie() {
      return false;
    }

    @Override
    public boolean isRequestedSessionIdFromURL() {
      return false;
    }
  }
}
