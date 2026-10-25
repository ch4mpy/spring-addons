package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.io.IOException;
import java.util.List;
import java.util.regex.Pattern;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.web.filter.OncePerRequestFilter;
import com.c4_soft.springaddons.security.oidc.starter.OAuth2ClientRefusal;
import com.c4_soft.springaddons.security.oidc.starter.properties.InvalidRedirectionUriException;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * <p>
 * Answers {@code 400} (through the {@link OAuth2ClientRefusalWriter}) to requests carrying a
 * post-login success or failure URI (header or request parameter) which does not match
 * {@code com.c4-soft.springaddons.oidc.client.post-login-allowed-uri-patterns}: nothing is stored in
 * session, no session is opened, no authorization request is resolved and the authentication
 * failure handler is not called.
 * </p>
 * <p>
 * Inserted before the {@link OAuth2AuthorizationRequestRedirectFilter}: that filter calls the
 * authorization request resolver on every request and hands the {@link InvalidRedirectionUriException}
 * the resolver throws to its own failure handler, as if the authorization request had failed.
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
public class InvalidPostLoginUriFilter extends OncePerRequestFilter {
  private final List<Pattern> postLoginAllowedUriPatterns;
  private final OAuth2ClientRefusalWriter refusalWriter;

  public InvalidPostLoginUriFilter(SpringAddonsOidcClientProperties clientProperties,
      OAuth2ClientRefusalWriter refusalWriter) {
    this.postLoginAllowedUriPatterns = clientProperties.getPostLoginAllowedUriPatterns();
    this.refusalWriter = refusalWriter;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    for (final var candidate : List.of(PostLoginUris.success(request),
        PostLoginUris.failure(request))) {
      if (candidate.isPresent() && !SpringAddonsOidcClientProperties
          .isAllowedRedirectionUri(candidate.get(), postLoginAllowedUriPatterns)) {
        refusalWriter.write(request, response, OAuth2ClientRefusal
            .invalidPostLoginUri(new InvalidRedirectionUriException(candidate.get())));
        return;
      }
    }
    filterChain.doFilter(request, response);
  }
}
