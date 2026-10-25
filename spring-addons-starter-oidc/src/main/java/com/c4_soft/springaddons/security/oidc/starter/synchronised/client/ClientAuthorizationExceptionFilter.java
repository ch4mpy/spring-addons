package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.io.IOException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.web.filter.OncePerRequestFilter;
import com.c4_soft.springaddons.security.oidc.starter.OAuth2ClientRefusal;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

/**
 * <p>
 * When a {@link ClientAuthorizationException} (of any subclass and with any error code) is thrown
 * down the filter-chain, logs the session out as {@code /logout} does
 * ({@link SecurityContextLogoutHandler}: session invalidated, security context cleared, an empty
 * context saved) and answers {@code 401} through the {@link OAuth2ClientRefusalWriter}: no
 * {@code Location} header, no authorization request resolved nor saved. The next request with the
 * stale session cookie is anonymous.
 * </p>
 * <p>
 * Such exceptions are thrown by {@code OAuth2AuthorizedClientManager#authorize()} when it runs
 * inside a request handler (Spring Cloud Gateway's {@code TokenRelay=} filter, a {@code RestClient}
 * with an OAuth2 interceptor...): a {@link ClientAuthorizationRequiredException} when there is no
 * authorized client for the registration, a plain {@link ClientAuthorizationException} when the
 * authorization server refuses the refresh ({@code invalid_grant}: SSO session or refresh token
 * expired, the authorized client has already been removed by the failure handler). Spring Security's
 * {@link OAuth2AuthorizationRequestRedirectFilter} answers the first with a redirection to the
 * authorization endpoint, which a single page or mobile application can't follow, and does not
 * handle the second (it is not an {@code AuthenticationException}, so it surfaces as a server
 * error). In both cases, the session keeps its {@code OAuth2AuthenticationToken}.
 * </p>
 * <p>
 * Inserted after the {@link OAuth2AuthorizationRequestRedirectFilter} (closer to the handler) when
 * {@code com.c4-soft.springaddons.oidc.client.client-authorization-required.enabled} is
 * {@code true}, so that the exception never reaches that filter. Mind that an exception thrown by a
 * handler goes through the {@code DispatcherServlet}'s {@code HandlerExceptionResolver}s first: a
 * resolver (or {@code @ControllerAdvice}) handling every exception would swallow it before this
 * filter sees it.
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Slf4j
public class ClientAuthorizationExceptionFilter extends OncePerRequestFilter {
  private final ThrowableAnalyzer throwableAnalyzer = new DefaultThrowableAnalyzer();
  private final LogoutHandler logoutHandler = new SecurityContextLogoutHandler();
  private final SecurityContextHolderStrategy securityContextHolderStrategy =
      SecurityContextHolder.getContextHolderStrategy();
  private final OAuth2ClientRefusalWriter refusalWriter;

  public ClientAuthorizationExceptionFilter(OAuth2ClientRefusalWriter refusalWriter) {
    this.refusalWriter = refusalWriter;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    try {
      filterChain.doFilter(request, response);
    } catch (IOException ex) {
      throw ex;
    } catch (Exception ex) {
      final var causeChain = throwableAnalyzer.determineCauseChain(ex);
      final var authorizationException = (ClientAuthorizationException) throwableAnalyzer
          .getFirstThrowableOfType(ClientAuthorizationException.class, causeChain);
      if (authorizationException == null) {
        if (ex instanceof ServletException servletException) {
          throw servletException;
        }
        if (ex instanceof RuntimeException runtimeException) {
          throw runtimeException;
        }
        throw new ServletException(ex);
      }
      log.debug(
          "Client must be authorized again for registration {} ({}) on {}: logging out and answering 401",
          authorizationException.getClientRegistrationId(),
          authorizationException.getError().getErrorCode(), request.getRequestURI());
      logoutHandler.logout(request, response,
          securityContextHolderStrategy.getContext().getAuthentication());
      refusalWriter.write(request, response,
          OAuth2ClientRefusal.authorizationRequired(authorizationException));
    }
  }

  /**
   * Same as the one in {@link OAuth2AuthorizationRequestRedirectFilter}: follows
   * {@link ServletException#getRootCause()} too.
   */
  private static final class DefaultThrowableAnalyzer extends ThrowableAnalyzer {
    @Override
    protected void initExtractorMap() {
      super.initExtractorMap();
      registerExtractor(ServletException.class, throwable -> {
        ThrowableAnalyzer.verifyThrowableHierarchy(throwable, ServletException.class);
        return ((ServletException) throwable).getRootCause();
      });
    }
  }
}
