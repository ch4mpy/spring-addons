package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.io.IOException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
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
 * When a {@link ClientAuthorizationException} (of any subclass and with any error code) for an
 * {@code authorization_code} registration is thrown down the filter-chain, logs the session out
 * ({@link SecurityContextLogoutHandler}: session invalidated, security context cleared, an empty
 * context saved) and answers {@code 401} through the {@link OAuth2ClientRefusalWriter}: no
 * {@code Location} header, no authorization request resolved nor saved.
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
 * When the user is logged in with {@code oauth2Login} and the exception (of either subclass) is for
 * another {@code authorization_code} registration than the one they logged in with (one needing
 * its own consent, for instance), the session is kept and a
 * {@link ClientAuthorizationRequiredException} for that registration is thrown instead, for the
 * {@link OAuth2AuthorizationRequestRedirectFilter} to initiate its authorization (incremental
 * authorization).
 * </p>
 * <p>
 * Rethrown untouched: exceptions for registrations with another grant type
 * ({@code client_credentials} for instance), which logging the user in again would not fix, and
 * exceptions thrown once the response is committed, which can't be answered with a status any
 * more.
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
  private SecurityContextHolderStrategy securityContextHolderStrategy =
      SecurityContextHolder.getContextHolderStrategy();
  private final SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
  private final ClientRegistrationRepository clientRegistrationRepository;
  private final OAuth2ClientRefusalWriter refusalWriter;

  public ClientAuthorizationExceptionFilter(
      ClientRegistrationRepository clientRegistrationRepository,
      OAuth2ClientRefusalWriter refusalWriter) {
    this.clientRegistrationRepository = clientRegistrationRepository;
    this.refusalWriter = refusalWriter;
    // the default repositories of a security filter-chain
    this.logoutHandler.setSecurityContextRepository(new DelegatingSecurityContextRepository(
        new RequestAttributeSecurityContextRepository(),
        new HttpSessionSecurityContextRepository()));
    this.logoutHandler.setSecurityContextHolderStrategy(securityContextHolderStrategy);
  }

  /**
   * @param securityContextHolderStrategy the strategy of the filter-chain, when the application
   *        exposes one (the global {@link SecurityContextHolder} one by default)
   */
  public void setSecurityContextHolderStrategy(
      SecurityContextHolderStrategy securityContextHolderStrategy) {
    this.securityContextHolderStrategy = securityContextHolderStrategy;
    this.logoutHandler.setSecurityContextHolderStrategy(securityContextHolderStrategy);
  }

  /**
   * An exception completing an async handler result (a {@code WebClient} call returned as a
   * {@code Mono}, a {@code Callable}...) is rethrown during the {@code ASYNC} dispatch.
   */
  @Override
  protected boolean shouldNotFilterAsyncDispatch() {
    return false;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    try {
      filterChain.doFilter(request, response);
    } catch (IOException ex) {
      throw ex;
    } catch (Exception ex) {
      final var authorizationException = (ClientAuthorizationException) throwableAnalyzer
          .getFirstThrowableOfType(ClientAuthorizationException.class,
              throwableAnalyzer.determineCauseChain(ex));
      if (authorizationException == null || response.isCommitted()
          || !isAuthorizationCode(authorizationException.getClientRegistrationId())) {
        rethrow(ex);
        return;
      }
      final var registrationId = authorizationException.getClientRegistrationId();
      if (isLoggedInWithAnotherRegistration(registrationId)) {
        log.debug(
            "Client must be authorized for registration {} ({}) on {}: incremental authorization",
            registrationId, authorizationException.getError().getErrorCode(),
            request.getRequestURI());
        throw new ClientAuthorizationRequiredException(registrationId);
      }
      log.debug(
          "Client must be authorized again for registration {} ({}) on {}: logging out and answering 401",
          authorizationException.getClientRegistrationId(),
          authorizationException.getError().getErrorCode(), request.getRequestURI());
      logout(request, response);
      refusalWriter.write(request, response,
          OAuth2ClientRefusal.authorizationRequired(authorizationException));
    }
  }

  private boolean isAuthorizationCode(String registrationId) {
    final var registration = clientRegistrationRepository.findByRegistrationId(registrationId);
    return registration != null && AuthorizationGrantType.AUTHORIZATION_CODE
        .equals(registration.getAuthorizationGrantType());
  }

  private boolean isLoggedInWithAnotherRegistration(String registrationId) {
    return securityContextHolderStrategy.getContext()
        .getAuthentication() instanceof OAuth2AuthenticationToken login
        && !registrationId.equals(login.getAuthorizedClientRegistrationId());
  }

  private void logout(HttpServletRequest request, HttpServletResponse response) {
    try {
      logoutHandler.logout(request, response,
          securityContextHolderStrategy.getContext().getAuthentication());
    } catch (IllegalStateException e) {
      // a concurrent request (which got the same failed refresh) already invalidated the session
      log.debug("Session already invalidated: {}", e.getMessage());
      securityContextHolderStrategy.clearContext();
    }
  }

  private static void rethrow(Exception ex) throws ServletException {
    if (ex instanceof ServletException servletException) {
      throw servletException;
    }
    if (ex instanceof RuntimeException runtimeException) {
      throw runtimeException;
    }
    throw new ServletException(ex);
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
