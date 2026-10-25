package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.io.IOException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.util.ThrowableAnalyzer;
import com.c4_soft.springaddons.security.oidc.starter.OAuth2ClientRefusal;
import com.c4_soft.springaddons.security.oidc.starter.properties.InvalidPostLoginUriException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * <p>
 * The failure handler of the {@link OAuth2AuthorizationRequestRedirectFilter}, which receives the
 * exceptions of the authorization request resolver (wrapped in an {@link AuthenticationException}).
 * </p>
 * <ul>
 * <li>an {@link InvalidPostLoginUriException} in the cause chain (a post-login URI provided by the
 * user-agent does not match {@code post-login-allowed-uri-patterns}) is answered with {@code 400}
 * by the {@link OAuth2ClientRefusalWriter}. The resolver checks both post-login URIs before storing
 * anything, so the session is left untouched;</li>
 * <li>anything else gets Spring Security's default: logged (with the redirect filter's logger, so
 * that its level still applies), and answered with {@code 500}.</li>
 * </ul>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
public class AuthorizationRequestFailureHandler implements AuthenticationFailureHandler {
  static final String INVALID_CLIENT_REGISTRATION_ID_EXCEPTION =
      "org.springframework.security.oauth2.client.web.InvalidClientRegistrationIdException";

  private static final Log logger = LogFactory.getLog(OAuth2AuthorizationRequestRedirectFilter.class);

  private final ThrowableAnalyzer throwableAnalyzer = new ThrowableAnalyzer();
  private final OAuth2ClientRefusalWriter refusalWriter;

  public AuthorizationRequestFailureHandler(OAuth2ClientRefusalWriter refusalWriter) {
    this.refusalWriter = refusalWriter;
  }

  @Override
  public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException exception) throws IOException {
    final var invalidPostLoginUri = (InvalidPostLoginUriException) throwableAnalyzer
        .getFirstThrowableOfType(InvalidPostLoginUriException.class,
            throwableAnalyzer.determineCauseChain(exception));
    if (invalidPostLoginUri != null) {
      refusalWriter.write(request, response,
          OAuth2ClientRefusal.invalidPostLoginUri(invalidPostLoginUri));
      return;
    }

    // Same as OAuth2AuthorizationRequestRedirectFilter's default (a private method). Its
    // InvalidClientRegistrationIdException (an unknown registration ID) is package-private: matched
    // by name
    final var cause = exception.getCause();
    if (cause != null) {
      final var message = LogMessage.format("Authorization Request failed: %s", cause);
      if (INVALID_CLIENT_REGISTRATION_ID_EXCEPTION.equals(cause.getClass().getName())) {
        logger.warn(message, exception);
      } else {
        logger.error(message, exception);
      }
    }
    response.sendError(HttpStatus.INTERNAL_SERVER_ERROR.value(),
        HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase());
  }
}
