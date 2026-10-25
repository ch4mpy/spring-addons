package com.c4_soft.springaddons.security.oidc.starter;

import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import com.c4_soft.springaddons.security.oidc.starter.properties.InvalidPostLoginUriException;

/**
 * <p>
 * A request the auto-configured OAuth2 client filter-chain refuses with a status instead of a
 * redirection, handed to the {@code OAuth2ClientRefusalWriter} (servlet) or
 * {@code ServerOAuth2ClientRefusalWriter} (reactive) bean which writes the response.
 * </p>
 * <ul>
 * <li>{@link Kind#AUTHORIZATION_REQUIRED}: a {@link ClientAuthorizationException} was thrown while
 * the request was processed (an access token relayed by a gateway, a {@code RestClient} or
 * {@code WebClient} with an authorized client manager...): there is no authorized client for the
 * registration, or the authorization server refused the refresh. The session has been logged out
 * and the status is {@code 401}.</li>
 * <li>{@link Kind#INVALID_POST_LOGIN_URI}: the request carries a post-login URI (header or request
 * parameter) which does not match {@code post-login-allowed-uri-patterns}. Nothing was stored in
 * session and the status is {@code 400}.</li>
 * </ul>
 *
 * @param kind which refusal happened
 * @param status the status the default writers answer with
 * @param cause the exception which caused the refusal
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
public record OAuth2ClientRefusal(Kind kind, HttpStatus status, RuntimeException cause) {

  public enum Kind {
    AUTHORIZATION_REQUIRED, INVALID_POST_LOGIN_URI
  }

  public static OAuth2ClientRefusal authorizationRequired(ClientAuthorizationException cause) {
    return new OAuth2ClientRefusal(Kind.AUTHORIZATION_REQUIRED, HttpStatus.UNAUTHORIZED, cause);
  }

  public static OAuth2ClientRefusal invalidPostLoginUri(InvalidPostLoginUriException cause) {
    return new OAuth2ClientRefusal(Kind.INVALID_POST_LOGIN_URI, HttpStatus.BAD_REQUEST, cause);
  }
}
