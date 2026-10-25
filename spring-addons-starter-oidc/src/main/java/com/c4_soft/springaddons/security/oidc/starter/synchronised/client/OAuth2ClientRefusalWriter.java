package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.io.IOException;
import com.c4_soft.springaddons.security.oidc.starter.OAuth2ClientRefusal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * <p>
 * Writes the response to a request the auto-configured client filter-chain refuses with a status:
 * {@code 401} when the client must be authorized again (see
 * {@link ClientAuthorizationExceptionFilter}), {@code 400} when a post-login URI is not allowed
 * (see {@link InvalidPostLoginUriFilter}).
 * </p>
 * <p>
 * The default, {@link SpringAddonsOAuth2ClientRefusalWriter}, writes the status alone. Expose a
 * bean of this type to write a body (an RFC 9457 problem for instance) or another status.
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@FunctionalInterface
public interface OAuth2ClientRefusalWriter {

  void write(HttpServletRequest request, HttpServletResponse response, OAuth2ClientRefusal refusal)
      throws IOException;
}
