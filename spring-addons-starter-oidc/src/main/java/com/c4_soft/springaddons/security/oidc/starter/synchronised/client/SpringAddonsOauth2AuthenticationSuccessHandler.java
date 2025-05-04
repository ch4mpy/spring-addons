package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.io.IOException;
import java.util.Optional;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

/**
 * An authentication success handler reading post-login success URI in session (set by the frontend
 * with a header or request param when initiating the authorization_code flow) and using a
 * {@link SpringAddonsOauth2RedirectStrategy}
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @see SpringAddonsOidcClientProperties#POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE for
 *      constant used as session attribute keys
 * @see SpringAddonsOAuth2AuthorizationRequestResolver which sets the post-login URI session
 *      attribute
 */
@Slf4j
public class SpringAddonsOauth2AuthenticationSuccessHandler
    implements AuthenticationSuccessHandler {
  private final String redirectUri;
  private final SpringAddonsOauth2RedirectStrategy redirectStrategy;

  public SpringAddonsOauth2AuthenticationSuccessHandler(
      SpringAddonsOidcProperties addonsProperties) {
    this.redirectUri = addonsProperties.getClient().getPostLoginRedirectUri().toString();
    this.redirectStrategy = new SpringAddonsOauth2RedirectStrategy(
        addonsProperties.getClient().getOauth2Redirections().getPostAuthorizationCode());
  }

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException, ServletException {
    final var uri = Optional
        .ofNullable(request.getSession().getAttribute(
            SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE))
        .map(Object::toString).orElse(redirectUri);

    log.debug("Authentication success. Status: {}, location: {}",
        redirectStrategy.getDefaultStatus(), uri);

    redirectStrategy.sendRedirect(request, response, uri);
  }
}
