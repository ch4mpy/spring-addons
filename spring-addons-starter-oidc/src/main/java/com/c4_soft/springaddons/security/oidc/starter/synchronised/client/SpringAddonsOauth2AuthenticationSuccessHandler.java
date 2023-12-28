package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.io.IOException;
import java.net.URI;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * An authentication success handler reading post-login success URI in session (set by the frontend with a header or request param when initiating the
 * authorization_code flow) and using a {@link SpringAddonsOauth2RedirectStrategy}
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @see SpringAddonsOidcClientProperties#POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE for constant used as session attribute keys
 * @see SpringAddonsOAuth2AuthorizationRequestResolver which sets the post-login URI session attribute
 */
public class SpringAddonsOauth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private final String redirectUri;
    private final SpringAddonsOauth2RedirectStrategy redirectStrategy;

    public SpringAddonsOauth2AuthenticationSuccessHandler(SpringAddonsOidcProperties addonsProperties) {
        this.redirectUri = addonsProperties.getClient().getPostLoginRedirectUri().map(URI::toString).orElse("/");
        this.redirectStrategy = new SpringAddonsOauth2RedirectStrategy(addonsProperties.getClient().getOauth2Redirections().getPostAuthorizationCode());
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException,
                ServletException {
        redirectStrategy.sendRedirect(request, response, redirectUri);

    }
}
