package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.io.IOException;
import java.net.URI;
import java.util.Optional;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;

import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * An authentication failure handler reading post-login failure URI in session (set by the frontend with a header or request param when
 * initiating the authorization_code flow) and using a {@link SpringAddonsOauth2RedirectStrategy}
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @see    SpringAddonsOidcClientProperties#POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE for constant used as session attribute keys
 * @see    SpringAddonsOAuth2AuthorizationRequestResolver which sets the post-login URI session attribute
 */
public class SpringAddonsOauth2AuthenticationFailureHandler implements AuthenticationFailureHandler {
	private final String redirectUri;
	private final SpringAddonsOauth2RedirectStrategy redirectStrategy;

	public SpringAddonsOauth2AuthenticationFailureHandler(SpringAddonsOidcProperties addonsProperties) {
		this.redirectUri = addonsProperties.getClient().getLoginErrorRedirectPath().map(URI::toString).orElse("/");
		this.redirectStrategy = new SpringAddonsOauth2RedirectStrategy(addonsProperties.getClient().getOauth2Redirections().getPostAuthorizationCode());
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
			throws IOException,
			ServletException {
		final var uri = UriComponentsBuilder.fromUriString(
				Optional.ofNullable(request.getSession().getAttribute(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE))
						.map(Object::toString).orElse(redirectUri))
				.queryParam(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_CAUSE_ATTRIBUTE, HtmlUtils.htmlEscape(exception.getMessage())).build()
				.toUri();
		redirectStrategy.sendRedirect(request, response, uri.toString());
	}
}
