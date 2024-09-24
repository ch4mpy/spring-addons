package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.io.IOException;
import java.net.URI;
import java.util.Optional;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;

import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

/**
 * An authentication failure handler reading post-login failure URI in session (set by the frontend with a header or request param when
 * initiating the authorization_code flow) and using a {@link SpringAddonsOauth2RedirectStrategy}
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @see    SpringAddonsOidcClientProperties#POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE for constant used as session attribute keys
 * @see    SpringAddonsOAuth2AuthorizationRequestResolver which sets the post-login URI session attribute
 */
@Slf4j
public class SpringAddonsOauth2AuthenticationFailureHandler implements AuthenticationFailureHandler {
	private final String redirectUri;
	private final HttpStatus postAuthorizationFailureStatus;

	public SpringAddonsOauth2AuthenticationFailureHandler(SpringAddonsOidcProperties addonsProperties) {
		this.redirectUri = addonsProperties.getClient().getLoginErrorRedirectPath().map(URI::toString).orElse("/");
		this.postAuthorizationFailureStatus = addonsProperties.getClient().getOauth2Redirections().getPostAuthorizationFailure();
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
			throws IOException,
			ServletException {
		final var location = UriComponentsBuilder.fromUriString(
				Optional.ofNullable(request.getSession().getAttribute(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE))
						.map(Object::toString).orElse(redirectUri))
				.queryParam(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_CAUSE_ATTRIBUTE, HtmlUtils.htmlEscape(exception.getMessage())).build()
				.toUri().toString();

		log.debug("Authentication failure. Status: {}, location: {}, message: {}", postAuthorizationFailureStatus.value(), location, exception.getMessage());

		response.setStatus(postAuthorizationFailureStatus.value());
		response.setHeader(HttpHeaders.LOCATION, location);
		response.setHeader(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_CAUSE_ATTRIBUTE, exception.getMessage());

		if (postAuthorizationFailureStatus.is4xxClientError() || postAuthorizationFailureStatus.is5xxServerError()) {
			response.getOutputStream().write(exception.getMessage().getBytes());
		}

		response.flushBuffer();
	}
}
