package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import java.net.URI;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;

import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;

import reactor.core.publisher.Mono;

/**
 * An authentication failure handler reading post-login failure URI in session (set by the frontend with a header or request param when
 * initiating the authorization_code flow) and using a {@link SpringAddonsOauth2ServerRedirectStrategy}
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @see    SpringAddonsOidcClientProperties#POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE for constant used as session attribute keys
 * @see    SpringAddonsServerOAuth2AuthorizationRequestResolver which sets the post-login URI session attribute
 */
public class SpringAddonsOauth2ServerAuthenticationFailureHandler implements ServerAuthenticationFailureHandler {
	private final URI defaultRedirectUri;
	private final SpringAddonsOauth2ServerRedirectStrategy redirectStrategy;

	public SpringAddonsOauth2ServerAuthenticationFailureHandler(SpringAddonsOidcProperties addonsProperties) {
		this.defaultRedirectUri = addonsProperties.getClient().getLoginErrorRedirectPath().orElse(URI.create("/"));
		this.redirectStrategy = new SpringAddonsOauth2ServerRedirectStrategy(addonsProperties.getClient().getOauth2Redirections().getPostAuthorizationCode());
	}

	@Override
	public Mono<Void> onAuthenticationFailure(WebFilterExchange webFilterExchange, AuthenticationException exception) {
		return webFilterExchange.getExchange().getSession().flatMap(session -> {
			final var uri = UriComponentsBuilder.fromUri(
					session.getAttributeOrDefault(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE, defaultRedirectUri))
					.queryParam(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_CAUSE_ATTRIBUTE, HtmlUtils.htmlEscape(exception.getMessage()))
					.build().toUri();
			return redirectStrategy.sendRedirect(webFilterExchange.getExchange(), uri);
		});
	}
}
