package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import java.net.URI;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;

import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * An authentication success handler reading post-login success URI in session (set by the frontend with a header or request param when
 * initiating the authorization_code flow) and using a {@link SpringAddonsOauth2ServerRedirectStrategy}
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @see    SpringAddonsOidcClientProperties#POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE for constant used as session attribute keys
 * @see    SpringAddonsServerOAuth2AuthorizationRequestResolver which sets the post-login URI session attribute
 */
@Slf4j
public class SpringAddonsOauth2ServerAuthenticationSuccessHandler implements ServerAuthenticationSuccessHandler {
	private final URI defaultRedirectUri;
	private final SpringAddonsOauth2ServerRedirectStrategy redirectStrategy;

	public SpringAddonsOauth2ServerAuthenticationSuccessHandler(SpringAddonsOidcProperties addonsProperties) {
		this.defaultRedirectUri = addonsProperties.getClient().getPostLoginRedirectUri().orElse(URI.create("/"));
		this.redirectStrategy = new SpringAddonsOauth2ServerRedirectStrategy(addonsProperties.getClient().getOauth2Redirections().getPostAuthorizationCode());
	}

	@Override
	public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
		return webFilterExchange.getExchange().getSession().flatMap(session -> {
			final var uri =
					session.getAttributeOrDefault(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE, defaultRedirectUri);

			log.debug("Login success. Status: {}, location: {}", redirectStrategy.getDefaultStatus(), uri.toString());
			return redirectStrategy.sendRedirect(webFilterExchange.getExchange(), uri);
		});
	}

}
