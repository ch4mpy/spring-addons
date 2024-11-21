package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import java.net.URI;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;

import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * An authentication failure handler reading post-login failure URI in session (set by the frontend with a header or request param when
 * initiating the authorization_code flow) and using a {@link SpringAddonsOauth2ServerRedirectStrategy}
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @see    SpringAddonsOidcClientProperties#POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE for constant used as session attribute keys
 * @see    SpringAddonsServerOAuth2AuthorizationRequestResolver which sets the post-login URI session attribute
 */
@Slf4j
public class SpringAddonsOauth2ServerAuthenticationFailureHandler implements ServerAuthenticationFailureHandler {
	private final URI defaultRedirectUri;
	private final HttpStatus postAuthorizationFailureStatus;

	public SpringAddonsOauth2ServerAuthenticationFailureHandler(SpringAddonsOidcProperties addonsProperties) {
		this.defaultRedirectUri = addonsProperties.getClient().getLoginErrorRedirectPath().orElse(URI.create("/"));
		this.postAuthorizationFailureStatus = addonsProperties.getClient().getOauth2Redirections().getPostAuthorizationFailure();
	}

	@Override
	public Mono<Void> onAuthenticationFailure(WebFilterExchange webFilterExchange, AuthenticationException exception) {
		return webFilterExchange.getExchange().getSession().flatMap(session -> {
			final var location = UriComponentsBuilder.fromUri(
					session.getAttributeOrDefault(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE, defaultRedirectUri))
					.queryParam(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_CAUSE_ATTRIBUTE, HtmlUtils.htmlEscape(exception.getMessage()))
					.build().toUri().toString();

			final var response = webFilterExchange.getExchange().getResponse();
			response.setStatusCode(postAuthorizationFailureStatus);
			response.getHeaders().add(HttpHeaders.LOCATION, location);
			response.getHeaders().add(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_CAUSE_ATTRIBUTE, exception.getMessage());

			log.debug("Login failure. Status: {}, location: {}, message: {}", postAuthorizationFailureStatus, location, exception.getMessage());

			if (postAuthorizationFailureStatus.is4xxClientError() || postAuthorizationFailureStatus.is5xxServerError()) {
				final var buffer = response.bufferFactory().wrap(exception.getMessage().getBytes());
				return response.writeWith(Flux.just(buffer));
			}
			return response.setComplete();
		});
	}
}
