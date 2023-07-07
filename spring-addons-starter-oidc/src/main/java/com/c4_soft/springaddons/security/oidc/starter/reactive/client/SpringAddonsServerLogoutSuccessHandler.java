package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import java.net.URI;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;

import com.c4_soft.springaddons.security.oidc.starter.LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oidc.starter.SpringAddonsOAuth2LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

/**
 * <p>
 * Provide with <a href= "https://openid.net/specs/openid-connect-rpinitiated-1_0.html">RP-Initiated Logout</a> for authorization-servers fully compliant with
 * OIDC standard as well as those "almost" implementing the spec. It is (auto)configured with {@link SpringAddonsOidcClientProperties}.
 * </p>
 * <p>
 * <b>This implementation is not multi-tenant ready</b>. It will terminate the user session on this application as well as on a single authorization-server (the
 * one which emitted the access-token with which the logout request is made).
 * </p>
 * <p>
 * This bean is auto-configured by {@link ReactiveSpringAddonsOidcClientBeans} as {@link ConditionalOnMissingBean &#64;ConditionalOnMissingBean} of type
 * {@link ServerLogoutSuccessHandler}. Usage:
 * </p>
 *
 * <pre>
 * SecurityFilterChain uiFilterChain(HttpSecurity http, ServerLogoutSuccessHandler logoutSuccessHandler) {
 * 	http.logout().logoutSuccessHandler(logoutSuccessHandler);
 * }
 * </pre>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @see    SpringAddonsOAuth2LogoutRequestUriBuilder
 * @see    SpringAddonsOidcClientProperties
 */
@Data
@RequiredArgsConstructor
public class SpringAddonsServerLogoutSuccessHandler implements ServerLogoutSuccessHandler {
	private final LogoutRequestUriBuilder uriBuilder;
	private final ReactiveClientRegistrationRepository clientRegistrationRepo;
	private final ServerRedirectStrategy redirectStrategy = new DefaultServerRedirectStrategy();

	@Override
	public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
		if (authentication instanceof OAuth2AuthenticationToken oauth) {
			return clientRegistrationRepo.findByRegistrationId(oauth.getAuthorizedClientRegistrationId())
					.map(client -> uriBuilder.getLogoutRequestUri(client, ((OidcUser) oauth.getPrincipal()).getIdToken().getTokenValue()))
					.flatMap(logoutUri -> {
						return this.redirectStrategy.sendRedirect(exchange.getExchange(), URI.create(logoutUri));
					});
		}
		return Mono.empty().then();
	}
}