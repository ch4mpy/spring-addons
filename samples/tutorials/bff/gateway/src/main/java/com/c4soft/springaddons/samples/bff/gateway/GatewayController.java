package com.c4soft.springaddons.samples.bff.gateway;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;

import com.c4_soft.springaddons.security.oidc.starter.LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;

import io.micrometer.observation.annotation.Observed;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.NotEmpty;
import reactor.core.publisher.Mono;

@RestController
@Tag(name = "Gateway")
@Observed(name = "GatewayController")
public class GatewayController {
	private final ReactiveClientRegistrationRepository clientRegistrationRepository;
	private final SpringAddonsOidcClientProperties addonsClientProperties;
	private final LogoutRequestUriBuilder logoutRequestUriBuilder;
	private final ServerLogoutHandler logoutHandler;
	private final List<LoginOptionDto> loginOptions;

	public GatewayController(
			OAuth2ClientProperties clientProps,
			ReactiveClientRegistrationRepository clientRegistrationRepository,
			SpringAddonsOidcProperties addonsProperties,
			LogoutRequestUriBuilder logoutRequestUriBuilder,
			ServerLogoutHandler logoutHandler) {
		this.addonsClientProperties = addonsProperties.getClient();
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.logoutRequestUriBuilder = logoutRequestUriBuilder;
		this.loginOptions = clientProps.getRegistration().entrySet().stream().filter(e -> "authorization_code".equals(e.getValue().getAuthorizationGrantType()))
				.map(
						e -> new LoginOptionDto(
								e.getValue().getProvider(),
								"%s/oauth2/authorization/%s".formatted(addonsClientProperties.getClientUri(), e.getKey())))
				.toList();
		this.logoutHandler = logoutHandler;
	}

	@GetMapping(path = "/login-options", produces = "application/json")
	@Tag(name = "getLoginOptions")
	public Mono<List<LoginOptionDto>> getLoginOptions(Authentication auth) throws URISyntaxException {
		final boolean isAuthenticated = auth instanceof OAuth2AuthenticationToken;
		return Mono.just(isAuthenticated ? List.of() : this.loginOptions);
	}

	@PutMapping(path = "/logout", produces = "application/json")
	@Tag(name = "logout")
	@Operation(responses = { @ApiResponse(responseCode = "204") })
	public Mono<ResponseEntity<Void>> logout(ServerWebExchange exchange, Authentication authentication) {
		final Mono<URI> uri;
		if (authentication instanceof OAuth2AuthenticationToken oauth && oauth.getPrincipal() instanceof OidcUser oidcUser) {
			uri = clientRegistrationRepository.findByRegistrationId(oauth.getAuthorizedClientRegistrationId()).map(clientRegistration -> {
				final var uriString = logoutRequestUriBuilder
						.getLogoutRequestUri(clientRegistration, oidcUser.getIdToken().getTokenValue(), addonsClientProperties.getPostLogoutRedirectUri());
				return StringUtils.hasText(uriString) ? URI.create(uriString) : addonsClientProperties.getPostLogoutRedirectUri();
			});
		} else {
			uri = Mono.just(addonsClientProperties.getPostLogoutRedirectUri());
		}
		return uri.flatMap(logoutUri -> {
			return logoutHandler.logout(new WebFilterExchange(exchange, ex -> Mono.empty().then()), authentication).thenReturn(logoutUri);
		}).map(logoutUri -> {
			return ResponseEntity.noContent().location(logoutUri).build();
		});
	}

	static record LoginOptionDto(@NotEmpty String label, @NotEmpty String loginUri) {
	}
}
