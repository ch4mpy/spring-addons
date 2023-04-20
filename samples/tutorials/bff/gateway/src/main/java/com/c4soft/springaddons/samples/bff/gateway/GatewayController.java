package com.c4soft.springaddons.samples.bff.gateway;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;
import java.util.Optional;

import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;

import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;
import com.c4_soft.springaddons.security.oauth2.config.LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsOAuth2ClientProperties;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.NotEmpty;
import reactor.core.publisher.Mono;

@RestController
@Tag(name = "Gateway")
public class GatewayController {
	private final ReactiveClientRegistrationRepository clientRegistrationRepository;
	private final SpringAddonsOAuth2ClientProperties addonsClientProps;
	private final LogoutRequestUriBuilder logoutRequestUriBuilder;
	private final ServerSecurityContextRepository securityContextRepository = new WebSessionServerSecurityContextRepository();
	private final List<LoginOptionDto> loginOptions;

	public GatewayController(
			OAuth2ClientProperties clientProps,
			ReactiveClientRegistrationRepository clientRegistrationRepository,
			SpringAddonsOAuth2ClientProperties addonsClientProps,
			LogoutRequestUriBuilder logoutRequestUriBuilder) {
		this.addonsClientProps = addonsClientProps;
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.logoutRequestUriBuilder = logoutRequestUriBuilder;
		this.loginOptions = clientProps.getRegistration().entrySet().stream().filter(e -> "authorization_code".equals(e.getValue().getAuthorizationGrantType()))
				.map(e -> new LoginOptionDto(e.getValue().getProvider(), "%s/oauth2/authorization/%s".formatted(addonsClientProps.getClientUri(), e.getKey())))
				.toList();
	}

	@GetMapping(path = "/login-options", produces = "application/json")
	@Tag(name = "getLoginOptions")
	public Mono<List<LoginOptionDto>> getLoginOptions(Authentication auth) throws URISyntaxException {
		final boolean isAuthenticated = auth instanceof OAuth2AuthenticationToken;
		return Mono.just(isAuthenticated ? List.of() : this.loginOptions);
	}

	@GetMapping(path = "/me", produces = "application/json")
	@Tag(name = "getMe")
	@Operation(responses = { @ApiResponse(responseCode = "200") })
	public Mono<UserDto> getMe(Authentication auth) {
		if (auth instanceof OAuth2AuthenticationToken oauth && oauth.getPrincipal() instanceof OidcUser user) {
			final var claims = new OpenidClaimSet(user.getClaims());
			return Mono.just(
					new UserDto(
							claims.getSubject(),
							Optional.ofNullable(claims.getIssuer()).map(URL::toString).orElse(""),
							oauth.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList()));
		}
		return Mono.just(UserDto.ANONYMOUS);
	}

	@PutMapping(path = "/logout", produces = "application/json")
	@Tag(name = "logout")
	@Operation(responses = { @ApiResponse(responseCode = "204") })
	public Mono<ResponseEntity<Void>> logout(ServerWebExchange exchange, Authentication authentication) {
		final Mono<URI> uri;
		if (authentication instanceof OAuth2AuthenticationToken oauth && oauth.getPrincipal() instanceof OidcUser oidcUser) {
			uri = clientRegistrationRepository.findByRegistrationId(oauth.getAuthorizedClientRegistrationId()).map(clientRegistration -> {
				final var uriString = logoutRequestUriBuilder
						.getLogoutRequestUri(clientRegistration, oidcUser.getIdToken().getTokenValue(), addonsClientProps.getPostLogoutRedirectUri());
				return StringUtils.hasText(uriString) ? URI.create(uriString) : addonsClientProps.getPostLogoutRedirectUri();
			});
		} else {
			uri = Mono.just(addonsClientProps.getPostLogoutRedirectUri());
		}
		return uri.flatMap(logoutUri -> {
			return securityContextRepository.save(exchange, null).thenReturn(logoutUri);
		}).map(logoutUri -> {
			return ResponseEntity.noContent().location(logoutUri).build();
		});
	}

	static record UserDto(String subject, String issuer, List<String> roles) {
		static final UserDto ANONYMOUS = new UserDto("", "", List.of());
	}

	static record LoginOptionDto(@NotEmpty String label, @NotEmpty String loginUri) {
	}
}
