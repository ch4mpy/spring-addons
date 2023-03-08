package com.c4soft.springaddons.samples.bff.gateway;

import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.server.WebSession;
import org.springframework.web.util.UriComponentsBuilder;

import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;
import com.c4_soft.springaddons.security.oauth2.config.LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsOAuth2ClientProperties;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Data;
import reactor.core.publisher.Mono;

@Controller
@Tag(name = "Gateway")
public class GatewayApiController {
	private final ReactiveOAuth2AuthorizedClientService authorizedClientService;
	private final SpringAddonsOAuth2ClientProperties addonsClientProps;
	private final LogoutRequestUriBuilder logoutRequestUriBuilder;
	private final List<LoginOptionDto> loginOptions;

	public GatewayApiController(
			OAuth2ClientProperties clientProps,
			ReactiveOAuth2AuthorizedClientService authorizedClientService,
			SpringAddonsOAuth2ClientProperties addonsClientProps,
			LogoutRequestUriBuilder logoutRequestUriBuilder) {
		this.authorizedClientService = authorizedClientService;
		this.addonsClientProps = addonsClientProps;
		this.logoutRequestUriBuilder = logoutRequestUriBuilder;
		this.loginOptions = clientProps.getRegistration().entrySet().stream().filter(e -> "authorization_code".equals(e.getValue().getAuthorizationGrantType()))
				.map(e -> new LoginOptionDto(e.getValue().getProvider(), "%s/oauth2/authorization/%s".formatted(addonsClientProps.getClientUri(), e.getKey())))
				.toList();
	}

	@GetMapping(path = "/login-options", produces = "application/json")
	@ResponseBody
	@Tag(name = "getLoginOptions")
	public Mono<List<LoginOptionDto>> getLoginOptions(Authentication auth) throws URISyntaxException {
		final boolean isAuthenticated = auth instanceof OAuth2AuthenticationToken;
		return Mono.just(isAuthenticated ? List.of() : this.loginOptions);
	}

	@GetMapping(path = "/me", produces = "application/json")
	@ResponseBody
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

	@PutMapping(path = "/logout")
	@Tag(name = "logout")
	@ResponseBody
	@Operation(parameters = {}, responses = { @ApiResponse(responseCode = "202"), @ApiResponse(responseCode = "401") })
	public Mono<ResponseEntity<Void>> logout(@Parameter(hidden = true) OAuth2AuthenticationToken auth, @Parameter(hidden = true) WebSession session) {
		final var user = (OidcUser) auth.getPrincipal();
		return authorizedClientService.loadAuthorizedClient(auth.getAuthorizedClientRegistrationId(), user.getSubject()).map(authorizedClient -> {
			final var postLogoutUri =
					UriComponentsBuilder.fromUri(addonsClientProps.getClientUri()).path("/ui").encode(StandardCharsets.UTF_8).build().toUriString();
			String logoutUri = logoutRequestUriBuilder.getLogoutRequestUri(authorizedClient, user.getIdToken().getTokenValue(), URI.create(postLogoutUri));

			this.authorizedClientService.removeAuthorizedClient(auth.getAuthorizedClientRegistrationId(), user.getSubject());
			session.invalidate();
			return ResponseEntity.accepted().location(URI.create(logoutUri)).build();
		});
	}

	@Data
	@AllArgsConstructor
	static class UserDto implements Serializable {
		private static final long serialVersionUID = 7279086703249177904L;
		static final UserDto ANONYMOUS = new UserDto("", "", List.of());

		@NotEmpty
		private final String subject;

		private final String issuer;

		private final List<String> roles;
	}

	@Data
	@AllArgsConstructor
	static class LoginOptionDto implements Serializable {
		private static final long serialVersionUID = -60479618490275339L;

		@NotEmpty
		private final String label;

		@NotEmpty
		private final String loginUri;
	}
}
