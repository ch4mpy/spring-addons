package com.c4soft.springaddons.samples.bff.gateway;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.reactive.result.view.Rendering;
import org.springframework.web.server.WebSession;
import org.springframework.web.util.UriComponentsBuilder;

import com.c4_soft.springaddons.security.oauth2.config.LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsOAuth2ClientProperties;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

@Controller
@RequiredArgsConstructor
public class LoginController {
	private final OAuth2ClientProperties clientProps;
	private final ReactiveOAuth2AuthorizedClientService authorizedClientService;
	private final SpringAddonsOAuth2ClientProperties addonsClientProps;
	private final LogoutRequestUriBuilder logoutRequestUriBuilder;

	@GetMapping("/login")
	public Mono<Rendering> getLogin(Authentication auth) throws URISyntaxException {
		final boolean isAuthenticated = auth != null && auth.isAuthenticated();
		final List<LoginOptionDto> loginOptions = isAuthenticated
				? List.of()
				: clientProps.getRegistration().entrySet().stream().filter(e -> "authorization_code".equals(e.getValue().getAuthorizationGrantType()))
						.map(e -> new LoginOptionDto(e.getValue().getProvider(), e.getKey())).toList();

		if (isAuthenticated) {
			return Mono.just(Rendering.redirectTo("/ui").build());
		}
		return Mono.just(Rendering.view("login").modelAttribute("isAuthenticated", isAuthenticated).modelAttribute("loginOptions", loginOptions).build());
	}

	@PostMapping("/logout-uri")
	@ResponseBody
	public Mono<LogoutDto> logout(OAuth2AuthenticationToken auth, WebSession session) {
		final var user = (OidcUser) auth.getPrincipal();
		return authorizedClientService.loadAuthorizedClient(auth.getAuthorizedClientRegistrationId(), user.getSubject()).map(authorizedClient -> {
			final var postLogoutUri =
					UriComponentsBuilder.fromUri(addonsClientProps.getClientUri()).path("/ui").encode(StandardCharsets.UTF_8).build().toUriString();
			String logoutUri = logoutRequestUriBuilder.getLogoutRequestUri(authorizedClient, user.getIdToken().getTokenValue(), URI.create(postLogoutUri));

			this.authorizedClientService.removeAuthorizedClient(auth.getAuthorizedClientRegistrationId(), user.getSubject());
			session.invalidate();
			return new LogoutDto(logoutUri);
		});
	}

	@Data
	@AllArgsConstructor
	static class LoginOptionDto {
		private final String label;
		private final String provider;
	}

	@Data
	@AllArgsConstructor
	static class LogoutDto {
		private final String uri;
	}
}
