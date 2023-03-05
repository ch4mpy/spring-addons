package com.c4soft.springaddons.tutorials.ui;

import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Optional;
import java.util.stream.StreamSupport;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestClientException;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClient.RequestHeadersSpec;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;

import com.c4_soft.springaddons.security.oauth2.config.LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsOAuth2ClientProperties;
import com.c4soft.springaddons.tutorials.HttpSessionSupport;

import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Controller
@RequestMapping("/ui")
@RequiredArgsConstructor
@Slf4j
public class UiController {
	private final WebClient api;
	private final InMemoryClientRegistrationRepository clientRegistrationRepository;
	private final OAuth2AuthorizedClientService authorizedClientService;
	private final SpringAddonsOAuth2ClientProperties addonsClientProps;
	private final LogoutRequestUriBuilder logoutRequestUriBuilder;

	@GetMapping("/")
	public String getIndex(Model model, Authentication auth) {
		model.addAttribute("isAuthenticated", auth != null && auth.isAuthenticated());
		return "index";
	}

	@GetMapping("/greet")
	@PreAuthorize("isAuthenticated()")
	public String getGreeting(HttpServletRequest request, Model model) throws URISyntaxException {
		final var unauthorizedClients = new ArrayList<UnauthorizedClientDto>();
		final var authorizedClients = new ArrayList<AuthorizedClientDto>();
		StreamSupport.stream(this.clientRegistrationRepository.spliterator(), false)
				.filter(registration -> AuthorizationGrantType.AUTHORIZATION_CODE.equals(registration.getAuthorizationGrantType())).forEach(registration -> {
					final var subject = HttpSessionSupport.getUserSubject(registration.getRegistrationId());
					final var authorizedClient =
							subject == null ? null : authorizedClientService.loadAuthorizedClient(registration.getRegistrationId(), subject);
					if (authorizedClient == null) {
						unauthorizedClients.add(new UnauthorizedClientDto(registration.getClientName(), registration.getRegistrationId()));
					} else {
						try {
							final var greetApiUri = new URI(
									addonsClientProps.getClientUri().getScheme(),
									null,
									addonsClientProps.getClientUri().getHost(),
									addonsClientProps.getClientUri().getPort(),
									"/api/greet",
									null,
									null);
							final var response = authorize(api.get().uri(greetApiUri), registration.getRegistrationId())
									.exchangeToMono(r -> r.toEntity(String.class)).block();

							authorizedClients.add(
									new AuthorizedClientDto(
											registration.getClientName(),
											response.getStatusCode().is2xxSuccessful() ? response.getBody() : response.getStatusCode().toString(),
											"/ui/logout-idp?clientRegistrationId=%s".formatted(registration.getRegistrationId())));

						} catch (RestClientException | URISyntaxException e) {
							final var error = e.getMessage();
							authorizedClients.add(new AuthorizedClientDto(registration.getClientName(), error, registration.getRegistrationId()));

						}

					}
				});
		model.addAttribute("unauthorizedClients", unauthorizedClients);
		model.addAttribute("authorizedClients", authorizedClients);
		return "greet";
	}

	@GetMapping("/logout-idp")
	@PreAuthorize("isAuthenticated()")
	public RedirectView logout(
			@RequestParam("clientRegistrationId") String clientRegistrationId,
			@RequestParam(name = "redirectTo", required = false) Optional<String> redirectTo) {
		final var subject = HttpSessionSupport.getUserSubject(clientRegistrationId);
		final var idToken = HttpSessionSupport.getUserIdToken(clientRegistrationId);
		final var authorizedClient = authorizedClientService.loadAuthorizedClient(clientRegistrationId, subject);
		final var postLogoutUri = UriComponentsBuilder.fromUri(addonsClientProps.getClientUri()).path(redirectTo.orElse("/ui/greet"))
				.encode(StandardCharsets.UTF_8).build().toUriString();
		String logoutUri = logoutRequestUriBuilder.getLogoutRequestUri(authorizedClient, idToken, URI.create(postLogoutUri));

		log.info("Remove authorized client with ID {} for {}", clientRegistrationId, subject);
		this.authorizedClientService.removeAuthorizedClient(clientRegistrationId, subject);
		final var remainingIdentities = HttpSessionSupport.removeIdentity(clientRegistrationId);
		if (remainingIdentities.size() == 0) {
			HttpSessionSupport.invalidate();
		}

		log.info("Redirecting {} to {} for logout", subject, logoutUri);
		return new RedirectView(logoutUri);
	}

	@GetMapping("/bulk-logout-idps")
	@PreAuthorize("isAuthenticated()")
	public RedirectView bulkLogout() {
		final var identities = HttpSessionSupport.getIdentitiesByRegistrationId().entrySet().iterator();
		if (identities.hasNext()) {
			final var userId = identities.next();
			final var builder = UriComponentsBuilder.fromPath("/ui/logout-idp");
			builder.queryParam("clientRegistrationId", userId.getKey());
			builder.queryParam("redirectTo", "/ui/bulk-logout-idps");
			return new RedirectView(builder.encode(StandardCharsets.UTF_8).build().toUriString());

		}
		return new RedirectView("/");
	}

	private RequestHeadersSpec<?> authorize(RequestHeadersSpec<?> spec, String clientRegistrationId) {
		final String subject = HttpSessionSupport.getUserSubject(clientRegistrationId);
		final var authorizedClient = subject == null ? null : authorizedClientService.loadAuthorizedClient(clientRegistrationId, subject);
		return spec.attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient));
	}

	@Data
	@NoArgsConstructor
	@AllArgsConstructor
	public static class AuthorizedClientDto implements Serializable {
		private static final long serialVersionUID = -6623594577844506618L;

		private String label;
		private String message;
		private String logoutUri;
	}

	@Data
	@NoArgsConstructor
	@AllArgsConstructor
	public static class UnauthorizedClientDto {
		private String label;
		private String registrationId;
	}
}
