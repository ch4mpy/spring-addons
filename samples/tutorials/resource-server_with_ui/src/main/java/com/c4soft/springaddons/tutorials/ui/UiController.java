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
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestClientException;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;

import com.c4_soft.springaddons.security.oidc.starter.LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.client.AuthorizedSessionRepository;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.client.OAuth2PrincipalSupport;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
	private final OAuth2AuthorizedClientRepository authorizedClientRepo;
	private final AuthorizedSessionRepository authorizedSessionRepo;
	private final SpringAddonsOidcProperties addonsClientProps;
	private final LogoutRequestUriBuilder logoutRequestUriBuilder;

	@GetMapping("/")
	public String getIndex(Model model, Authentication auth) {
		model.addAttribute("isAuthenticated", auth != null && auth.isAuthenticated());
		return "index";
	}

	@GetMapping("/greet")
	@PreAuthorize("isAuthenticated()")
	public String getGreeting(HttpServletRequest request, Authentication auth, Model model) throws URISyntaxException {
		final var unauthorizedClients = new ArrayList<UnauthorizedClientDto>();
		final var authorizedClients = new ArrayList<AuthorizedClientDto>();
		StreamSupport.stream(this.clientRegistrationRepository.spliterator(), false)
				.filter(registration -> AuthorizationGrantType.AUTHORIZATION_CODE.equals(registration.getAuthorizationGrantType())).forEach(registration -> {
					final var authorizedClient =
							auth == null ? null : authorizedClientRepo.loadAuthorizedClient(registration.getRegistrationId(), auth, request);
					if (authorizedClient == null) {
						unauthorizedClients.add(new UnauthorizedClientDto(registration.getClientName(), registration.getRegistrationId()));
					} else {
						try {
							final var greetApiUri = new URI(
									addonsClientProps.getClient().getClientUri().getScheme(),
									null,
									addonsClientProps.getClient().getClientUri().getHost(),
									addonsClientProps.getClient().getClientUri().getPort(),
									"/api/greet",
									null,
									null);
							final var response = api.get().uri(greetApiUri)
									.attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
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
			@RequestParam(name = "redirectTo", required = false) Optional<String> redirectTo,
			HttpServletRequest request,
			HttpServletResponse response) {
		final var postLogoutUri = UriComponentsBuilder.fromUri(addonsClientProps.getClient().getClientUri()).path(redirectTo.orElse("/ui/greet"))
				.encode(StandardCharsets.UTF_8).build().toUriString();
		final var authentication = OAuth2PrincipalSupport.getAuthentication(request.getSession(), clientRegistrationId).orElse(null);
		final var authorizedClient = authorizedClientRepo.loadAuthorizedClient(clientRegistrationId, authentication, request);
		final var idToken = authentication instanceof OidcUser oidcUser ? oidcUser.getIdToken().getTokenValue() : null;
		String logoutUri = logoutRequestUriBuilder.getLogoutRequestUri(authorizedClient.getClientRegistration(), idToken, URI.create(postLogoutUri));

		log.info("Remove authorized client with ID {} for {}", clientRegistrationId, authentication.getName());
		this.authorizedClientRepo.removeAuthorizedClient(clientRegistrationId, authentication, request, response);
		final var authorizedClientIds = authorizedSessionRepo.findAuthorizedClientIdsBySessionId(request.getSession().getId());
		if (authorizedClientIds.isEmpty()) {
			request.getSession().invalidate();
		}

		log.info("Redirecting {} to {} for logout", authentication.getName(), logoutUri);
		return new RedirectView(logoutUri);
	}

	@GetMapping("/bulk-logout-idps")
	@PreAuthorize("isAuthenticated()")
	public RedirectView bulkLogout(HttpServletRequest request) {
		final var authorizedClientIds = authorizedSessionRepo.findAuthorizedClientIdsBySessionId(request.getSession().getId()).iterator();
		if (authorizedClientIds.hasNext()) {
			final var id = authorizedClientIds.next();
			final var builder = UriComponentsBuilder.fromPath("/ui/logout-idp");
			builder.queryParam("clientRegistrationId", id.getClientRegistrationId());
			builder.queryParam("redirectTo", "/ui/bulk-logout-idps");
			return new RedirectView(builder.encode(StandardCharsets.UTF_8).build().toUriString());
		}
		return new RedirectView(addonsClientProps.getClient().getPostLogoutRedirectPath());
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
