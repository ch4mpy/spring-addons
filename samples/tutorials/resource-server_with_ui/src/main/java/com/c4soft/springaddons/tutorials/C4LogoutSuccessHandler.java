package com.c4soft.springaddons.tutorials;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.web.util.UriComponentsBuilder;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;

@Data
@EqualsAndHashCode(callSuper = true)
@Log4j2
public class C4LogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {

	private final ClientRegistrationRepository clientRegistrationRepository;
	private final OidcClientInitiatedLogoutSuccessHandler oidcHandler;
	private final String postLogoutRedirectUri;

	public C4LogoutSuccessHandler(ClientRegistrationRepository clientRegistrationRepository, String postLogoutRedirectUri) {
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.postLogoutRedirectUri = postLogoutRedirectUri;
		this.oidcHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
		oidcHandler.setPostLogoutRedirectUri(postLogoutRedirectUri);
	}

	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
		String registrationId = ((OAuth2AuthenticationToken) authentication).getAuthorizedClientRegistrationId();
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);

		try {
			if (authentication instanceof OAuth2AuthenticationToken oauth2auth && oauth2auth.getPrincipal() instanceof OidcUser oidcUser) {
				final var issuer = new URI(clientRegistration.getProviderDetails().getConfigurationMetadata().get("issuer").toString());
				if (!issuer.getHost().endsWith(".auth0.com") && !issuer.getHost().startsWith("cognito-idp")) {
					oidcHandler.onLogoutSuccess(request, response, authentication);
				}
			}
		} catch (URISyntaxException e) {
			log.error("Missconfigured issuer: %s".formatted(clientRegistration.getProviderDetails().getConfigurationMetadata().get("issuer")));
			throw new RuntimeException(e);
		}
		super.onLogoutSuccess(request, response, authentication);
	}

	@Override
	protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		String registrationId = ((OAuth2AuthenticationToken) authentication).getAuthorizedClientRegistrationId();
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
		try {
			if (authentication instanceof OAuth2AuthenticationToken oauth2auth && oauth2auth.getPrincipal() instanceof OidcUser oidcUser) {
				final var issuer = new URI(clientRegistration.getProviderDetails().getConfigurationMetadata().get("issuer").toString());
				if (issuer.getHost().endsWith(".auth0.com")) {
					return new OAuth2LogoutSuccessHandler(
							clientRegistration.getClientId(),
							"https://dev-ch4mpy.eu.auth0.com/v2/logout",
							"returnTo",
							postLogoutRedirectUri).determineTargetUrl(request, response, authentication);
				}
				if (issuer.getHost().startsWith("cognito-idp")) {
					return new OAuth2LogoutSuccessHandler(
							clientRegistration.getClientId(),
							"https://spring-addons.auth.us-west-2.amazoncognito.com/logout",
							"logout_uri",
							postLogoutRedirectUri).determineTargetUrl(request, response, authentication);
				}
			}
		} catch (URISyntaxException e) {
			log.error("Missconfigured issuer: %s".formatted(clientRegistration.getProviderDetails().getConfigurationMetadata().get("issuer")));
			throw new RuntimeException(e);
		}
		return null;

	}

	@Data
	@RequiredArgsConstructor
	@EqualsAndHashCode(callSuper = true)
	public static class OAuth2LogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {

		private final String clientId;
		private final String logoutUrl;
		private final String postLogoutParamName;
		private final String postLogoutRedirectUri;

		@Override
		protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
			return UriComponentsBuilder
					.fromUri(URI.create(logoutUrl))
					.queryParam("client_id", clientId)
					.queryParam(postLogoutParamName, postLogoutRedirectUri)
					.encode(StandardCharsets.UTF_8)
					.build()
					.toUriString();
		}
	}
}
