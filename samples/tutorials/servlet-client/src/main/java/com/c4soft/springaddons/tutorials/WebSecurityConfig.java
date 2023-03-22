package com.c4soft.springaddons.tutorials;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@EnableReactiveMethodSecurity
public class WebSecurityConfig {

	@Bean
	SecurityFilterChain
			clientSecurityFilterChain(HttpSecurity http, InMemoryClientRegistrationRepository clientRegistrationRepository, LogoutProperties logoutProperties)
					throws Exception {
		http.oauth2Login();
		http.logout(logout -> {
			logout.logoutSuccessHandler(new DelegatingOidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository, logoutProperties, "{baseUrl}"));
		});
		http.authorizeHttpRequests(ex -> ex.requestMatchers("/login/**", "/oauth2/**").permitAll().anyRequest().authenticated());
		return http.build();
	}

	@Data
	@Configuration
	@ConfigurationProperties(prefix = "logout")
	static class LogoutProperties {
		private Map<String, ProviderLogoutProperties> registration = new HashMap<>();

		@Data
		static class ProviderLogoutProperties {
			private URI logoutUri;
			private String postLogoutUriParameterName;
		}
	}

	static interface PostLogoutUriBuilder {
		URI getPostLogoutUri(WebFilterExchange exchange);
	}

	@RequiredArgsConstructor
	static class AlmostOidcClientInitiatedLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {
		private final LogoutProperties.ProviderLogoutProperties properties;
		private final ClientRegistration clientRegistration;
		private final String postLogoutRedirectUri;

		@Override
		protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
			if (authentication instanceof OAuth2AuthenticationToken oauthentication && authentication.getPrincipal() instanceof OidcUser oidcUser) {
				final var endSessionUri = UriComponentsBuilder.fromUri(properties.getLogoutUri()).queryParam("client_id", clientRegistration.getClientId())
						.queryParam("id_token_hint", oidcUser.getIdToken().getTokenValue())
						.queryParam(properties.getPostLogoutUriParameterName(), postLogoutRedirectUri(request).toString()).toUriString();
				return endSessionUri.toString();
			}
			return super.determineTargetUrl(request, response, authentication);
		}

		private String postLogoutRedirectUri(HttpServletRequest request) {
			if (this.postLogoutRedirectUri == null) {
				return null;
			}
		// @formatter:off
		UriComponents uriComponents = UriComponentsBuilder.fromUriString(request.getRequestURL().toString())
				.replacePath(request.getContextPath())
				.replaceQuery(null)
				.fragment(null)
				.build();

		Map<String, String> uriVariables = new HashMap<>();
		String scheme = uriComponents.getScheme();
		uriVariables.put("baseScheme", (scheme != null) ? scheme : "");
		uriVariables.put("baseUrl", uriComponents.toUriString());

		String host = uriComponents.getHost();
		uriVariables.put("baseHost", (host != null) ? host : "");

		String path = uriComponents.getPath();
		uriVariables.put("basePath", (path != null) ? path : "");

		int port = uriComponents.getPort();
		uriVariables.put("basePort", (port == -1) ? "" : ":" + port);

		uriVariables.put("registrationId", clientRegistration.getRegistrationId());

		return UriComponentsBuilder.fromUriString(this.postLogoutRedirectUri)
				.buildAndExpand(uriVariables)
				.toUriString();
		// @formatter:on
		}
	}

	@RequiredArgsConstructor
	static class DelegatingOidcClientInitiatedLogoutSuccessHandler implements LogoutSuccessHandler {
		private final Map<String, LogoutSuccessHandler> delegates;

		public DelegatingOidcClientInitiatedLogoutSuccessHandler(
				InMemoryClientRegistrationRepository clientRegistrationRepository,
				LogoutProperties properties,
				String postLogoutRedirectUri) {
			delegates = StreamSupport.stream(clientRegistrationRepository.spliterator(), false)
					.collect(Collectors.toMap(ClientRegistration::getRegistrationId, clientRegistration -> {
						final var registrationProperties = properties.getRegistration().get(clientRegistration.getRegistrationId());
						if (registrationProperties == null) {
							final var handler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
							handler.setPostLogoutRedirectUri(postLogoutRedirectUri);
							return handler;
						}
						return new AlmostOidcClientInitiatedLogoutSuccessHandler(registrationProperties, clientRegistration, postLogoutRedirectUri);
					}));
		}

		@Override
		public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
				throws IOException,
				ServletException {
			if (authentication instanceof OAuth2AuthenticationToken oauthentication && authentication.getPrincipal() instanceof OidcUser oidcUser) {
				delegates.get(oauthentication.getAuthorizedClientRegistrationId()).onLogoutSuccess(request, response, authentication);
			}
		}

	}

}
