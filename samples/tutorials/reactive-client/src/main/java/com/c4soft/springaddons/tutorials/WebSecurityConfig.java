package com.c4soft.springaddons.tutorials;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.RedirectServerLogoutSuccessHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class WebSecurityConfig {

	@Bean
	SecurityWebFilterChain clientSecurityFilterChain(
			ServerHttpSecurity http,
			InMemoryReactiveClientRegistrationRepository clientRegistrationRepository,
			LogoutProperties logoutProperties) {
		http.oauth2Login();
		http.logout(logout -> {
			logout.logoutSuccessHandler(
					new DelegatingOidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository, logoutProperties, "{baseUrl}"));
		});
		http.authorizeExchange(ex -> ex.pathMatchers("/login/**", "/oauth2/**").permitAll().anyExchange().authenticated());
		return http.build();
	}

	@Data
	@Configuration
	@ConfigurationProperties(prefix = "logout")
	static class LogoutProperties {
		private Map<String, ProviderLogoutProperties> provider = new HashMap<>();

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
	static class AlmostOidcClientInitiatedServerLogoutSuccessHandler implements ServerLogoutSuccessHandler {
		private final LogoutProperties.ProviderLogoutProperties properties;
		private final ClientRegistration clientRegistration;
		private final String postLogoutRedirectUri;
		private final RedirectServerLogoutSuccessHandler serverLogoutSuccessHandler = new RedirectServerLogoutSuccessHandler();
		private final ServerRedirectStrategy redirectStrategy = new DefaultServerRedirectStrategy();

		@Override
		public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
			// @formatter:off
			return Mono.just(authentication)
					.filter(OAuth2AuthenticationToken.class::isInstance)
					.filter((token) -> authentication.getPrincipal() instanceof OidcUser)
					.map(OAuth2AuthenticationToken.class::cast)
					.flatMap(oauthentication -> {
						final var oidcUser = ((OidcUser) oauthentication.getPrincipal());
						final var endSessionUri = UriComponentsBuilder.fromUri(properties.getLogoutUri())
								.queryParam("client_id", clientRegistration.getClientId())
								.queryParam("id_token_hint", oidcUser.getIdToken().getTokenValue())
								.queryParam(properties.getPostLogoutUriParameterName(), postLogoutRedirectUri(exchange.getExchange().getRequest()).toString()).toUriString();
						return Mono.just(endSessionUri);
					}).switchIfEmpty(this.serverLogoutSuccessHandler.onLogoutSuccess(exchange, authentication).then(Mono.empty()))
					.flatMap((endpointUri) -> this.redirectStrategy.sendRedirect(exchange.getExchange(), URI.create(endpointUri)));
			// @formatter:on
		}

		private String postLogoutRedirectUri(ServerHttpRequest request) {
			if (this.postLogoutRedirectUri == null) {
				return null;
			}
			// @formatter:off
			UriComponents uriComponents = UriComponentsBuilder.fromUri(request.getURI())
					.replacePath(request.getPath().contextPath().value())
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
	static class DelegatingOidcClientInitiatedServerLogoutSuccessHandler implements ServerLogoutSuccessHandler {
		private final Map<String, ServerLogoutSuccessHandler> delegates;

		public DelegatingOidcClientInitiatedServerLogoutSuccessHandler(
				InMemoryReactiveClientRegistrationRepository clientRegistrationRepository,
				LogoutProperties properties,
				String postLogoutRedirectUri) {
			delegates = StreamSupport.stream(clientRegistrationRepository.spliterator(), false)
					.collect(Collectors.toMap(ClientRegistration::getRegistrationId, clientRegistration -> {
						final var registrationProperties = properties.getProvider().get(clientRegistration.getRegistrationId());
						if (registrationProperties == null) {
							final var handler = new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository);
							handler.setPostLogoutRedirectUri(postLogoutRedirectUri);
							return handler;
						}
						return new AlmostOidcClientInitiatedServerLogoutSuccessHandler(registrationProperties, clientRegistration, postLogoutRedirectUri);
					}));
		}

		@Override
		public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
			return Mono.just(authentication).filter(OAuth2AuthenticationToken.class::isInstance).map(OAuth2AuthenticationToken.class::cast)
					.flatMap(oauthentication -> delegates.get(oauthentication.getAuthorizedClientRegistrationId()).onLogoutSuccess(exchange, authentication));
		}

	}

}
