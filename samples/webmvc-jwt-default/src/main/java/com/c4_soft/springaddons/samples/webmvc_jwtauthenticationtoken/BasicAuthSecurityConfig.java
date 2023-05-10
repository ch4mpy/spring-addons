package com.c4_soft.springaddons.samples.webmvc_jwtauthenticationtoken;

import static org.springframework.security.config.Customizer.withDefaults;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ExchangeFilterFunctions;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;

import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties.IssuerProperties;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.ResourceServerExpressionInterceptUrlRegistryPostProcessor;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.ResourceServerHttpSecurityPostProcessor;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.ServletConfigurationSupport;
import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.servlet.http.HttpServletRequest;
import lombok.Data;

/**
 * <p>
 * This is just for demonstration purpose for https://github.com/keycloak/keycloak/discussions/10187
 * </p>
 * <p>
 * Here, we add a security filter chain for requests with Basic authentication. The authentication manager in this filter-chain first retrieves tokens using
 * password-grant flow, and then delegates to an OAuth2 authentication manger (after replacing the Basic Authorization header to a Bearer one containing the
 * just retrieved access token)
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Profile("basic-authentication")
@Configuration
public class BasicAuthSecurityConfig {

	@Bean
	@Order(Ordered.LOWEST_PRECEDENCE - 1)
	SecurityFilterChain basicAuthFilterChain(
			HttpSecurity http,
			ServerProperties serverProperties,
			SpringAddonsSecurityProperties addonsProperties,
			TokenEndpointsProperties tokenEndpointsProperties,
			AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver,
			ResourceServerExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor,
			ResourceServerHttpSecurityPostProcessor httpPostProcessor)
			throws Exception {

		// process only requests with HTTP Basic Authorization
		http.securityMatcher((HttpServletRequest request) -> {
			return Optional.ofNullable(request.getHeader(HttpHeaders.AUTHORIZATION)).map(h -> {
				return h.toLowerCase().startsWith("basic ");
			}).orElse(false);
		});

		http.httpBasic(withDefaults());

		http.userDetailsService((String username) -> {
			return new User(username, "", List.of());
		});

		final var keycloakIssuer = Stream.of(addonsProperties.getIssuers()).filter(iss -> iss.getLocation().toString().contains("/realms/")).findAny()
				.map(IssuerProperties::getLocation).orElse(null);
		final var keycloakBaseUri = UriComponentsBuilder.fromUri(keycloakIssuer).replacePath(null).build().toString();

		http.authenticationManager(new KeycloakPasswordFlowAuthenticationManager(keycloakBaseUri, tokenEndpointsProperties, authenticationManagerResolver));

		ServletConfigurationSupport.configureResourceServer(http, serverProperties, addonsProperties, authorizePostProcessor, httpPostProcessor);

		return http.build();
	}

	static class KeycloakPasswordFlowAuthenticationManager implements AuthenticationManager {
		private final String baseUri;
		private final TokenEndpointsProperties tokenEndpointsProperties;
		private final AuthenticationManagerResolver<HttpServletRequest> jwtAuthenticationManagerResolver;
		private final Map<String, WebClient> webClients = new ConcurrentHashMap<>();

		public KeycloakPasswordFlowAuthenticationManager(
				String baseUri,
				TokenEndpointsProperties tokenEndpointsProperties,
				AuthenticationManagerResolver<HttpServletRequest> jwtAuthenticationManagerResolver) {
			this.baseUri = baseUri;
			this.tokenEndpointsProperties = tokenEndpointsProperties;
			this.jwtAuthenticationManagerResolver = jwtAuthenticationManagerResolver;
		}

		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			try {
				final var requestAttributes = RequestContextHolder.getRequestAttributes();
				if (!(requestAttributes instanceof ServletRequestAttributes)) {
					throw new AuthenticationFailureException("Missing servlet Request context");
				}
				final var request = ((ServletRequestAttributes) requestAttributes).getRequest();
				final var realm = request.getHeader("X-Realm");
				final var realmProperties = tokenEndpointsProperties.getRealms().get(realm);
				final var webClient = getWebClient(baseUri, realmProperties, realm);
				final var tokenResponse = webClient.post()
						.body(
								BodyInserters.fromFormData("grant_type", "password").with("client_id", realmProperties.getClientId())
										.with("username", authentication.getName()).with("password", authentication.getCredentials().toString()))
						.retrieve().bodyToFlux(TokenResponseDto.class).onErrorMap(e -> new AuthenticationFailureException(e)).blockLast();

				// Change request Authorization header: make it a Bearer authorization with the
				// just retrieved access token (instead of a "Basic" one)
				request.setAttribute(HttpHeaders.AUTHORIZATION, "Bearer %s".formatted(tokenResponse.accessToken()));

				// Delegate to the JWT authentication manager we already defined for the OAuth2
				// security filter-chain
				return jwtAuthenticationManagerResolver.resolve(request).authenticate(new BearerTokenAuthenticationToken(tokenResponse.accessToken()));
			} catch (Throwable e) {
				throw new AuthenticationFailureException(e);
			}
		}

		private WebClient getWebClient(String issuerUri, TokenEndpointsProperties.RealmProperties realmProperties, String realm) {
			if (!webClients.containsKey(realm)) {
				final var builder = WebClient.builder().baseUrl("%s/realms/%s/protocol/openid-connect/token".formatted(issuerUri, realm));
				if (StringUtils.hasText(realmProperties.getClientSecret())) {
					builder.filter(ExchangeFilterFunctions.basicAuthentication(realmProperties.getClientId(), realmProperties.getClientSecret()));
				}
				builder.defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);
				webClients.put(realm, builder.build());
			}
			return webClients.get(realm);
		}

		static record TokenResponseDto(@JsonProperty("access_token") String accessToken) {
		}

		@ResponseStatus(HttpStatus.UNAUTHORIZED)
		static class AuthenticationFailureException extends RuntimeException {
			private static final long serialVersionUID = -96469109512884829L;

			public AuthenticationFailureException(Throwable e) {
				super(e);
			}

			public AuthenticationFailureException(String e) {
				super(e);
			}
		}
	}

	@Data
	@Configuration
	@ConfigurationProperties(prefix = "token-endpoints")
	public class TokenEndpointsProperties {
		@NestedConfigurationProperty
		private Map<String, RealmProperties> realms = new HashMap<>();

		@Data
		static class RealmProperties {
			private String clientId;
			private String clientSecret;
		}

		public RealmProperties get(String realm) throws MisconfigurationException {
			if (!realms.containsKey(realm)) {
				throw new MisconfigurationException("Missing token-endpoints properties for %s".formatted(realm.toString()));
			}
			return realms.get(realm);
		}

		static class MisconfigurationException extends RuntimeException {
			private static final long serialVersionUID = 5887967904749547431L;

			public MisconfigurationException(String msg) {
				super(msg);
			}
		}
	}
}
