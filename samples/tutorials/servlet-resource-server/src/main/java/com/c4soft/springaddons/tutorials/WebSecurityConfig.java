package com.c4soft.springaddons.tutorials;

import java.net.URL;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;

import jakarta.servlet.http.HttpServletRequest;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@EnableWebSecurity
@EnableMethodSecurity
@Configuration
public class WebSecurityConfig {

	@Bean
	SecurityFilterChain filterChain(
			HttpSecurity http,
			ServerProperties serverProperties,
			@Value("${origins:[]}") String[] origins,
			@Value("${permit-all:[]}") String[] permitAll,
			AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver)
			throws Exception {

		http.oauth2ResourceServer(oauth2 -> oauth2.authenticationManagerResolver(authenticationManagerResolver));

		// Enable and configure CORS
		http.cors(cors -> cors.configurationSource(corsConfigurationSource(origins)));

		// State-less session (state in access-token only)
		http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

		// Disable CSRF because of state-less session-management
		http.csrf(csrf -> csrf.disable());

		// Return 401 (unauthorized) instead of 302 (redirect to login) when
		// authorization is missing or invalid
		http.exceptionHandling(eh -> eh.authenticationEntryPoint((request, response, authException) -> {
			response.addHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"Restricted Content\"");
			response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
		}));

		// If SSL enabled, disable http (https only)
		if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
			http.requiresChannel(channel -> channel.anyRequest().requiresSecure());
		}

		// @formatter:off
        http.authorizeHttpRequests(requests -> requests
            .requestMatchers(Stream.of(permitAll).map(AntPathRequestMatcher::new).toArray(AntPathRequestMatcher[]::new)).permitAll()
            .anyRequest().authenticated());
        // @formatter:on

		return http.build();
	}

	private UrlBasedCorsConfigurationSource corsConfigurationSource(String[] origins) {
		final var configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList(origins));
		configuration.setAllowedMethods(List.of("*"));
		configuration.setAllowedHeaders(List.of("*"));
		configuration.setExposedHeaders(List.of("*"));

		final var source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

	@Data
	@Configuration
	@ConfigurationProperties(prefix = "spring-addons")
	static class SpringAddonsProperties {
		private IssuerProperties[] issuers = {};

		@Data
		static class IssuerProperties {
			private URL uri;

			@NestedConfigurationProperty
			private ClaimMappingProperties[] claims;

			private String usernameJsonPath = JwtClaimNames.SUB;

			@Data
			static class ClaimMappingProperties {
				private String jsonPath;
				private CaseProcessing caseProcessing = CaseProcessing.UNCHANGED;
				private String prefix = "";

				static enum CaseProcessing {
					UNCHANGED, TO_LOWER, TO_UPPER
				}
			}
		}

		public IssuerProperties get(URL issuerUri) throws MisconfigurationException {
			final var issuerProperties = Stream.of(issuers).filter(iss -> issuerUri.equals(iss.getUri())).toList();
			if (issuerProperties.size() == 0) {
				throw new MisconfigurationException("Missing authorities mapping properties for %s".formatted(issuerUri.toString()));
			}
			if (issuerProperties.size() > 1) {
				throw new MisconfigurationException("Too many authorities mapping properties for %s".formatted(issuerUri.toString()));
			}
			return issuerProperties.get(0);
		}

		static class MisconfigurationException extends RuntimeException {
			private static final long serialVersionUID = 5887967904749547431L;

			public MisconfigurationException(String msg) {
				super(msg);
			}
		}
	}

	@RequiredArgsConstructor
	static class JwtGrantedAuthoritiesConverter implements Converter<Jwt, Collection<? extends GrantedAuthority>> {
		private final SpringAddonsProperties.IssuerProperties properties;

		@Override
		@SuppressWarnings({ "rawtypes", "unchecked" })
		public Collection<? extends GrantedAuthority> convert(@NonNull Jwt jwt) {
			return Stream.of(properties.claims).flatMap(claimProperties -> {
				Object claim;
				try {
					claim = JsonPath.read(jwt.getClaims(), claimProperties.jsonPath);
				} catch (PathNotFoundException e) {
					claim = null;
				}
				if (claim == null) {
					return Stream.empty();
				}
				if (claim instanceof String claimStr) {
					return Stream.of(claimStr.split(","));
				}
				if (claim instanceof String[] claimArr) {
					return Stream.of(claimArr);
				}
				if (Collection.class.isAssignableFrom(claim.getClass())) {
					final var iter = ((Collection) claim).iterator();
					if (!iter.hasNext()) {
						return Stream.empty();
					}
					final var firstItem = iter.next();
					if (firstItem instanceof String) {
						return (Stream<String>) ((Collection) claim).stream();
					}
					if (Collection.class.isAssignableFrom(firstItem.getClass())) {
						return (Stream<String>) ((Collection) claim).stream().flatMap(colItem -> ((Collection) colItem).stream()).map(String.class::cast);
					}
				}
				return Stream.empty();
			}).map(SimpleGrantedAuthority::new).map(GrantedAuthority.class::cast).toList();
		}
	}

	@Component
	@RequiredArgsConstructor
	static class SpringAddonsJwtAuthenticationConverter implements Converter<Jwt, JwtAuthenticationToken> {
		private final SpringAddonsProperties springAddonsProperties;

		@Override
		public JwtAuthenticationToken convert(@NonNull Jwt jwt) {
			final var issuerProperties = springAddonsProperties.get(jwt.getIssuer());
			final var authorities = new JwtGrantedAuthoritiesConverter(issuerProperties).convert(jwt);
			final String username = JsonPath.read(jwt.getClaims(), issuerProperties.getUsernameJsonPath());
			return new JwtAuthenticationToken(jwt, authorities, username);
		}
	}

	@Bean
	AuthenticationManagerResolver<HttpServletRequest>
			authenticationManagerResolver(SpringAddonsProperties addonsProperties, SpringAddonsJwtAuthenticationConverter authenticationConverter) {
		final Map<String, AuthenticationManager> authenticationProviders =
				Stream.of(addonsProperties.getIssuers()).map(SpringAddonsProperties.IssuerProperties::getUri).map(URL::toString)
						.collect(Collectors.toMap(issuer -> issuer, issuer -> authenticationProvider(issuer, authenticationConverter)::authenticate));
		return new JwtIssuerAuthenticationManagerResolver((AuthenticationManagerResolver<String>) authenticationProviders::get);
	}

	JwtAuthenticationProvider authenticationProvider(String issuer, SpringAddonsJwtAuthenticationConverter authenticationConverter) {
		JwtDecoder decoder = JwtDecoders.fromIssuerLocation(issuer);
		var provider = new JwtAuthenticationProvider(decoder);
		provider.setJwtAuthenticationConverter(authenticationConverter);
		return provider;
	}
}