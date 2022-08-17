package com.c4soft.springaddons.tutorials;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import lombok.RequiredArgsConstructor;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	private final ServerProperties serverProperties;

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		// Enable OIDC
		http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(authenticationConverter(authoritiesConverter()));

		// Enable anonymous
		http.anonymous();

		// Enable and configure CORS
		http.cors().configurationSource(corsConfigurationSource());

		// State-less session (client state in JWT token only)
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		// Enable CSRF with cookie repo because of state-less session-management
		http.csrf().csrfTokenRepository(new CookieCsrfTokenRepository());

		// Return 401 instead of redirect to login page
		http.exceptionHandling().authenticationEntryPoint((request, response, authException) -> {
			response.addHeader(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"Restricted Content\"");
			response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
		});

		// If SSL enabled, disable http (https only)
		if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
			http.requiresChannel().anyRequest().requiresSecure();
		} else {
			http.requiresChannel().anyRequest().requiresInsecure();
		}

		// Route security: authenticated to all routes but actuator and Swagger-UI
		// @formatter:off
		http.authorizeRequests()
				.antMatchers("/actuator/health/readiness", "/actuator/health/liveness", "/v3/api-docs/**").permitAll()
				.anyRequest().authenticated();
		// @formatter:on
	}

	public interface Jw2tAuthoritiesConverter extends Converter<Jwt, Collection<? extends GrantedAuthority>> {
	}

	public interface Jwt2AuthenticationConverter extends Converter<Jwt, JwtAuthenticationToken> {
	}

	@Bean
	public Jwt2AuthenticationConverter authenticationConverter(Jw2tAuthoritiesConverter authoritiesConverter) {
		return jwt -> new JwtAuthenticationToken(jwt, authoritiesConverter.convert(jwt));
	}

	@SuppressWarnings("unchecked")
	@Bean
	public Jw2tAuthoritiesConverter authoritiesConverter() {
		// This is a converter for roles as embedded in the JWT by a Keycloak server
		// Roles are taken from both realm_access.roles & resource_access.{client}.roles
		return jwt -> {
			final Map<String, Object> realmAccess = (Map<String, Object>) jwt.getClaims().getOrDefault("realm_access", Collections.emptyMap());
			final Collection<String> realmRoles = (Collection<String>) realmAccess.getOrDefault("roles", Collections.emptyList());

			final Map<String, Object> resourceAccess = (Map<String, Object>) jwt.getClaims().getOrDefault("resource_access", Collections.emptyMap());
			// We assume here you have a "spring-addons" client configure in your Keycloak realm
			final Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.getOrDefault("spring-addons", Collections.emptyMap());
			final Collection<String> clientRoles = (Collection<String>) clientAccess.getOrDefault("roles", Collections.emptyList());

			return Stream.concat(realmRoles.stream(), clientRoles.stream()).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
		};
	}

	private CorsConfigurationSource corsConfigurationSource() {
		// Very permissive CORS config...
		final CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList("*"));
		configuration.setAllowedMethods(Arrays.asList("*"));
		configuration.setAllowedHeaders(Arrays.asList("*"));
		configuration.setExposedHeaders(Arrays.asList("*"));

		// Limited to API routes (neither actuator nor Swagger-UI)
		final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/greet/**", configuration);

		return source;
	}
}
