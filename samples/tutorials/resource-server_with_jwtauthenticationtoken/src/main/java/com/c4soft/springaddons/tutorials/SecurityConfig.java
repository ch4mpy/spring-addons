package com.c4soft.springaddons.tutorials;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

	public interface Jwt2AuthoritiesConverter extends Converter<Jwt, Collection<? extends GrantedAuthority>> {
	}

	@SuppressWarnings("unchecked")
	@Bean
	public Jwt2AuthoritiesConverter authoritiesConverter() {
		// This is a converter for roles as embedded in the JWT by a Keycloak server
		// Roles are taken from both realm_access.roles & resource_access.{client}.roles
		return jwt -> {
			final Map<String, Object> realmAccess = (Map<String, Object>) jwt.getClaims().getOrDefault("realm_access", new HashMap<>());
			final Collection<String> realmRoles = (Collection<String>) realmAccess.getOrDefault("roles", Arrays.asList());

			final Map<String, Object> resourceAccess = (Map<String, Object>) jwt.getClaims().getOrDefault("resource_access", new HashMap<>());
			// We assume here you have "spring-addons-confidential" and "spring-addons-public" clients configured with "client roles" mapper in Keycloak
			final Map<String, Object> confidentialClientAccess =
					(Map<String, Object>) resourceAccess.getOrDefault("spring-addons-confidential", new HashMap<>());
			final Collection<String> confidentialClientRoles = (Collection<String>) confidentialClientAccess.getOrDefault("roles", Arrays.asList());
			final Map<String, Object> publicClientAccess = (Map<String, Object>) resourceAccess.getOrDefault("spring-addons-public", new HashMap<>());
			final Collection<String> publicClientRoles = (Collection<String>) publicClientAccess.getOrDefault("roles", Arrays.asList());

			return Stream.concat(realmRoles.stream(), Stream.concat(confidentialClientRoles.stream(), publicClientRoles.stream()))
					.map(SimpleGrantedAuthority::new).collect(Collectors.toList());
		};
	}

	public interface Jwt2AuthenticationConverter extends Converter<Jwt, AbstractAuthenticationToken> {
	}

	@Bean
	public Jwt2AuthenticationConverter authenticationConverter(Jwt2AuthoritiesConverter authoritiesConverter) {
		return jwt -> new JwtAuthenticationToken(jwt, authoritiesConverter.convert(jwt));
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http, Jwt2AuthenticationConverter authenticationConverter, ServerProperties serverProperties)
			throws Exception {

		// Enable OAuth2 with custom authorities mapping
		http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(authenticationConverter);

		// Enable anonymous
		http.anonymous();

		// Enable and configure CORS
		http.cors().configurationSource(corsConfigurationSource());

		// State-less session (state in access-token only)
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		// Enable CSRF with cookie repo because of state-less session-management
		http.csrf().disable();

		// Return 401 (unauthorized) instead of 403 (redirect to login) when authorization is missing or invalid
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

		return http.build();
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