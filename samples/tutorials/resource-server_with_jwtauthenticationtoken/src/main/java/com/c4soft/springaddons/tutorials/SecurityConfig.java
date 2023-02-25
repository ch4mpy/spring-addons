package com.c4soft.springaddons.tutorials;

import java.net.URI;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.c4soft.springaddons.tutorials.SecurityConfig.SpringAddonsSecurityProperties.SimpleAuthoritiesMappingProperties;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;

import jakarta.servlet.http.HttpServletRequest;
import lombok.Data;

@EnableWebSecurity
@EnableMethodSecurity
@Configuration
public class SecurityConfig {

	interface Jwt2AuthoritiesConverter extends Converter<Jwt, Collection<? extends GrantedAuthority>> {
	}

	interface Jwt2AuthenticationConverter extends Converter<Jwt, JwtAuthenticationToken> {
	}

	@Bean
	SecurityFilterChain filterChain(
			HttpSecurity http,
			ServerProperties serverProperties,
			SpringAddonsSecurityProperties addonsProperties,
			AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver)
			throws Exception {

		http.oauth2ResourceServer(oauth2 -> oauth2.authenticationManagerResolver(authenticationManagerResolver));

		// Enable anonymous
		http.anonymous();

		// Enable and configure CORS
		if (addonsProperties.getCors().length > 0) {
			http.cors().configurationSource(corsConfigurationSource(addonsProperties));
		} else {
			http.cors().disable();
		}

		// State-less session (state in access-token only)
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		// Disable CSRF because of state-less session-management
		http.csrf().disable();

		// Return 401 (unauthorized) instead of 302 (redirect to login) when
		// authorization is missing or invalid
		http.exceptionHandling().authenticationEntryPoint((request, response, authException) -> {
			response.addHeader(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"Restricted Content\"");
			response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
		});

		// If SSL enabled, disable http (https only)
		if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
			http.requiresChannel().anyRequest().requiresSecure();
		}

		// Route security: authenticated to all routes but actuator and Swagger-UI
		// @formatter:off
        http.authorizeHttpRequests()
            .requestMatchers(addonsProperties.getPermitAll()).permitAll()
            .anyRequest().authenticated();
        // @formatter:on

		return http.build();
	}

	@Bean
	JwtIssuerAuthenticationManagerResolver authenticationManagerResolver(
			OAuth2ResourceServerProperties auth2ResourceServerProperties,
			SpringAddonsSecurityProperties addonsProperties,
			Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter) {
		final Map<String, AuthenticationManager> jwtManagers =
				Stream.of(addonsProperties.getIssuers()).collect(Collectors.toMap(issuer -> issuer.getLocation().toString(), issuer -> {
					JwtDecoder decoder = issuer.getJwkSetUri() != null && StringUtils.hasLength(issuer.getJwkSetUri().toString())
							? NimbusJwtDecoder.withJwkSetUri(issuer.getJwkSetUri().toString()).build()
							: JwtDecoders.fromIssuerLocation(issuer.getLocation().toString());
					var provider = new JwtAuthenticationProvider(decoder);
					provider.setJwtAuthenticationConverter(jwtAuthenticationConverter);
					return provider::authenticate;
				}));

		return new JwtIssuerAuthenticationManagerResolver((AuthenticationManagerResolver<String>) jwtManagers::get);
	}

	@Bean
	Jwt2AuthenticationConverter authenticationConverter(
			Converter<Jwt, Collection<? extends GrantedAuthority>> authoritiesConverter,
			SpringAddonsSecurityProperties addonsProperties) {
		return jwt -> new JwtAuthenticationToken(
				jwt,
				authoritiesConverter.convert(jwt),
				JsonPath.read(jwt.getClaims(), addonsProperties.getIssuerProperties(jwt.getIssuer()).getUsernameClaim()));
	}

	@Bean
	Jwt2AuthoritiesConverter authoritiesConverter(SpringAddonsSecurityProperties addonsProperties) {
		// @formatter:off
        return jwt -> {
            final var issuerProps = addonsProperties.getIssuerProperties(jwt.getIssuer());
            return Stream.of(issuerProps.getAuthorities())
                    .flatMap(props -> getAuthorities(jwt.getClaims(), props))
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toSet());
        };
        // @formatter:on
	}

	@Data
	@Configuration
	@ConfigurationProperties(prefix = "com.c4-soft.springaddons.security")
	public static class SpringAddonsSecurityProperties {
		private CorsProperties[] cors = {};
		private IssuerProperties[] issuers = {};
		private String[] permitAll = {};

		@Data
		public static class CorsProperties {
			private String path;
			private String[] allowedOrigins = { "*" };
			private String[] allowedMethods = { "*" };
			private String[] allowedHeaders = { "*" };
			private String[] exposedHeaders = { "*" };
		}

		@Data
		public static class IssuerProperties {
			private URI location;
			private URI jwkSetUri;
			private SimpleAuthoritiesMappingProperties[] authorities = { new SimpleAuthoritiesMappingProperties() };
			private String usernameClaim = StandardClaimNames.SUB;
		}

		@Data
		public static class SimpleAuthoritiesMappingProperties {
			private String path = "realm_access.roles";
			private String prefix = "";
			private Case caze = Case.UNCHANGED;
		}

		public static enum Case {
			UNCHANGED, UPPER, LOWER
		}

		public IssuerProperties getIssuerProperties(String iss) throws NotATrustedIssuerException {
			return Stream.of(issuers).filter(issuerProps -> Objects.equals(Optional.ofNullable(issuerProps.getLocation()).map(URI::toString).orElse(null), iss))
					.findAny().orElseThrow(() -> new NotATrustedIssuerException(iss));
		}

		public IssuerProperties getIssuerProperties(Object iss) throws NotATrustedIssuerException {
			if (iss == null && issuers.length == 1) {
				return issuers[0];
			}
			return getIssuerProperties(Optional.ofNullable(iss).map(Object::toString).orElse(null));
		}

		@ResponseStatus(HttpStatus.UNAUTHORIZED)
		public static final class NotATrustedIssuerException extends RuntimeException {
			private static final long serialVersionUID = 3122111462329395017L;

			public NotATrustedIssuerException(String iss) {
				super("%s is not configured as trusted issuer".formatted(iss));
			}
		}
	}

	private static Stream<String> getAuthorities(Map<String, Object> claims, SimpleAuthoritiesMappingProperties props) {
		return getRoles(claims, props.getPath()).map(r -> processCase(r, props.getCaze())).map(r -> String.format("%s%s", props.getPrefix(), r));
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private static Stream<String> getRoles(Map<String, Object> claims, String path) {
		try {
			final var res = JsonPath.read(claims, path);
			if (res instanceof String r) {
				return Stream.of(r);
			}
			if (res instanceof List l) {
				if (l.size() == 0) {
					return Stream.empty();
				}
				if (l.get(0) instanceof String) {
					return l.stream();
				}
				if (l.get(0) instanceof List) {
					return l.stream().flatMap(o -> ((List) o).stream());
				}
			}
			return Stream.empty();
		} catch (PathNotFoundException e) {
			return Stream.empty();
		}
	}

	private static String processCase(String role, SpringAddonsSecurityProperties.Case caze) {
		switch (caze) {
		case UPPER: {
			return role.toUpperCase();
		}
		case LOWER: {
			return role.toLowerCase();
		}
		default:
			return role;
		}
	}

	private CorsConfigurationSource corsConfigurationSource(SpringAddonsSecurityProperties addonsProperties) {
		final var source = new UrlBasedCorsConfigurationSource();
		for (final var corsProps : addonsProperties.getCors()) {
			final var configuration = new CorsConfiguration();
			configuration.setAllowedOrigins(Arrays.asList(corsProps.getAllowedOrigins()));
			configuration.setAllowedMethods(Arrays.asList(corsProps.getAllowedMethods()));
			configuration.setAllowedHeaders(Arrays.asList(corsProps.getAllowedHeaders()));
			configuration.setExposedHeaders(Arrays.asList(corsProps.getExposedHeaders()));
			source.registerCorsConfiguration(corsProps.getPath(), configuration);
		}
		return source;
	}
}