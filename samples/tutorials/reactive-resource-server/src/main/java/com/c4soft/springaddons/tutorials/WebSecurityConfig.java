package com.c4soft.springaddons.tutorials;

import java.net.URL;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;

import com.c4soft.springaddons.tutorials.WebSecurityConfig.SpringAddonsProperties.IssuerProperties;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@Configuration
public class WebSecurityConfig {

	@Bean
	SecurityWebFilterChain filterChain(
			ServerHttpSecurity http,
			ServerProperties serverProperties,
			@Value("origins") String[] origins,
			@Value("permit-all") String[] permitAll,
			SpringAddonsProperties springAddonsProperties,
			ReactiveAuthenticationManagerResolver<ServerWebExchange> authenticationManagerResolver)
			throws Exception {

		// Configure the app as resource-server with an authentication manager resolver capable of handling multi-tenancy
		http.oauth2ResourceServer(resourceServer -> resourceServer.authenticationManagerResolver(authenticationManagerResolver));

		http.cors(cors -> cors.configurationSource(corsConfigurationSource(origins)));

		// State-less session (state in access-token only)
		http.securityContextRepository(NoOpServerSecurityContextRepository.getInstance());

		// Disable CSRF because of state-less session-management
		http.csrf().disable();

		// Return 401 (unauthorized) instead of 302 (redirect to login) when
		// authorization is missing or invalid
		http.exceptionHandling(exceptionHandling -> {
			exceptionHandling.accessDeniedHandler(accessDeniedHandler());
		});

		// If SSL enabled, disable http (https only)
		if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
			http.redirectToHttps();
		}

		http.authorizeExchange(exchange -> exchange.pathMatchers(permitAll).permitAll().anyExchange().authenticated());

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

	private ServerAccessDeniedHandler accessDeniedHandler() {
		return (var exchange, var ex) -> exchange.getPrincipal().flatMap(principal -> {
			var response = exchange.getResponse();
			response.setStatusCode(principal instanceof AnonymousAuthenticationToken ? HttpStatus.UNAUTHORIZED : HttpStatus.FORBIDDEN);
			response.getHeaders().setContentType(MediaType.TEXT_PLAIN);
			var dataBufferFactory = response.bufferFactory();
			var buffer = dataBufferFactory.wrap(ex.getMessage().getBytes(Charset.defaultCharset()));
			return response.writeWith(Mono.just(buffer)).doOnError(error -> DataBufferUtils.release(buffer));
		});
	}

	@Data
	@Configuration
	@ConfigurationProperties(prefix = "spring-addons")
	public class SpringAddonsProperties {
		private IssuerProperties[] issuers = {};

		@Data
		static class IssuerProperties {
			private URL uri;
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
		public Collection<? extends GrantedAuthority> convert(Jwt jwt) {
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
	static class SpringAddonsJwtAuthenticationConverter implements Converter<Jwt, Mono<? extends AbstractAuthenticationToken>> {
		private final SpringAddonsProperties springAddonsProperties;

		@Override
		public Mono<? extends AbstractAuthenticationToken> convert(Jwt jwt) {
			final var issuerProperties = springAddonsProperties.get(jwt.getIssuer());
			final var authorities = new JwtGrantedAuthoritiesConverter(issuerProperties).convert(jwt);
			final String username = JsonPath.read(jwt.getClaims(), issuerProperties.getUsernameJsonPath());
			return Mono.just(new JwtAuthenticationToken(jwt, authorities, username));
		}
	}

	@Bean
	ReactiveAuthenticationManagerResolver<ServerWebExchange>
			authenticationManagerResolver(SpringAddonsProperties addonsProperties, SpringAddonsJwtAuthenticationConverter authenticationConverter) {
		final Map<String, Mono<ReactiveAuthenticationManager>> jwtManagers = Stream.of(addonsProperties.getIssuers()).map(IssuerProperties::getUri)
				.map(URL::toString).collect(Collectors.toMap(issuer -> issuer, issuer -> Mono.just(authenticationManager(issuer, authenticationConverter))));
		return new JwtIssuerReactiveAuthenticationManagerResolver(issuerLocation -> jwtManagers.getOrDefault(issuerLocation, Mono.empty()));
	}

	JwtReactiveAuthenticationManager authenticationManager(String issuer, SpringAddonsJwtAuthenticationConverter authenticationConverter) {
		ReactiveJwtDecoder decoder = ReactiveJwtDecoders.fromIssuerLocation(issuer);
		var provider = new JwtReactiveAuthenticationManager(decoder);
		provider.setJwtAuthenticationConverter(authenticationConverter);
		return provider;
	}
}
