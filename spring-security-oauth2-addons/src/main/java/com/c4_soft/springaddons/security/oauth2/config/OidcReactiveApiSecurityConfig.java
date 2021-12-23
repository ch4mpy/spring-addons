package com.c4_soft.springaddons.security.oauth2.config;

import java.nio.charset.Charset;
import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;

import com.c4_soft.springaddons.security.oauth2.ReactiveJwt2GrantedAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.oidc.ReactiveJwt2OidcAuthenticationConverter;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

/**
 * <p>
 * Web-security configuration for reactive (webflux) APIs using OidcAuthentication.
 * </p>
 * <p>
 * authorizeRequests default behavior is setting \"permitAll\" (see SecurityProperties) endpoints access to anyone and requesting
 * authentication for others.
 * </p>
 * <p>
 * Quite a few properties allow to configure web security-config {@link SecurityProperties}
 * </p>
 * Here are the defaults
 *
 * <pre>
 * com.c4-soft.springaddons.security.authorities-prefix=
 * com.c4-soft.springaddons.security.uppercase-authorities=false
 * com.c4-soft.springaddons.security.permit-all=/actuator/**,/v3/api-docs/**,/swagger-ui/**,/swagger-ui.html,/webjars/swagger-ui/**,/favicon.ico
 * com.c4-soft.springaddons.security.cors.path=/**
 * com.c4-soft.springaddons.security.cors.allowed-origins=*
 * com.c4-soft.springaddons.security.cors.allowed-methods=*
 * com.c4-soft.springaddons.security.cors.allowed-headers=*
 * com.c4-soft.springaddons.security.cors.exposed-headers=*
 * com.c4-soft.springaddons.security.keycloak.client-id=
 * com.c4-soft.springaddons.security.auth0.roles-claim=https://manage.auth0.com/roles
 * </pre>
 *
 * Sample implementation:
 *
 * <pre>
 * &#64;EnableWebFluxSecurity
 * &#64;EnableReactiveMethodSecurity
 * &#64;Import(SecurityProperties.class)
 * public static class WebSecurityConfig extends OidcReactiveApiSecurityConfig {
 * 	public WebSecurityConfig(&#64;Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUri, SecurityProperties securityProperties) {
 * 		super(issuerUri, securityProperties);
 * 	}
 * }
 * </pre>
 *
 * @author ch4mp
 */
@Getter
@RequiredArgsConstructor
public class OidcReactiveApiSecurityConfig {
	private final String issuerUri;

	private final SecurityProperties securityProperties;

	protected ReactiveJwt2GrantedAuthoritiesConverter authoritiesConverter() {
		return this.securityProperties.getKeycloak() != null
				? new KeycloakReactiveJwt2GrantedAuthoritiesConverter(securityProperties)
				: new Auth0ReactiveJwt2GrantedAuthoritiesConverter(securityProperties);
	}

	protected ServerHttpSecurity.AuthorizeExchangeSpec authorizeRequests(ServerHttpSecurity.AuthorizeExchangeSpec spec) {
		return spec.anyExchange().authenticated();
	}

	@Bean
	public JwtDecoder jwtDecoder() {
		return JwtDecoders.fromOidcIssuerLocation(issuerUri);
	}

	@Bean
	public SecurityWebFilterChain springSecurityFilterChain(
			ServerHttpSecurity http,
			ReactiveJwt2GrantedAuthoritiesConverter authoritiesConverter,
			SpringAddonsAccessDeniedHandler accessDeniedHandler) {

		http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(new ReactiveJwt2OidcAuthenticationConverter(authoritiesConverter));

		// @formatter:off
        http.anonymous().and()
            .cors().and()
            .csrf().disable()
            .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
            .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler);

        authorizeRequests(http.authorizeExchange().pathMatchers(securityProperties.getPermitAll()).permitAll());
        // @formatter:on

		http.redirectToHttps();

		return http.build();
	}

	@Bean
	public CorsConfigurationSource getCorsConfiguration() {
		final CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList(securityProperties.getCors().getAllowedOrigins()));
		configuration.setAllowedMethods(Arrays.asList(securityProperties.getCors().getAllowedMethods()));
		configuration.setAllowedHeaders(Arrays.asList(securityProperties.getCors().getAllowedHeaders()));
		configuration.setExposedHeaders(Arrays.asList(securityProperties.getCors().getExposedHeaders()));
		final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		for (final String p : securityProperties.getCors().getPath()) {
			source.registerCorsConfiguration(p, configuration);
		}
		return source;
	}

	@Component
	public static class SpringAddonsAccessDeniedHandler implements ServerAccessDeniedHandler {

		@Override
		public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException ex) {
			return exchange.getPrincipal().flatMap(principal -> {
				final ServerHttpResponse response = exchange.getResponse();
				response.setStatusCode(principal instanceof AnonymousAuthenticationToken ? HttpStatus.UNAUTHORIZED : HttpStatus.FORBIDDEN);
				response.getHeaders().setContentType(MediaType.TEXT_PLAIN);
				final DataBufferFactory dataBufferFactory = response.bufferFactory();
				final DataBuffer buffer = dataBufferFactory.wrap(ex.getMessage().getBytes(Charset.defaultCharset()));
				return response.writeWith(Mono.just(buffer)).doOnError(error -> DataBufferUtils.release(buffer));
			});
		}

	}

}
