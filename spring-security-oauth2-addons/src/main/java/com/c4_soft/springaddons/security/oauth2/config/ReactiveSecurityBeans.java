package com.c4_soft.springaddons.security.oauth2.config;

import java.nio.charset.Charset;
import java.util.Arrays;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;

import com.c4_soft.springaddons.security.oauth2.ReactiveJwt2AuthenticationConverter;
import com.c4_soft.springaddons.security.oauth2.ReactiveJwt2GrantedAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.ReactiveJwt2OidcTokenConverter;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcAuthentication;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcToken;
import com.c4_soft.springaddons.security.oauth2.oidc.ReactiveJwt2OidcAuthenticationConverter;

import reactor.core.publisher.Mono;

public class ReactiveSecurityBeans {
	private final String issuerUri;
	private final SpringAddonsSecurityProperties securityProperties;

	public ReactiveSecurityBeans(
			@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUri,
			SpringAddonsSecurityProperties securityProperties) {
		this.issuerUri = issuerUri;
		this.securityProperties = securityProperties;
	}

	@ConditionalOnMissingBean
	@Bean
	public <T extends OidcToken> ReactiveJwt2AuthenticationConverter<OidcAuthentication<T>> authenticationConverter(
			ReactiveJwt2GrantedAuthoritiesConverter authoritiesConverter,
			ReactiveJwt2OidcTokenConverter<T> tokenConverter) {
		return new ReactiveJwt2OidcAuthenticationConverter<>(authoritiesConverter, tokenConverter);
	}

	@ConditionalOnMissingBean
	@Bean
	public ReactiveJwt2GrantedAuthoritiesConverter authoritiesConverter() {
		return this.securityProperties.getKeycloak() != null
				? new KeycloakReactiveJwt2GrantedAuthoritiesConverter(securityProperties)
				: new Auth0ReactiveJwt2GrantedAuthoritiesConverter(securityProperties);
	}

	@ConditionalOnMissingBean
	@Bean
	public ReactiveJwt2OidcTokenConverter<OidcToken> tokenConverter() {
		return (Jwt jwt) -> Mono.just(new OidcToken(jwt.getClaims()));
	}

	@ConditionalOnMissingBean
	@Bean
	public ReactiveJwtDecoder jwtDecoder() {
		return ReactiveJwtDecoders.fromOidcIssuerLocation(issuerUri);
	}

	@ConditionalOnMissingBean
	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
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

	@ConditionalOnMissingBean
	@Bean
	public ServerAccessDeniedHandler serverAccessDeniedHandler() {
		return (ServerWebExchange exchange, AccessDeniedException ex) -> exchange.getPrincipal().flatMap(principal -> {
			final ServerHttpResponse response = exchange.getResponse();
			response.setStatusCode(principal instanceof AnonymousAuthenticationToken ? HttpStatus.UNAUTHORIZED : HttpStatus.FORBIDDEN);
			response.getHeaders().setContentType(MediaType.TEXT_PLAIN);
			final DataBufferFactory dataBufferFactory = response.bufferFactory();
			final DataBuffer buffer = dataBufferFactory.wrap(ex.getMessage().getBytes(Charset.defaultCharset()));
			return response.writeWith(Mono.just(buffer)).doOnError(error -> DataBufferUtils.release(buffer));
		});
	}
}