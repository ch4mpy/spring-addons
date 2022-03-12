package com.c4_soft.springaddons.security.oauth2.config.reactive;

import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;

import com.c4_soft.springaddons.security.oauth2.ReactiveJwt2AuthenticationConverter;
import com.c4_soft.springaddons.security.oauth2.ReactiveJwt2GrantedAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.ReactiveJwt2OidcTokenConverter;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcAuthentication;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcToken;
import com.c4_soft.springaddons.security.oauth2.oidc.ReactiveJwt2OidcAuthenticationConverter;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

@RequiredArgsConstructor
@Configuration
@Import({ SpringAddonsSecurityProperties.class })
public class ReactiveSecurityBeans {
	private final OAuth2ResourceServerProperties auth2ResourceServerProperties;
	private final SpringAddonsSecurityProperties securityProperties;

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
		return new ReactiveEmbeddedJwt2GrantedAuthoritiesConverter(securityProperties);
	}

	@ConditionalOnMissingBean
	@Bean
	public ReactiveJwt2OidcTokenConverter<OidcToken> tokenConverter() {
		return (var jwt) -> Mono.just(new OidcToken(jwt.getClaims()));
	}

	@ConditionalOnMissingBean
	@Bean
	public ReactiveAuthenticationManagerResolver<ServerWebExchange> authenticationManagerResolver() {
		final var locations =
				Stream
						.concat(
								Optional
										.of(auth2ResourceServerProperties.getJwt())
										.map(org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties.Jwt::getIssuerUri)
										.stream(),
								Stream.of(securityProperties.getAuthorizationServerLocations()))
						.filter(l -> l != null && l.length() > 0)
						.collect(Collectors.toSet());

		final Map<String, Mono<ReactiveAuthenticationManager>> managers = locations.stream().collect(Collectors.toMap(l -> l, l -> {
			final var decoder = ReactiveJwtDecoders.fromIssuerLocation(l);
			final var provider = new JwtReactiveAuthenticationManager(decoder);
			provider.setJwtAuthenticationConverter(authenticationConverter(authoritiesConverter(), tokenConverter()));
			return Mono.just(provider::authenticate);
		}));

		return new JwtIssuerReactiveAuthenticationManagerResolver((ReactiveAuthenticationManagerResolver<String>) managers::get);
	}

	@ConditionalOnMissingBean
	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		final var source = new UrlBasedCorsConfigurationSource();
		for (final var corsProps : securityProperties.getCors()) {
			final var configuration = new CorsConfiguration();
			configuration.setAllowedOrigins(Arrays.asList(corsProps.getAllowedOrigins()));
			configuration.setAllowedMethods(Arrays.asList(corsProps.getAllowedMethods()));
			configuration.setAllowedHeaders(Arrays.asList(corsProps.getAllowedHeaders()));
			configuration.setExposedHeaders(Arrays.asList(corsProps.getExposedHeaders()));
			source.registerCorsConfiguration(corsProps.getPath(), configuration);
		}
		return source;
	}

	@ConditionalOnMissingBean
	@Bean
	public ServerAccessDeniedHandler serverAccessDeniedHandler() {
		return (var exchange, var ex) -> exchange.getPrincipal().flatMap(principal -> {
			final var response = exchange.getResponse();
			response.setStatusCode(principal instanceof AnonymousAuthenticationToken ? HttpStatus.UNAUTHORIZED : HttpStatus.FORBIDDEN);
			response.getHeaders().setContentType(MediaType.TEXT_PLAIN);
			final var dataBufferFactory = response.bufferFactory();
			final var buffer = dataBufferFactory.wrap(ex.getMessage().getBytes(Charset.defaultCharset()));
			return response.writeWith(Mono.just(buffer)).doOnError(error -> DataBufferUtils.release(buffer));
		});
	}
}