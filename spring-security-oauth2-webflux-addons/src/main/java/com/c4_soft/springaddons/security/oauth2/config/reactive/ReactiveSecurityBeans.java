package com.c4_soft.springaddons.security.oauth2.config.reactive;

import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;

import com.c4_soft.springaddons.security.oauth2.ReactiveJwt2AuthenticationConverter;
import com.c4_soft.springaddons.security.oauth2.ReactiveJwt2GrantedAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.ReactiveJwt2OidcAuthenticationConverter;
import com.c4_soft.springaddons.security.oauth2.ReactiveJwt2OidcTokenConverter;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcAuthentication;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcToken;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@EnableWebFluxSecurity
@RequiredArgsConstructor
@AutoConfiguration
@Slf4j
@Import(SpringAddonsSecurityProperties.class)
public class ReactiveSecurityBeans {

	@ConditionalOnMissingBean
	@Bean
	public AuthorizeExchangeSpecPostProcessor authorizeExchangeSpecPostProcessor() {
		return (ServerHttpSecurity.AuthorizeExchangeSpec spec) -> spec.anyExchange().authenticated();
	}

	@ConditionalOnMissingBean
	@Bean
	public <T extends OidcToken> ReactiveJwt2AuthenticationConverter<OidcAuthentication<T>> authenticationConverter(
			ReactiveJwt2GrantedAuthoritiesConverter authoritiesConverter,
			ReactiveJwt2OidcTokenConverter<T> tokenConverter) {
		log.debug("Building default ReactiveJwt2OidcAuthenticationConverter");
		return new ReactiveJwt2OidcAuthenticationConverter<>(authoritiesConverter, tokenConverter);
	}

	@ConditionalOnMissingBean
	@Bean
	public ReactiveJwt2GrantedAuthoritiesConverter authoritiesConverter(SpringAddonsSecurityProperties securityProperties) {
		log.debug("Building default CorsConfigurationSource with: ", securityProperties);
		return new ReactiveEmbeddedJwt2GrantedAuthoritiesConverter(securityProperties);
	}

	@ConditionalOnMissingBean
	@Bean
	public ReactiveJwt2OidcTokenConverter<OidcToken> tokenConverter() {
		log.debug("Building default ReactiveJwt2OidcTokenConverter");
		return (var jwt) -> Mono.just(new OidcToken(jwt.getClaims()));
	}

	@ConditionalOnMissingBean
	@Bean
	public ReactiveAuthenticationManagerResolver<ServerWebExchange> authenticationManagerResolver(
			OAuth2ResourceServerProperties auth2ResourceServerProperties,
			SpringAddonsSecurityProperties securityProperties,
			Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> authenticationConverter) {
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
			provider.setJwtAuthenticationConverter(authenticationConverter);
			return Mono.just(provider::authenticate);
		}));

		log
				.debug(
						"Building default JwtIssuerReactiveAuthenticationManagerResolver with: ",
						auth2ResourceServerProperties.getJwt(),
						securityProperties.getAuthorizationServerLocations());
		return new JwtIssuerReactiveAuthenticationManagerResolver((ReactiveAuthenticationManagerResolver<String>) managers::get);
	}

	@ConditionalOnProperty("com.c4-soft.springaddons.security.cors")
	@Bean
	public CorsConfigurationSource corsConfigurationSource(SpringAddonsSecurityProperties securityProperties) {
		log.debug("Building default CorsConfigurationSource with: ", (Object[]) securityProperties.getCors());
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
		log.debug("Building default ServerAccessDeniedHandler");
		return (var exchange, var ex) -> exchange.getPrincipal().flatMap(principal -> {
			final var response = exchange.getResponse();
			response.setStatusCode(principal instanceof AnonymousAuthenticationToken ? HttpStatus.UNAUTHORIZED : HttpStatus.FORBIDDEN);
			response.getHeaders().setContentType(MediaType.TEXT_PLAIN);
			final var dataBufferFactory = response.bufferFactory();
			final var buffer = dataBufferFactory.wrap(ex.getMessage().getBytes(Charset.defaultCharset()));
			return response.writeWith(Mono.just(buffer)).doOnError(error -> DataBufferUtils.release(buffer));
		});
	}

	@ConditionalOnMissingBean
	@Bean
	public SecurityWebFilterChain springSecurityFilterChain(
			ServerHttpSecurity http,
			ServerAccessDeniedHandler accessDeniedHandler,
			ReactiveAuthenticationManagerResolver<ServerWebExchange> authenticationManagerResolver,
			SpringAddonsSecurityProperties securityProperties,
			ServerProperties serverProperties,
			AuthorizeExchangeSpecPostProcessor authorizeExchangeSpecPostProcessor) {

		http.oauth2ResourceServer().authenticationManagerResolver(authenticationManagerResolver);

		if (securityProperties.isAnonymousEnabled()) {
			http.anonymous();
		}

		if (securityProperties.getCors().length > 0) {
			http.cors();
		}

		if (!securityProperties.isCsrfEnabled()) {
			http.csrf().disable();
		}

		if (securityProperties.isStatlessSessions()) {
			http.securityContextRepository(NoOpServerSecurityContextRepository.getInstance());
		}

		if (!securityProperties.isRedirectToLoginIfUnauthorizedOnRestrictedContent()) {
			http.exceptionHandling().accessDeniedHandler(accessDeniedHandler);
		}

		if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
			http.redirectToHttps();
		}

		authorizeExchangeSpecPostProcessor.authorizeRequests(http.authorizeExchange().pathMatchers(securityProperties.getPermitAll()).permitAll());

		return http.build();
	}
}