package com.c4_soft.springaddons.security.oauth2.config.reactive;

import java.io.Serializable;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
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
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;

import com.c4_soft.springaddons.security.oauth2.OAuthentication;
import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;
import com.c4_soft.springaddons.security.oauth2.ReactiveJwt2AuthenticationConverter;
import com.c4_soft.springaddons.security.oauth2.ReactiveJwt2OAuthenticationConverter;
import com.c4_soft.springaddons.security.oauth2.ReactiveJwt2OpenidClaimSetConverter;
import com.c4_soft.springaddons.security.oauth2.config.ConfigurableJwtGrantedAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.Jwt2AuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties.TokenIssuerProperties;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * <p>
 * <b>Usage</b><br>
 * If not using spring-boot, &#64;Import or &#64;ComponentScan this class. All beans defined here are &#64;ConditionalOnMissingBean => just
 * define your own &#64;Beans to override.
 * </p>
 * <p>
 * <b>Provided &#64;Beans</b>
 * </p>
 * <ul>
 * <li><b>SecurityWebFilterChain</b>: applies CORS, CSRF, anonymous, sessionCreationPolicy, SSL redirect and 401 instead of redirect to
 * login properties as defined in {@link SpringAddonsSecurityProperties}</li>
 * <li><b>AuthorizeExchangeSpecPostProcessor</b>. Override if you need fined grained HTTP security (more than authenticated() to all routes
 * but the ones defined as permitAll() in {@link SpringAddonsSecurityProperties}</li>
 * <li><b>Jwt2AuthoritiesConverter</b>: responsible for converting the JWT into Collection&lt;? extends GrantedAuthority&gt;</li>
 * <li><b>ReactiveJwt2OpenidClaimSetConverter&lt;T extends OpenidClaimSet&gt;</b>: responsible for converting the JWT into
 * OpenidClaimSet</li>
 * <li><b>ReactiveJwt2AuthenticationConverter&lt;OAuthentication&lt;T extends OpenidClaimSet&gt;&gt;</b>: responsible for converting the JWT
 * into an Authentication (uses both beans above)</li>
 * <li><b>ReactiveAuthenticationManagerResolver</b>: required to be able to define more than one token issuer until
 * https://github.com/spring-projects/spring-boot/issues/30108 is solved</li>
 * </ul>
 *
 * @author Jerome Wacongne ch4mp@c4-soft.com
 */
@EnableWebFluxSecurity
@RequiredArgsConstructor
@AutoConfiguration
@Slf4j
@Import(SpringAddonsSecurityProperties.class)
public class ReactiveSecurityBeans {

	@ConditionalOnMissingBean
	@Bean
	AuthorizeExchangeSpecPostProcessor authorizeExchangeSpecPostProcessor() {
		return (ServerHttpSecurity.AuthorizeExchangeSpec spec) -> spec.anyExchange().authenticated();
	}

	@ConditionalOnMissingBean
	@Bean
	<T extends OpenidClaimSet> ReactiveJwt2AuthenticationConverter<OAuthentication<T>> authenticationConverter(
			Jwt2AuthoritiesConverter authoritiesConverter,
			ReactiveJwt2OpenidClaimSetConverter<T> tokenConverter) {
		log.debug("Building default ReactiveJwt2OAuthenticationConverter");
		return new ReactiveJwt2OAuthenticationConverter<>(authoritiesConverter, tokenConverter);
	}

	@ConditionalOnMissingBean
	@Bean
	Jwt2AuthoritiesConverter authoritiesConverter(SpringAddonsSecurityProperties securityProperties) {
		log.debug("Building default CorsConfigurationSource with: {}", securityProperties);
		return new ConfigurableJwtGrantedAuthoritiesConverter(securityProperties);
	}

	@ConditionalOnMissingBean
	@Bean
	ReactiveJwt2OpenidClaimSetConverter<OpenidClaimSet> tokenConverter() {
		log.debug("Building default ReactiveJwt2OpenidClaimSetConverter");
		return (var jwt) -> Mono.just(new OpenidClaimSet(jwt.getClaims()));
	}

	@ConditionalOnMissingBean
	@Bean
	ReactiveAuthenticationManagerResolver<ServerWebExchange> authenticationManagerResolver(
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
								Stream.of(securityProperties.getTokenIssuers()).map(TokenIssuerProperties::getLocation))
						.filter(Objects::nonNull)
						.map(Serializable::toString)
						.filter(StringUtils::hasLength)
						.collect(Collectors.toSet());

		final Map<String, Mono<ReactiveAuthenticationManager>> managers = locations.stream().collect(Collectors.toMap(l -> l, l -> {
			final var decoder = ReactiveJwtDecoders.fromIssuerLocation(l);
			final var provider = new JwtReactiveAuthenticationManager(decoder);
			provider.setJwtAuthenticationConverter(authenticationConverter);
			return Mono.just(provider::authenticate);
		}));

		log
				.debug(
						"Building default JwtIssuerReactiveAuthenticationManagerResolver with: {} {}",
						auth2ResourceServerProperties.getJwt(),
						Stream.of(securityProperties.getTokenIssuers()).toList());
		return new JwtIssuerReactiveAuthenticationManagerResolver((ReactiveAuthenticationManagerResolver<String>) managers::get);
	}

	private CorsConfigurationSource corsConfigurationSource(SpringAddonsSecurityProperties securityProperties) {
		log.debug("Building default CorsConfigurationSource with: {}", Stream.of(securityProperties.getCors()).toList());
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
	ServerAccessDeniedHandler serverAccessDeniedHandler() {
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
	SecurityWebFilterChain springSecurityFilterChain(
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
			http.cors().configurationSource(corsConfigurationSource(securityProperties));
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