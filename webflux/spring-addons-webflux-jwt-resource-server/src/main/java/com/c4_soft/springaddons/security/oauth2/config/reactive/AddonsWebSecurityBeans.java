package com.c4_soft.springaddons.security.oauth2.config.reactive;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
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
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;

import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties.IssuerProperties;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * <p>
 * <b>Usage</b><br>
 * If not using spring-boot, &#64;Import or &#64;ComponentScan this class. All beans defined here are &#64;ConditionalOnMissingBean =&gt;
 * just define your own &#64;Beans to override.
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
 * <li><b>ReactiveJwt2OpenidClaimSetConverter&lt;T extends Map&lt;String, Object&gt; &amp; Serializable&gt;</b>: responsible for converting
 * the JWT into a claim-set of your choice (OpenID or not)</li>
 * <li><b>ReactiveJwt2AuthenticationConverter&lt;OAuthentication&lt;T extends OpenidClaimSet&gt;&gt;</b>: responsible for converting the JWT
 * into an Authentication (uses both beans above)</li>
 * <li><b>ReactiveAuthenticationManagerResolver</b>: required to be able to define more than one token issuer until
 * https://github.com/spring-projects/spring-boot/issues/30108 is solved</li>
 * </ul>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@EnableWebFluxSecurity
@AutoConfiguration
@Slf4j
@Import({ AddonsSecurityBeans.class })
public class AddonsWebSecurityBeans {

	/**
	 * Hook to override security rules for all path that are not listed in "permit-all". Default is isAuthenticated().
	 *
	 * @param  securityProperties
	 * @return
	 */
	@ConditionalOnMissingBean
	@Bean
	AuthorizeExchangeSpecPostProcessor authorizeExchangeSpecPostProcessor(SpringAddonsSecurityProperties securityProperties) {
		return (ServerHttpSecurity.AuthorizeExchangeSpec spec) -> spec.anyExchange().authenticated();
	}

	/**
	 * Hook to override all or part of HttpSecurity auto-configuration. Called after spring-addons configuration was applied so that you can
	 * modify anything
	 *
	 * @return
	 */
	@ConditionalOnMissingBean
	@Bean
	ServerHttpSecurityPostProcessor serverHttpSecuritySecurityPostProcessor() {
		return serverHttpSecurity -> serverHttpSecurity;
	}

	public static interface Jwt2AuthenticationConverter extends Converter<Jwt, Mono<AbstractAuthenticationToken>> {
	}

	@ConditionalOnMissingBean
	@Bean
	Jwt2AuthenticationConverter authenticationConverter(
			Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
			SpringAddonsSecurityProperties securityProperties,
			Optional<OAuth2AuthenticationFactory> authenticationFactory) {
		return jwt -> authenticationFactory.map(af -> af.build(jwt.getTokenValue(), jwt.getClaims()))
				.orElse(Mono.just(new JwtAuthenticationToken(jwt, authoritiesConverter.convert(jwt.getClaims()))));
	}

	/**
	 * Provides with multi-tenancy: builds a ReactiveAuthenticationManager per provided OIDC issuer URI
	 *
	 * @param  auth2ResourceServerProperties
	 * @param  securityProperties
	 * @param  authenticationConverter       converts from a Jwt to an `Authentication` implementation
	 * @return
	 */
	@ConditionalOnMissingBean
	@Bean
	ReactiveAuthenticationManagerResolver<ServerWebExchange> authenticationManagerResolver(
			OAuth2ResourceServerProperties auth2ResourceServerProperties,
			SpringAddonsSecurityProperties securityProperties,
			Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
			Converter<Jwt, Mono<AbstractAuthenticationToken>> authenticationConverter) {
		final Optional<IssuerProperties> bootIssuer = Optional.ofNullable(auth2ResourceServerProperties.getJwt())
				.flatMap(jwt -> Optional.ofNullable(StringUtils.hasLength(jwt.getIssuerUri()) ? jwt.getIssuerUri() : null)).map(issuerUri -> {
					final IssuerProperties issuerProps = new IssuerProperties();
					issuerProps.setJwkSetUri(
							Optional.ofNullable(auth2ResourceServerProperties.getJwt().getJwkSetUri()).map(uri -> StringUtils.hasLength(uri) ? uri : null)
									.map(jwkSetUri -> {
										try {
											return new URI(jwkSetUri);
										} catch (URISyntaxException e) {
											throw new RuntimeException("Malformed JWK-set URI: %s".formatted(jwkSetUri));
										}
									}).orElse(null));
					return issuerProps;
				});

		final Map<String, Mono<ReactiveAuthenticationManager>> jwtManagers = Stream.concat(bootIssuer.stream(), Stream.of(securityProperties.getIssuers()))
				.collect(Collectors.toMap(issuer -> issuer.getLocation().toString(), issuer -> {
					final ReactiveJwtDecoder decoder = issuer.getJwkSetUri() != null && StringUtils.hasLength(issuer.getJwkSetUri().toString())
							? NimbusReactiveJwtDecoder.withJwkSetUri(issuer.getJwkSetUri().toString()).build()
							: ReactiveJwtDecoders.fromIssuerLocation(issuer.getLocation().toString());
					final var provider = new JwtReactiveAuthenticationManager(decoder);
					provider.setJwtAuthenticationConverter(authenticationConverter::convert);
					return Mono.just(provider::authenticate);
				}));

		log.debug(
				"Building default JwtIssuerReactiveAuthenticationManagerResolver with: {} {}",
				auth2ResourceServerProperties.getJwt(),
				Stream.of(securityProperties.getIssuers()).toList());
		return new JwtIssuerReactiveAuthenticationManagerResolver((ReactiveAuthenticationManagerResolver<String>) jwtManagers::get);
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

	/**
	 * Switch from default behavior of redirecting unauthorized users to login (302) to returning 401 (unauthorized)
	 *
	 * @return
	 */
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

	/**
	 * Applies SpringAddonsSecurityProperties to web security config. Be aware that overriding this bean will disable most of this lib
	 * auto-configuration for OpenID resource-servers. You should consider providing a ServerHttpSecurityPostProcessor bean instead.
	 *
	 * @param  http
	 * @param  accessDeniedHandler
	 * @param  authenticationManagerResolver
	 * @param  securityProperties
	 * @param  serverProperties
	 * @param  authorizeExchangeSpecPostProcessor
	 * @return
	 */
	@Bean
	SecurityWebFilterChain springSecurityFilterChain(
			ServerHttpSecurity http,
			ServerHttpSecurityPostProcessor serverHttpSecuritySecurityPostProcessor,
			ServerAccessDeniedHandler accessDeniedHandler,
			ReactiveAuthenticationManagerResolver<ServerWebExchange> authenticationManagerResolver,
			SpringAddonsSecurityProperties securityProperties,
			ServerProperties serverProperties,
			AuthorizeExchangeSpecPostProcessor authorizeExchangeSpecPostProcessor) {

		http.oauth2ResourceServer().authenticationManagerResolver(authenticationManagerResolver);

		if (securityProperties.getPermitAll().length > 0) {
			http.anonymous();
		}

		if (securityProperties.getCors().length > 0) {
			http.cors().configurationSource(corsConfigurationSource(securityProperties));
		}

		switch (securityProperties.getCsrf()) {
		case DISABLE:
			http.csrf().disable();
			break;
		case DEFAULT:
			if (securityProperties.isStatlessSessions()) {
				http.csrf().disable();
			} else {
				http.csrf();
			}
			break;
		case SESSION:
			break;
		case COOKIE_HTTP_ONLY:
			http.csrf().csrfTokenRepository(new CookieServerCsrfTokenRepository());
			break;
		case COOKIE_ACCESSIBLE_FROM_JS:
			http.csrf().csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse());
			break;
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

		return serverHttpSecuritySecurityPostProcessor.process(http).build();
	}
}