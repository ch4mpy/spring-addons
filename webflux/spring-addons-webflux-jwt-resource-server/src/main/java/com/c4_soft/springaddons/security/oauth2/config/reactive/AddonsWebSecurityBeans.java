package com.c4_soft.springaddons.security.oauth2.config.reactive;

import java.net.URI;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.AnyNestedCondition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;

import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties.CorsProperties;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * <p>
 * <b>Usage</b><br>
 * If not using spring-boot, &#64;Import or &#64;ComponentScan this class. All beans defined here are &#64;ConditionalOnMissingBean =&gt; just define your own
 * &#64;Beans to override.
 * </p>
 * <p>
 * <b>Provided &#64;Beans</b>
 * </p>
 * <ul>
 * <li><b>SecurityWebFilterChain</b>: applies CORS, CSRF, anonymous, sessionCreationPolicy, SSL redirect and 401 instead of redirect to login properties as
 * defined in {@link SpringAddonsSecurityProperties}</li>
 * <li><b>AuthorizeExchangeSpecPostProcessor</b>. Override if you need fined grained HTTP security (more than authenticated() to all routes but the ones defined
 * as permitAll() in {@link SpringAddonsSecurityProperties}</li>
 * <li><b>Jwt2AuthoritiesConverter</b>: responsible for converting the JWT into Collection&lt;? extends GrantedAuthority&gt;</li>
 * <li><b>ReactiveJwt2OpenidClaimSetConverter&lt;T extends Map&lt;String, Object&gt; &amp; Serializable&gt;</b>: responsible for converting the JWT into a
 * claim-set of your choice (OpenID or not)</li>
 * <li><b>ReactiveJwt2AuthenticationConverter&lt;OAuthentication&lt;T extends OpenidClaimSet&gt;&gt;</b>: responsible for converting the JWT into an
 * Authentication (uses both beans above)</li>
 * <li><b>ReactiveAuthenticationManagerResolver</b>: required to be able to define more than one token issuer until
 * https://github.com/spring-projects/spring-boot/issues/30108 is solved</li>
 * </ul>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@ConditionalOnProperty(matchIfMissing = true, prefix = "com.c4-soft.springaddons.security", name = "enabled")
@EnableWebFluxSecurity
@AutoConfiguration
@Slf4j
@Import({ AddonsSecurityBeans.class })
public class AddonsWebSecurityBeans {

	/**
	 * <p>
	 * Applies SpringAddonsSecurityProperties to web security config. Be aware that defining a {@link SecurityWebFilterChain} bean with no security matcher and
	 * an order higher than LOWEST_PRECEDENCE will disable most of this lib auto-configuration for OpenID resource-servers.
	 * </p>
	 * <p>
	 * You should consider to set security matcher to all other {@link SecurityWebFilterChain} beans and provide a
	 * {@link ResourceServerHttpSecurityPostProcessor} bean to override anything from this bean
	 * </p>
	 * .
	 *
	 * @param  http                          HTTP security to configure
	 * @param  serverProperties              Spring "server" configuration properties
	 * @param  addonsProperties              "com.c4-soft.springaddons.security" configuration properties
	 * @param  authorizePostProcessor        Hook to override access-control rules for all path that are not listed in "permit-all"
	 * @param  httpPostProcessor             Hook to override all or part of HttpSecurity auto-configuration
	 * @param  authenticationManagerResolver Converts successful JWT decoding result into an {@link Authentication}
	 * @param  accessDeniedHandler           handler for unauthorized requests (missing or invalid access-token)
	 * @return                               A default {@link SecurityWebFilterChain} for reactive resource-servers with JWT decoder(matches all unmatched
	 *                                       routes with lowest precedence)
	 */
	@Order(Ordered.LOWEST_PRECEDENCE)
	@Bean
	SecurityWebFilterChain springAddonsResourceServerSecurityFilterChain(
			ServerHttpSecurity http,
			ServerProperties serverProperties,
			SpringAddonsSecurityProperties addonsProperties,
			ResourceServerAuthorizeExchangeSpecPostProcessor authorizePostProcessor,
			ResourceServerHttpSecurityPostProcessor httpPostProcessor,
			ReactiveAuthenticationManagerResolver<ServerWebExchange> authenticationManagerResolver,
			ServerAccessDeniedHandler accessDeniedHandler) {
		http.oauth2ResourceServer(server -> server.authenticationManagerResolver(authenticationManagerResolver));

		ReactiveConfigurationSupport
				.configureResourceServer(http, serverProperties, addonsProperties, accessDeniedHandler, authorizePostProcessor, httpPostProcessor);

		return http.build();
	}

	/**
	 * Hook to override security rules for all path that are not listed in "permit-all". Default is isAuthenticated().
	 *
	 * @return a hook to override security rules for all path that are not listed in "permit-all". Default is isAuthenticated().
	 */
	@ConditionalOnMissingBean
	@Bean
	ResourceServerAuthorizeExchangeSpecPostProcessor authorizePostProcessor() {
		return (ServerHttpSecurity.AuthorizeExchangeSpec spec) -> spec.anyExchange().authenticated();
	}

	/**
	 * Hook to override all or part of HttpSecurity auto-configuration. Called after spring-addons configuration was applied so that you can modify anything
	 *
	 * @return a hook to override all or part of HttpSecurity auto-configuration. Called after spring-addons configuration was applied so that you can modify
	 *         anything
	 */
	@ConditionalOnMissingBean
	@Bean
	ResourceServerHttpSecurityPostProcessor httpPostProcessor() {
		return serverHttpSecurity -> serverHttpSecurity;
	}

	CorsConfigurationSource corsConfig(CorsProperties[] corsProperties) {
		final var source = new UrlBasedCorsConfigurationSource();
		for (final var corsProps : corsProperties) {
			final var configuration = new CorsConfiguration();
			configuration.setAllowedOrigins(Arrays.asList(corsProps.getAllowedOrigins()));
			configuration.setAllowedMethods(Arrays.asList(corsProps.getAllowedMethods()));
			configuration.setAllowedHeaders(Arrays.asList(corsProps.getAllowedHeaders()));
			configuration.setExposedHeaders(Arrays.asList(corsProps.getExposedHeaders()));
			source.registerCorsConfiguration(corsProps.getPath(), configuration);
		}
		return source;
	}

	public static interface Jwt2AuthenticationConverter extends Converter<Jwt, Mono<AbstractAuthenticationToken>> {
	}

	/**
	 * Converter bean from {@link Jwt} to {@link AbstractAuthenticationToken}
	 *
	 * @param  authoritiesConverter  converts access-token claims into Spring authorities
	 * @param  authenticationFactory builds an {@link Authentication} instance from access-token string and claims
	 * @return                       a converter from {@link Jwt} to {@link AbstractAuthenticationToken}
	 */
	@ConditionalOnMissingBean
	@Bean
	Jwt2AuthenticationConverter jwtAuthenticationConverter(
			Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
			Optional<OAuth2AuthenticationFactory> authenticationFactory,
			SpringAddonsSecurityProperties addonsProperties) {
		return jwt -> authenticationFactory.map(af -> af.build(jwt.getTokenValue(), jwt.getClaims())).orElse(
				Mono.just(
						new JwtAuthenticationToken(
								jwt,
								authoritiesConverter.convert(jwt.getClaims()),
								jwt.getClaimAsString(addonsProperties.getIssuerProperties(jwt.getIssuer()).getUsernameClaim()))));
	}

	/**
	 * Provides with multi-tenancy: builds a ReactiveAuthenticationManagerResolver per provided OIDC issuer URI
	 *
	 * @param  auth2ResourceServerProperties "spring.security.oauth2.resourceserver" configuration properties
	 * @param  addonsProperties              "com.c4-soft.springaddons.security" configuration properties
	 * @param  jwtAuthenticationConverter    converts from a {@link Jwt} to an {@link Authentication} implementation
	 * @return                               Multi-tenant {@link ReactiveAuthenticationManagerResolver} (one for each configured issuer)
	 */
	@ConditionalOnMissingBean
	@Bean
	ReactiveAuthenticationManagerResolver<ServerWebExchange> authenticationManagerResolver(
			OAuth2ResourceServerProperties auth2ResourceServerProperties,
			SpringAddonsSecurityProperties addonsProperties,
			Converter<Jwt, Mono<AbstractAuthenticationToken>> jwtAuthenticationConverter) {
		final var jwtProps = Optional.ofNullable(auth2ResourceServerProperties).map(OAuth2ResourceServerProperties::getJwt);
		// @formatter:off
		Optional.ofNullable(jwtProps.map(OAuth2ResourceServerProperties.Jwt::getIssuerUri)).orElse(jwtProps.map(OAuth2ResourceServerProperties.Jwt::getJwkSetUri))
		    .filter(StringUtils::hasLength)
		    .ifPresent(jwtConf -> {
				log.warn("spring.security.oauth2.resourceserver configuration will be ignored in favor of com.c4-soft.springaddons.security");
			});
		// @formatter:on

		final Map<String, Mono<ReactiveAuthenticationManager>> jwtManagers =
				Stream.of(addonsProperties.getIssuers()).collect(Collectors.toMap(issuer -> issuer.getLocation().toString(), issuer -> {
					final var decoder = issuer.getJwkSetUri() != null && StringUtils.hasLength(issuer.getJwkSetUri().toString())
							? NimbusReactiveJwtDecoder.withJwkSetUri(issuer.getJwkSetUri().toString()).build()
							: NimbusReactiveJwtDecoder.withIssuerLocation(issuer.getLocation().toString()).build();

					final OAuth2TokenValidator<Jwt> defaultValidator = Optional.ofNullable(issuer.getLocation()).map(URI::toString)
							.map(JwtValidators::createDefaultWithIssuer).orElse(JwtValidators.createDefault());

					// If the spring-addons conf for resource server contains a non empty audience, add an audience validator
				// @formatter:off
					final OAuth2TokenValidator<Jwt> jwtValidator = Optional.ofNullable(issuer.getAudience())
							.map(URI::toString)
							.filter(StringUtils::hasText)
							.map(audience -> new JwtClaimValidator<List<String>>(
									JwtClaimNames.AUD,
									(aud) -> aud != null && aud.contains(audience)))
							.map(audValidator -> (OAuth2TokenValidator<Jwt>) new DelegatingOAuth2TokenValidator<>(List.of(defaultValidator, audValidator)))
							.orElse(defaultValidator);
					// @formatter:on

					decoder.setJwtValidator(jwtValidator);
					var provider = new JwtReactiveAuthenticationManager(decoder);
					provider.setJwtAuthenticationConverter(jwtAuthenticationConverter);
					return Mono.just(provider);
				}));

		log.debug(
				"Building default JwtIssuerReactiveAuthenticationManagerResolver with: {} {}",
				auth2ResourceServerProperties.getJwt(),
				Stream.of(addonsProperties.getIssuers()).toList());
		return new JwtIssuerReactiveAuthenticationManagerResolver(issuerLocation -> jwtManagers.getOrDefault(issuerLocation, Mono.empty()));
	}

	/**
	 * Bean to switch from default behavior of redirecting unauthorized users to login (302) to returning 401 (unauthorized)
	 *
	 * @return a bean to switch from default behavior of redirecting unauthorized users to login (302) to returning 401 (unauthorized)
	 */
	@ConditionalOnMissingBean
	@Bean
	ServerAccessDeniedHandler serverAccessDeniedHandler() {
		log.debug("Building default ServerAccessDeniedHandler");
		return (var exchange, var ex) -> exchange.getPrincipal().flatMap(principal -> {
			var response = exchange.getResponse();
			response.setStatusCode(principal instanceof AnonymousAuthenticationToken ? HttpStatus.UNAUTHORIZED : HttpStatus.FORBIDDEN);
			response.getHeaders().setContentType(MediaType.TEXT_PLAIN);
			var dataBufferFactory = response.bufferFactory();
			var buffer = dataBufferFactory.wrap(ex.getMessage().getBytes(Charset.defaultCharset()));
			return response.writeWith(Mono.just(buffer)).doOnError(error -> DataBufferUtils.release(buffer));
		});
	}

	/**
	 * https://docs.spring.io/spring-security/reference/5.8/migration/reactive.html#_i_am_using_angularjs_or_another_javascript_framework
	 */
	@Conditional(CookieCsrf.class)
	@ConditionalOnMissingBean(name = "csrfCookieWebFilter")
	@Bean
	WebFilter csrfCookieWebFilter() {
		return (exchange, chain) -> {
			Mono<CsrfToken> csrfToken = exchange.getAttributeOrDefault(CsrfToken.class.getName(), Mono.empty());
			return csrfToken.doOnSuccess(token -> {
			}).then(chain.filter(exchange));
		};
	}

	static class CookieCsrf extends AnyNestedCondition {

		public CookieCsrf() {
			super(ConfigurationPhase.PARSE_CONFIGURATION);
		}

		@ConditionalOnProperty(name = "com.c4-soft.springaddons.security.csrf", havingValue = "cookie-accessible-from-js")
		static class Value1Condition {

		}

		@ConditionalOnProperty(name = "com.c4-soft.springaddons.security.csrf", havingValue = "cookie-http-only")
		static class Value2Condition {

		}

	}
}