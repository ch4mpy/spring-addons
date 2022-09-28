package com.c4_soft.springaddons.security.oauth2.config.reactive;

import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties.CorsProperties;

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
@Configuration
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

	/**
	 * Switch from default behavior of redirecting unauthorized users to login (302) to returning 401 (unauthorized)
	 *
	 * @return
	 */
	@ConditionalOnMissingBean
	@Bean
	ServerAccessDeniedHandler serverAccessDeniedHandler() {
		log.debug("Building default ServerAccessDeniedHandler");
		return (exchange, ex) -> exchange.getPrincipal().flatMap(principal -> {
			final ServerHttpResponse response = exchange.getResponse();
			response.setStatusCode(principal instanceof AnonymousAuthenticationToken ? HttpStatus.UNAUTHORIZED : HttpStatus.FORBIDDEN);
			response.getHeaders().setContentType(MediaType.TEXT_PLAIN);
			final DataBufferFactory dataBufferFactory = response.bufferFactory();
			final DataBuffer buffer = dataBufferFactory.wrap(ex.getMessage().getBytes(Charset.defaultCharset()));
			return response.writeWith(Mono.just(buffer)).doOnError(error -> DataBufferUtils.release(buffer));
		});
	}

	/**
	 * Process introspection result to extract authorities. Could also switch resulting Authentication type if
	 * https://github.com/spring-projects/spring-security/issues/11661 is solved
	 *
	 * @param  <T>
	 * @param  oauth2Properties
	 * @param  claimsConverter
	 * @param  authoritiesConverter
	 * @return
	 */
	@ConditionalOnMissingBean
	@Bean
	ReactiveOpaqueTokenIntrospector introspector(
			OAuth2ResourceServerProperties oauth2Properties,
			Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter) {
		return new C4OpaqueTokenIntrospector(
				oauth2Properties.getOpaquetoken().getIntrospectionUri(),
				oauth2Properties.getOpaquetoken().getClientId(),
				oauth2Properties.getOpaquetoken().getClientSecret(),
				authoritiesConverter);
	}

	/**
	 * Applies SpringAddonsSecurityProperties to web security config. Be aware that overriding this bean will disable most of this lib
	 * auto-configuration for OpenID resource-servers. You should consider providing a ServerHttpSecurityPostProcessor bean instead.
	 *
	 * @param  http
	 * @param  serverHttpSecuritySecurityPostProcessor
	 * @param  accessDeniedHandler
	 * @param  authenticationManager
	 * @param  securityProperties
	 * @param  serverProperties
	 * @param  oauth2Properties
	 * @param  authorizeExchangeSpecPostProcessor
	 * @param  authenticationFactory
	 * @return
	 */
	@Bean
	SecurityWebFilterChain springSecurityFilterChain(
			ServerHttpSecurity http,
			ServerHttpSecurityPostProcessor serverHttpSecuritySecurityPostProcessor,
			AuthorizeExchangeSpecPostProcessor authorizeExchangeSpecPostProcessor,
			ServerAccessDeniedHandler accessDeniedHandler,
			SpringAddonsSecurityProperties securityProperties,
			ServerProperties serverProperties,
			OAuth2ResourceServerProperties oauth2Properties,
			ReactiveOpaqueTokenIntrospector introspector) {

		http.oauth2ResourceServer().opaqueToken().introspector(introspector);

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

	private CorsConfigurationSource corsConfigurationSource(SpringAddonsSecurityProperties securityProperties) {
		log.debug("Building default CorsConfigurationSource with: {}", Stream.of(securityProperties.getCors()).collect(Collectors.toList()));
		final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		for (final CorsProperties corsProps : securityProperties.getCors()) {
			final CorsConfiguration configuration = new CorsConfiguration();
			configuration.setAllowedOrigins(Arrays.asList(corsProps.getAllowedOrigins()));
			configuration.setAllowedMethods(Arrays.asList(corsProps.getAllowedMethods()));
			configuration.setAllowedHeaders(Arrays.asList(corsProps.getAllowedHeaders()));
			configuration.setExposedHeaders(Arrays.asList(corsProps.getExposedHeaders()));
			source.registerCorsConfiguration(corsProps.getPath(), configuration);
		}
		return source;
	}
}