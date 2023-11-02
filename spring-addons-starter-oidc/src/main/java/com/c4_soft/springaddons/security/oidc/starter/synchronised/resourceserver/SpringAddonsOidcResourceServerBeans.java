package com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.util.StringUtils;

import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultAuthenticationManagerResolverCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.IsIntrospectingResourceServerCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.IsJwtDecoderResourceServerCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsOidcResourceServerCondition;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.ServletConfigurationSupport;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.SpringAddonsOidcBeans;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

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
 * <li>springAddonsResourceServerSecurityFilterChain: applies CORS, CSRF, anonymous, sessionCreationPolicy, SSL, redirect and 401 instead of redirect to login
 * as defined in <a href=
 * "https://github.com/ch4mpy/spring-addons/blob/master/spring-addons-oauth2/src/main/java/com/c4_soft/springaddons/security/oauth2/config/SpringAddonsSecurityProperties.java">SpringAddonsSecurityProperties</a></li>
 * <li>authorizePostProcessor: a bean of type {@link ResourceServerExpressionInterceptUrlRegistryPostProcessor} to fine tune access control from java
 * configuration. It applies to all routes not listed in "permit-all" property configuration. Default requires users to be authenticated. <b>This is a bean to
 * provide in your application configuration if you prefer to define fine-grained access control rules with Java configuration rather than methods
 * security.</b></li>
 * <li>httpPostProcessor: a bean of type {@link ResourceServerHttpSecurityPostProcessor} to override anything from above auto-configuration. It is called just
 * before the security filter-chain is returned. Default is a no-op.</li>
 * <li>jwtAuthenticationConverter: a converter from a {@link Jwt} to something inheriting from {@link AbstractAuthenticationToken}. The default instantiate a
 * {@link JwtAuthenticationToken} with username and authorities as configured for the issuer of thi token. The easiest to override the type of
 * {@link AbstractAuthenticationToken}, is to provide with an Converter&lt;Jwt, ? extends AbstractAuthenticationToken&gt; bean.</li>
 * <li>authenticationManagerResolver: to accept authorities from more than one issuer, the recommended way is to provide an
 * {@link AuthenticationManagerResolver<HttpServletRequest>} supporting it. Default keeps a {@link JwtAuthenticationProvider} with its own {@link JwtDecoder}
 * for each issuer.</li>
 * </ul>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@ConditionalOnWebApplication(type = Type.SERVLET)
@Conditional(IsOidcResourceServerCondition.class)
@EnableWebSecurity
@AutoConfiguration
@ImportAutoConfiguration(SpringAddonsOidcBeans.class)
@Slf4j
public class SpringAddonsOidcResourceServerBeans {
	/**
	 * <p>
	 * Configures a SecurityFilterChain for a resource server with JwtDecoder with &#64;Order(LOWEST_PRECEDENCE). Defining a {@link SecurityWebFilterChain} bean
	 * with no security matcher and an order higher than LOWEST_PRECEDENCE will hide this filter-chain an disable most of spring-addons auto-configuration for
	 * OpenID resource-servers.
	 * </p>
	 *
	 * @param  http                          HTTP security to configure
	 * @param  serverProperties              Spring "server" configuration properties
	 * @param  addonsProperties              "com.c4-soft.springaddons.oidc" configuration properties
	 * @param  authorizePostProcessor        Hook to override access-control rules for all path that are not listed in "permit-all"
	 * @param  httpPostProcessor             Hook to override all or part of HttpSecurity auto-configuration
	 * @param  authenticationManagerResolver Converts successful JWT decoding result into an {@link Authentication}
	 * @return                               A {@link SecurityWebFilterChain} for servlet resource-servers with JWT decoder
	 */
	@Conditional(IsJwtDecoderResourceServerCondition.class)
	@Order(Ordered.LOWEST_PRECEDENCE)
	@Bean
	SecurityFilterChain springAddonsJwtResourceServerSecurityFilterChain(
			HttpSecurity http,
			ServerProperties serverProperties,
			SpringAddonsOidcProperties addonsProperties,
			ResourceServerExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor,
			ResourceServerHttpSecurityPostProcessor httpPostProcessor,
			AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver,
			AuthenticationEntryPoint authenticationEntryPoint,
			AuthenticationEntryPoint exceptionHandlerAuthenticationEntryPoint) throws Exception {
		http.oauth2ResourceServer(oauth2 -> {
			oauth2.authenticationManagerResolver(authenticationManagerResolver);
			oauth2.authenticationEntryPoint(authenticationEntryPoint);
		});

		ServletConfigurationSupport.configureResourceServer(http, serverProperties,
				addonsProperties.getResourceserver(),exceptionHandlerAuthenticationEntryPoint, authorizePostProcessor, httpPostProcessor);

		return http.build();
	}

	/**
	 * <p>
	 * Configures a SecurityFilterChain for a resource server with JwtDecoder with &#64;Order(LOWEST_PRECEDENCE). Defining a {@link SecurityWebFilterChain} bean
	 * with no security matcher and an order higher than LOWEST_PRECEDENCE will hide this filter-chain an disable most of spring-addons auto-configuration for
	 * OpenID resource-servers.
	 * </p>
	 *
	 * @param  http                                 HTTP security to configure
	 * @param  serverProperties                     Spring "server" configuration properties
	 * @param  addonsProperties                     "com.c4-soft.springaddons.oidc" configuration properties
	 * @param  authorizePostProcessor               Hook to override access-control rules for all path that are not listed in "permit-all"
	 * @param  httpPostProcessor                    Hook to override all or part of HttpSecurity auto-configuration
	 * @param  introspectionAuthenticationConverter Converts successful introspection result into an {@link Authentication}
	 * @param  opaqueTokenIntrospector              the instrospector to use
	 * @return                                      A {@link SecurityWebFilterChain} for servlet resource-servers with access token introspection
	 */
	@Conditional(IsIntrospectingResourceServerCondition.class)
	@Order(Ordered.LOWEST_PRECEDENCE)
	@Bean
	SecurityFilterChain springAddonsIntrospectingResourceServerSecurityFilterChain(
			HttpSecurity http,
			ServerProperties serverProperties,
			SpringAddonsOidcProperties addonsProperties,
			ResourceServerExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor,
			ResourceServerHttpSecurityPostProcessor httpPostProcessor,
			OpaqueTokenAuthenticationConverter introspectionAuthenticationConverter,
			OpaqueTokenIntrospector opaqueTokenIntrospector,
			AuthenticationEntryPoint authenticationEntryPoint,
			AuthenticationEntryPoint exceptionHandlerAuthenticationEntryPoint )
			throws Exception {
		http.oauth2ResourceServer(server -> {
			server.opaqueToken(ot -> {
				ot.introspector(opaqueTokenIntrospector);
				ot.authenticationConverter(introspectionAuthenticationConverter);
			});
			server.authenticationEntryPoint(authenticationEntryPoint);
		});

		ServletConfigurationSupport.configureResourceServer(http, serverProperties,
				addonsProperties.getResourceserver(),exceptionHandlerAuthenticationEntryPoint, authorizePostProcessor, httpPostProcessor);

		return http.build();
	}

	/**
	 * hook to override security rules for all path that are not listed in "permit-all". Default is isAuthenticated().
	 *
	 * @return a hook to override security rules for all path that are not listed in "permit-all". Default is isAuthenticated().
	 */
	@ConditionalOnMissingBean
	@Bean
	ResourceServerExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor() {
		return registry -> registry.anyRequest().authenticated();
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
		return httpSecurity -> httpSecurity;
	}

	
	/**
	 * hook to override authenticationEntryPoint for @see BearerTokenAuthenticationFilter.
	 * Default is @see BearerTokenAuthenticationEntryPoint.
	 *
	 * @return AuthenticationEntryPoint
	 */
	
	@ConditionalOnMissingBean
	@Bean
	AuthenticationEntryPoint authenticationEntryPoint() {
		return new BearerTokenAuthenticationEntryPoint();
	}
	
	/**
	 * hook to override exceptionHandlerAuthenticationEntryPoint
	 *
	 * @return AuthenticationEntryPoint
	 */
	
	@ConditionalOnMissingBean
	@Bean
	AuthenticationEntryPoint exceptionHandlerAuthenticationEntryPoint() {
		return (request, response, authException) ->{
			response.addHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"Restricted Content\"");
			response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());	
		} ;
	}

	/**
	 * Provides with multi-tenancy: builds a AuthenticationManagerResolver<HttpServletRequest> per provided OIDC issuer URI
	 *
	 * @param  auth2ResourceServerProperties "spring.security.oauth2.resourceserver" configuration properties
	 * @param  addonsProperties              "com.c4-soft.springaddons.oidc" configuration properties
	 * @param  jwtAuthenticationConverter    converts from a {@link Jwt} to an {@link Authentication} implementation
	 * @return                               Multi-tenant {@link AuthenticationManagerResolver<HttpServletRequest>} (one for each configured issuer)
	 */
	@Conditional(DefaultAuthenticationManagerResolverCondition.class)
	@Bean
	AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver(
			OAuth2ResourceServerProperties auth2ResourceServerProperties,
			SpringAddonsOidcProperties addonsProperties,
			JwtAbstractAuthenticationTokenConverter jwtAuthenticationConverter) {
		final var jwtProps = Optional.ofNullable(auth2ResourceServerProperties).map(OAuth2ResourceServerProperties::getJwt);
		// @formatter:off
		Optional.ofNullable(jwtProps.map(OAuth2ResourceServerProperties.Jwt::getIssuerUri)).orElse(jwtProps.map(OAuth2ResourceServerProperties.Jwt::getJwkSetUri))
		    .filter(StringUtils::hasLength)
		    .ifPresent(jwtConf -> {
				log.warn("spring.security.oauth2.resourceserver configuration will be ignored in favor of com.c4-soft.springaddons.oidc");
			});
		// @formatter:on

		final Map<String, AuthenticationManager> jwtManagers =
				Stream.of(addonsProperties.getOps()).collect(Collectors.toMap(issuer -> issuer.getIss().toString(), issuer -> {
					final var decoder = issuer.getJwkSetUri() != null && StringUtils.hasLength(issuer.getJwkSetUri().toString())
							? NimbusJwtDecoder.withJwkSetUri(issuer.getJwkSetUri().toString()).build()
							: NimbusJwtDecoder.withIssuerLocation(issuer.getIss().toString()).build();

					final OAuth2TokenValidator<Jwt> defaultValidator = Optional.ofNullable(issuer.getIss()).map(URI::toString)
							.map(JwtValidators::createDefaultWithIssuer).orElse(JwtValidators.createDefault());

				// @formatter:off
					final OAuth2TokenValidator<Jwt> jwtValidator = Optional.ofNullable(issuer.getAud())
							.filter(StringUtils::hasText)
							.map(audience -> new JwtClaimValidator<List<String>>(
									JwtClaimNames.AUD,
									(aud) -> aud != null && aud.contains(audience)))
							.map(audValidator -> (OAuth2TokenValidator<Jwt>) new DelegatingOAuth2TokenValidator<>(List.of(defaultValidator, audValidator)))
							.orElse(defaultValidator);
					// @formatter:on

					decoder.setJwtValidator(jwtValidator);
					var provider = new JwtAuthenticationProvider(decoder);
					provider.setJwtAuthenticationConverter(jwtAuthenticationConverter);
					return provider::authenticate;
				}));

		log.debug(
				"Building default JwtIssuerAuthenticationManagerResolver with: ",
				auth2ResourceServerProperties.getJwt(),
				Stream.of(addonsProperties.getOps()).toList());

		return new JwtIssuerAuthenticationManagerResolver((AuthenticationManagerResolver<String>) jwtManagers::get);
	}
}