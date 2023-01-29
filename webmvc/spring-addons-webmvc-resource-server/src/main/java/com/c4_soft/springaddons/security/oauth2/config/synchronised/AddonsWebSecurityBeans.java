package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import java.util.Arrays;
import java.util.Collection;
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
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.c4_soft.springaddons.security.oauth2.config.ConditionalOnMissingProperty;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

/**
 * <p>
 * <b>Usage</b><br>
 * If not using spring-boot, &#64;Import or &#64;ComponentScan this class. All
 * beans defined here are &#64;ConditionalOnMissingBean =&gt; just define your
 * own &#64;Beans to override.
 * </p>
 * <p>
 * <b>Provided &#64;Beans</b>
 * </p>
 * <ul>
 * <li><b>SecurityFilterChain</b>: applies CORS, CSRF, anonymous,
 * sessionCreationPolicy, SSL redirect and 401 instead of redirect to login
 * properties as defined in {@link SpringAddonsSecurityProperties}</li>
 * <li><b>ExpressionInterceptUrlRegistryPostProcessor</b>. Override if you need
 * fined grained HTTP security (more than authenticated() to all routes but the
 * ones defined as permitAll() in {@link SpringAddonsSecurityProperties}</li>
 * <li><b>SimpleJwtGrantedAuthoritiesConverter</b>: responsible for converting
 * the JWT into Collection&lt;? extends GrantedAuthority&gt;</li>
 * <li><b>SynchronizedJwt2OpenidClaimSetConverter&lt;T extends Map&lt;String,
 * Object&gt; &amp; Serializable&gt;</b>: responsible for converting the JWT
 * into a claim-set of your choice (OpenID or not)</li>
 * <li><b>SynchronizedJwt2AuthenticationConverter&lt;OAuthentication&lt;T&gt;&gt;</b>:
 * responsible for converting the JWT into an Authentication (uses both beans
 * above)</li>
 * <li><b>JwtIssuerAuthenticationManagerResolver</b>: required to be able to
 * define more than one token issuer until
 * https://github.com/spring-projects/spring-boot/issues/30108 is solved</li>
 * </ul>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@AutoConfiguration
@EnableWebSecurity
@Slf4j
@Import({ AddonsSecurityBeans.class })
public class AddonsWebSecurityBeans {

	/**
     * <p>
     * Applies SpringAddonsSecurityProperties to web security config. Be aware that
     * defining a {@link SecurityWebFilterChain} bean with no security matcher and
     * an order higher than LOWEST_PRECEDENCE will disable most of this lib
     * auto-configuration for OpenID resource-servers.
     * </p>
     * <p>
     * You should consider to set security matcher to all other
     * {@link SecurityWebFilterChain} beans and provide
     * a {@link ServerHttpSecurityPostProcessor} bean to override anything from this
     * bean.
     * </p>
     *
     * @param http                          HTTP security to configure
     * @param serverProperties              Spring "server" configuration properties
     * @param addonsProperties              "com.c4-soft.springaddons.security"
     *                                      configuration properties
     * @param authorizePostProcessor        Hook to override access-control rules
     *                                      for all path that are not listed in
     *                                      "permit-all"
     * @param httpPostProcessor             Hook to override all or part of
     *                                      HttpSecurity auto-configuration
	 * @param introspectingAuthenticationConverter Converts successful introspection result
     *                                      into an {@link Authentication}
     * @param authenticationManagerResolver Converts successful JWT decoding result
     *                                      into an {@link Authentication}
     * @return A default {@link SecurityWebFilterChain} for servlet resource-servers
     *         (matches all unmatched routes with lowest precedence)
	 */
	@Order(Ordered.LOWEST_PRECEDENCE)
	@Bean
	SecurityFilterChain c4ResourceServerSecurityFilterChain(
			HttpSecurity http,
			ServerProperties serverProperties,
			SpringAddonsSecurityProperties addonsProperties,
			ExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor,
			HttpSecurityPostProcessor httpPostProcessor,
			Optional<OpaqueTokenAuthenticationConverter> introspectingAuthenticationConverter,
			Optional<AuthenticationManagerResolver<HttpServletRequest>> authenticationManagerResolver)
			throws Exception {

		introspectingAuthenticationConverter.ifPresentOrElse(authenticationConverter -> {
			try {
				http.oauth2ResourceServer().opaqueToken().authenticationConverter(authenticationConverter);
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
			log.info("Building servlet c4ResourceServerSecurityFilterChain with introspection");
		}, () -> {
			authenticationManagerResolver.ifPresent(amr -> {
				try {
					http.oauth2ResourceServer().authenticationManagerResolver(amr);
				} catch (Exception e) {
					throw new RuntimeException(e);
				}
			});
			log.info("Building servlet c4ResourceServerSecurityFilterChain with JWT decoder");
		});

		if (addonsProperties.getPermitAll().length > 0) {
			http.anonymous();
		}

		if (addonsProperties.getCors().length > 0) {
			http.cors().configurationSource(corsConfigurationSource(addonsProperties));
		} else {
			http.cors().disable();
		}

		switch (addonsProperties.getCsrf()) {
		case DISABLE:
			http.csrf().disable();
			break;
		case DEFAULT:
			if (addonsProperties.isStatlessSessions()) {
				http.csrf().disable();
			} else {
				http.csrf();
			}
			break;
		case SESSION:
			http.csrf();
			break;
		case COOKIE_HTTP_ONLY:
			http.csrf().csrfTokenRepository(new CookieCsrfTokenRepository());
			break;
		case COOKIE_ACCESSIBLE_FROM_JS:
			http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
			break;
		}

		if (addonsProperties.isStatlessSessions()) {
			http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		}

		if (!addonsProperties.isRedirectToLoginIfUnauthorizedOnRestrictedContent()) {
			http.exceptionHandling().authenticationEntryPoint((request, response, authException) -> {
				response.addHeader(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"Restricted Content\"");
				response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
			});
		}

		if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
			http.requiresChannel().anyRequest().requiresSecure();
		}

		authorizePostProcessor.authorizeHttpRequests(
				http.authorizeHttpRequests().requestMatchers(addonsProperties.getPermitAll()).permitAll());

		return httpPostProcessor.process(http).build();
	}

    /**
     * hook to override security rules for all path that are not listed in
     * "permit-all". Default is isAuthenticated().
     *
     * @return a hook to override security rules for all path that are not listed in
     *         "permit-all". Default is isAuthenticated().
     */
    @ConditionalOnMissingBean
    @Bean
    ExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor() {
        return registry -> registry.anyRequest().authenticated();
    }

    /**
     * Hook to override all or part of HttpSecurity auto-configuration.
     * Called after spring-addons configuration was applied so that you can
     * modify anything
     *
     * @return a hook to override all or part of HttpSecurity auto-configuration.
     *         Called after spring-addons configuration was applied so that you can
     *         modify anything
     */
    @ConditionalOnMissingBean
    @Bean
    HttpSecurityPostProcessor httpPostProcessor() {
        return httpSecurity -> httpSecurity;
    }

    private CorsConfigurationSource corsConfigurationSource(SpringAddonsSecurityProperties securityProperties) {
        log.debug("Building default CorsConfigurationSource with: {}",
                Stream.of(securityProperties.getCors()).toList());
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
     * Converter bean from successful introspection result to an
     * {@link Authentication} instance
     *
     * @param authoritiesConverter  converts access-token claims into Spring
     *                              authorities
     * @param authenticationFactory builds an {@link Authentication} instance from
     *                              access-token string and claims
     * @return a converter from successful introspection result to an
     *         {@link Authentication} instance
     */
	@ConditionalOnMissingBean
	@ConditionalOnProperty("spring.security.oauth2.resourceserver.opaquetoken.introspection-uri")
	@Bean
	OpaqueTokenAuthenticationConverter introspectingAuthenticationConverter(
			Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
			Optional<OAuth2AuthenticationFactory> authenticationFactory) {
		return (String introspectedToken, OAuth2AuthenticatedPrincipal authenticatedPrincipal) -> authenticationFactory
				.map(af -> af.build(introspectedToken, authenticatedPrincipal.getAttributes()))
				.orElse(new BearerTokenAuthentication(authenticatedPrincipal,
						new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, introspectedToken,
								authenticatedPrincipal.getAttribute(OAuth2TokenIntrospectionClaimNames.IAT),
								authenticatedPrincipal.getAttribute(OAuth2TokenIntrospectionClaimNames.EXP)),
						authoritiesConverter.convert(authenticatedPrincipal.getAttributes())));
	}

	public static interface Jwt2AuthenticationConverter extends Converter<Jwt, AbstractAuthenticationToken> {
	}

    /**
     * Converter bean from {@link Jwt} to {@link AbstractAuthenticationToken}
     *
     * @param authoritiesConverter  converts access-token claims into Spring
     *                              authorities
     * @param securityProperties    Spring "spring.security" configuration
     *                              properties
     * @param authenticationFactory builds an {@link Authentication} instance from
     *                              access-token string and claims
     * @return a converter from {@link Jwt} to {@link AbstractAuthenticationToken}
     */
	@ConditionalOnMissingBean
	@ConditionalOnMissingProperty("spring.security.oauth2.resourceserver.opaquetoken.introspection-uri")
	@Bean
	Jwt2AuthenticationConverter jwtAuthenticationConverter(
			Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
			SpringAddonsSecurityProperties securityProperties,
			Optional<OAuth2AuthenticationFactory> authenticationFactory) {
		return jwt -> authenticationFactory.map(af -> af.build(jwt.getTokenValue(), jwt.getClaims()))
				.orElse(new JwtAuthenticationToken(jwt, authoritiesConverter.convert(jwt.getClaims())));
	}

    /**
     * Provides with multi-tenancy: builds a JwtIssuerAuthenticationManagerResolver
     * per provided OIDC issuer URI
     *
     * @param auth2ResourceServerProperties "spring.security.oauth2.resourceserver"
     *                                      configuration properties
     * @param addonsProperties              "com.c4-soft.springaddons.security"
     *                                      configuration properties
     * @param jwtAuthenticationConverter    converts from a {@link Jwt} to an
     *                                      {@link Authentication} implementation
     * @return Multi-tenant {@link JwtIssuerAuthenticationManagerResolver} (one for
     *         each configured issuer)
     */
	@ConditionalOnMissingBean
	@ConditionalOnMissingProperty("spring.security.oauth2.resourceserver.opaquetoken.introspection-uri")
	@Bean
	JwtIssuerAuthenticationManagerResolver authenticationManagerResolver(
			OAuth2ResourceServerProperties auth2ResourceServerProperties,
			SpringAddonsSecurityProperties addonsProperties,
			Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter) {
		final var jwtProps = Optional.ofNullable(auth2ResourceServerProperties)
				.map(OAuth2ResourceServerProperties::getJwt);
		// @formatter:off
		Optional.ofNullable(jwtProps.map(OAuth2ResourceServerProperties.Jwt::getIssuerUri)).orElse(jwtProps.map(OAuth2ResourceServerProperties.Jwt::getJwkSetUri))
		    .filter(StringUtils::hasLength)
		    .ifPresent(jwtConf -> {
				log.warn("spring.security.oauth2.resourceserver configuration will be ignored in favor of com.c4-soft.springaddons.security");
			});
		// @formatter:on

		final Map<String, AuthenticationManager> jwtManagers = Stream.of(addonsProperties.getIssuers())
				.collect(Collectors.toMap(issuer -> issuer.getLocation().toString(), issuer -> {
					final JwtDecoder decoder = issuer.getJwkSetUri() != null
							&& StringUtils.hasLength(issuer.getJwkSetUri().toString())
									? NimbusJwtDecoder.withJwkSetUri(issuer.getJwkSetUri().toString()).build()
									: JwtDecoders.fromIssuerLocation(issuer.getLocation().toString());
					final var provider = new JwtAuthenticationProvider(decoder);
					provider.setJwtAuthenticationConverter(jwtAuthenticationConverter::convert);
					return provider::authenticate;
				}));

		log.debug("Building default JwtIssuerAuthenticationManagerResolver with: ",
				auth2ResourceServerProperties.getJwt(), Stream.of(addonsProperties.getIssuers()).toList());

		return new JwtIssuerAuthenticationManagerResolver((AuthenticationManagerResolver<String>) jwtManagers::get);
	}
}