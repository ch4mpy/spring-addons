package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import java.io.Serializable;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.servlet.http.HttpServletRequest;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.SupplierJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.c4_soft.springaddons.security.oauth2.OAuthentication;
import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;
import com.c4_soft.springaddons.security.oauth2.config.ClaimSet2AuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.ConfigurableClaimSet2AuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.Jwt2ClaimSetConverter;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties.IssuerProperties;

import lombok.extern.slf4j.Slf4j;

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
 * <li><b>SecurityFilterChain</b>: applies CORS, CSRF, anonymous, sessionCreationPolicy, SSL redirect and 401 instead of redirect to login
 * properties as defined in {@link SpringAddonsSecurityProperties}</li>
 * <li><b>ExpressionInterceptUrlRegistryPostProcessor</b>. Override if you need fined grained HTTP security (more than authenticated() to
 * all routes but the ones defined as permitAll() in {@link SpringAddonsSecurityProperties}</li>
 * <li><b>SimpleJwtGrantedAuthoritiesConverter</b>: responsible for converting the JWT into Collection&lt;? extends
 * GrantedAuthority&gt;</li>
 * <li><b>SynchronizedJwt2OpenidClaimSetConverter&lt;T extends Map&lt;String, Object&gt; &amp; Serializable&gt;</b>: responsible for
 * converting the JWT into a claim-set of your choice (OpenID or not)</li>
 * <li><b>SynchronizedJwt2AuthenticationConverter&lt;OAuthentication&lt;T&gt;&gt;</b>: responsible for converting the JWT into an
 * Authentication (uses both beans above)</li>
 * <li><b>JwtIssuerAuthenticationManagerResolver</b>: required to be able to define more than one token issuer until
 * https://github.com/spring-projects/spring-boot/issues/30108 is solved</li>
 * </ul>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Configuration
@Import({ SpringAddonsSecurityProperties.class })
@EnableWebSecurity
@Slf4j
public class ServletSecurityBeans {

	/**
	 * Hook to override security rules for all path that are not listed in "permit-all". Default is isAuthenticated().
	 *
	 * @param  securityProperties
	 * @return
	 */
	@ConditionalOnMissingBean
	@Bean
	ExpressionInterceptUrlRegistryPostProcessor expressionInterceptUrlRegistryPostProcessor(SpringAddonsSecurityProperties securityProperties) {
		return registry -> registry.anyRequest().authenticated();
	}

	/**
	 * Hook to override all or part of HttpSecurity auto-configuration. Called after spring-addons configuration was applied so that you can
	 * modify anything
	 *
	 * @return
	 */
	@ConditionalOnMissingBean
	@Bean
	HttpSecurityPostProcessor httpSecurityPostProcessor() {
		return httpSecurity -> httpSecurity;
	}

	/**
	 * Applies SpringAddonsSecurityProperties to web security config. Be aware that overriding this bean will disable most of this lib
	 * auto-configuration for OpenID resource-servers. You should consider providing a HttpSecurityPostProcessor bean instead.
	 *
	 * @param  http
	 * @param  authenticationManagerResolver
	 * @param  expressionInterceptUrlRegistryPostProcessor
	 * @param  serverProperties
	 * @param  securityProperties
	 * @return
	 * @throws Exception
	 */
	@ConditionalOnMissingBean
	@Bean
	SecurityFilterChain filterChain(
			HttpSecurity http,
			AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver,
			ExpressionInterceptUrlRegistryPostProcessor expressionInterceptUrlRegistryPostProcessor,
			HttpSecurityPostProcessor httpSecurityPostProcessor,
			ServerProperties serverProperties,
			SpringAddonsSecurityProperties securityProperties)
			throws Exception {
		http.oauth2ResourceServer(oauth2 -> oauth2.authenticationManagerResolver(authenticationManagerResolver));

		if (securityProperties.getPermitAll().length > 0) {
			http.anonymous();
		}

		if (securityProperties.getCors().length > 0) {
			http.cors().configurationSource(corsConfigurationSource(securityProperties));
		}

		if (securityProperties.isCsrfEnabled()) {
			final CsrfConfigurer<HttpSecurity> configurer = http.csrf();
			if (securityProperties.isStatlessSessions()) {
				configurer.csrfTokenRepository(new CookieCsrfTokenRepository());
			}
		} else {
			http.csrf().disable();
		}

		if (securityProperties.isStatlessSessions()) {
			http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		}

		if (!securityProperties.isRedirectToLoginIfUnauthorizedOnRestrictedContent()) {
			http.exceptionHandling().authenticationEntryPoint((request, response, authException) -> {
				response.addHeader(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"Restricted Content\"");
				response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
			});
		}

		if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
			http.requiresChannel().anyRequest().requiresSecure();
		} else {
			http.requiresChannel().anyRequest().requiresInsecure();
		}

		expressionInterceptUrlRegistryPostProcessor.authorizeRequests(http.authorizeRequests().antMatchers(securityProperties.getPermitAll()).permitAll());

		return httpSecurityPostProcessor.process(http).build();
	}

	/**
	 * Converts a Jwt to an Authentication instance.
	 *
	 * @param  <T>                  a set of claims (or token attributes or whatever you want to call it) that will serve as
	 *                              &#64;AuthenticationPrincipal
	 * @param  authoritiesConverter retrieves granted authorities from the Jwt (from its private claims or with the help of an external service)
	 * @param  claimsConverter      extract claims from the Jwt and turn it into a T
	 * @return
	 */
	@ConditionalOnMissingBean
	@Bean
	<T extends Map<String, Object> & Serializable> SynchronizedJwt2AuthenticationConverter<OAuthentication<T>> authenticationConverter(
			ClaimSet2AuthoritiesConverter<T> authoritiesConverter,
			Jwt2ClaimSetConverter<T> claimsConverter) {
		log.debug("Building default SynchronizedJwt2OAuthenticationConverter");
		return new SynchronizedJwt2OAuthenticationConverter<>(authoritiesConverter, claimsConverter);
	}

	/**
	 * Retrieves granted authorities from the Jwt (from its private claims or with the help of an external service)
	 *
	 * @param  securityProperties
	 * @return
	 */
	@ConditionalOnMissingBean
	@Bean
	<T extends Map<String, Object> & Serializable> ClaimSet2AuthoritiesConverter<T> authoritiesConverter(SpringAddonsSecurityProperties securityProperties) {
		log.debug("Building default SimpleJwtGrantedAuthoritiesConverter with: {}", securityProperties);
		return new ConfigurableClaimSet2AuthoritiesConverter<>(securityProperties);
	}

	/**
	 * Extract claims from the Jwt and turn it into a T extends Map<String, Object> &amp; Serializable
	 *
	 * @return
	 */
	@ConditionalOnMissingBean
	@Bean
	Jwt2ClaimSetConverter<OpenidClaimSet> claimsConverter() {
		log.debug("Building default SynchronizedJwt2OpenidClaimSetConverter");
		return (Jwt jwt) -> new OpenidClaimSet(jwt.getClaims());
	}

	/**
	 * Provides with multi-tenancy: builds a JwtIssuerAuthenticationManagerResolver per provided OIDC issuer URI
	 *
	 * @param  auth2ResourceServerProperties
	 * @param  securityProperties
	 * @param  authenticationConverter       converts from a Jwt to an `Authentication` implementation
	 * @return
	 */
	@ConditionalOnMissingBean
	@Bean
	JwtIssuerAuthenticationManagerResolver authenticationManagerResolver(
			OAuth2ResourceServerProperties auth2ResourceServerProperties,
			SpringAddonsSecurityProperties securityProperties,
			Converter<Jwt, ? extends AbstractAuthenticationToken> authenticationConverter) {
		final Set<String> locations = new HashSet<>();
		Optional.of(auth2ResourceServerProperties.getJwt())
				.map(org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties.Jwt::getIssuerUri)
				.ifPresent(locations::add);
		Stream.of(securityProperties.getIssuers()).map(IssuerProperties::getLocation).filter(Objects::nonNull).map(Serializable::toString)
				.forEach(locations::add);
		locations.stream().filter(Objects::nonNull).map(Serializable::toString).filter(StringUtils::hasLength).collect(Collectors.toSet());
		final Map<String, AuthenticationManager> jwtManagers = locations.stream().collect(Collectors.toMap(l -> l, l -> {
			final JwtDecoder decoder = new SupplierJwtDecoder(() -> JwtDecoders.fromIssuerLocation(l));
			final JwtAuthenticationProvider provider = new JwtAuthenticationProvider(decoder);
			provider.setJwtAuthenticationConverter(authenticationConverter);
			return provider::authenticate;
		}));

		log.debug(
				"Building default JwtIssuerAuthenticationManagerResolver with: ",
				auth2ResourceServerProperties.getJwt(),
				Stream.of(securityProperties.getIssuers()).collect(Collectors.toList()));

		return new JwtIssuerAuthenticationManagerResolver((AuthenticationManagerResolver<String>) jwtManagers::get);
	}

	private CorsConfigurationSource corsConfigurationSource(SpringAddonsSecurityProperties securityProperties) {
		log.debug("Building default CorsConfigurationSource with: {}", Stream.of(securityProperties.getCors()).collect(Collectors.toList()));
		final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		for (final SpringAddonsSecurityProperties.CorsProperties corsProps : securityProperties.getCors()) {
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