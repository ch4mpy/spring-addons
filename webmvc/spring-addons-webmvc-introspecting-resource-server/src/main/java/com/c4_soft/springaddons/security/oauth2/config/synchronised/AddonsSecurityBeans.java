package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.c4_soft.springaddons.security.oauth2.config.ConfigurableClaimSet2AuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.OAuth2AuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;

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
 * <li><b>OpaqueTokenIntrospector</b>: extract authorities (could also turn introspection result into an Authentication of your choice if
 * https://github.com/spring-projects/spring-security/issues/11661 is solved)</li>
 * </ul>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@AutoConfiguration
@Import({ SpringAddonsSecurityProperties.class })
@EnableWebSecurity
@Slf4j
public class AddonsSecurityBeans {

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
	@Bean
	SecurityFilterChain filterChain(
			HttpSecurity http,
			ExpressionInterceptUrlRegistryPostProcessor expressionInterceptUrlRegistryPostProcessor,
			HttpSecurityPostProcessor httpSecurityPostProcessor,
			ServerProperties serverProperties,
			OAuth2ResourceServerProperties oauth2Properties,
			SpringAddonsSecurityProperties securityProperties)
			throws Exception {
		http.oauth2ResourceServer().opaqueToken();

		if (securityProperties.getPermitAll().length > 0) {
			http.anonymous();
		}

		if (securityProperties.getCors().length > 0) {
			http.cors().configurationSource(corsConfigurationSource(securityProperties));
		}

		if (securityProperties.isCsrfEnabled()) {
			final var configurer = http.csrf();
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
	 * Retrieves granted authorities from the introspected token attributes, according to configuration set for the issuer set in this
	 * attributes
	 *
	 * @param  securityProperties
	 * @return
	 */
	@ConditionalOnMissingBean
	@Bean
	OAuth2AuthoritiesConverter authoritiesConverter(SpringAddonsSecurityProperties securityProperties) {
		log.debug("Building default SimpleJwtGrantedAuthoritiesConverter with: {}", securityProperties);
		return new ConfigurableClaimSet2AuthoritiesConverter(securityProperties);
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
	<T extends Map<String, Object> & Serializable> OpaqueTokenIntrospector introspector(
			OAuth2ResourceServerProperties oauth2Properties,
			Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter) {
		// FIXME: remove when https://github.com/spring-projects/spring-security/issues/11661 is solved
		return new C4OpaqueTokenIntrospector(
				oauth2Properties.getOpaquetoken().getIntrospectionUri(),
				oauth2Properties.getOpaquetoken().getClientId(),
				oauth2Properties.getOpaquetoken().getClientSecret(),
				authoritiesConverter);
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
}