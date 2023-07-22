package com.c4_soft.springaddons.security.oidc.starter.synchronised;

import static org.springframework.security.config.Customizer.withDefaults;

import java.io.IOException;
import java.util.Arrays;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.c4_soft.springaddons.security.oidc.starter.properties.CorsProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.Csrf;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcResourceServerProperties;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.client.ClientExpressionInterceptUrlRegistryPostProcessor;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.client.ClientHttpSecurityPostProcessor;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.ResourceServerExpressionInterceptUrlRegistryPostProcessor;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.ResourceServerHttpSecurityPostProcessor;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class ServletConfigurationSupport {

	public static HttpSecurity configureResourceServer(
			HttpSecurity http,
			ServerProperties serverProperties,
			SpringAddonsOidcResourceServerProperties addonsResourceServerProperties,
			ResourceServerExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor,
			ResourceServerHttpSecurityPostProcessor httpPostProcessor)
			throws Exception {

		ServletConfigurationSupport.configureCors(http, addonsResourceServerProperties.getCors());
		ServletConfigurationSupport.configureState(http, addonsResourceServerProperties.isStatlessSessions(), addonsResourceServerProperties.getCsrf());
		ServletConfigurationSupport.configureAccess(http, addonsResourceServerProperties.getPermitAll(), authorizePostProcessor);

		http.exceptionHandling(exceptionHandling -> exceptionHandling.authenticationEntryPoint((request, response, authException) -> {
			response.addHeader(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"Restricted Content\"");
			response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
		}));

		if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
			http.requiresChannel(channel -> channel.anyRequest().requiresSecure());
		}

		return httpPostProcessor.process(http);
	}

	public static HttpSecurity configureClient(
			HttpSecurity http,
			ServerProperties serverProperties,
			SpringAddonsOidcClientProperties addonsClientProperties,
			ClientExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor,
			ClientHttpSecurityPostProcessor httpPostProcessor)
			throws Exception {

		ServletConfigurationSupport.configureCors(http, addonsClientProperties.getCors());
		ServletConfigurationSupport.configureState(http, false, addonsClientProperties.getCsrf());
		ServletConfigurationSupport.configureAccess(http, addonsClientProperties.getPermitAll(), authorizePostProcessor);

		if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
			http.requiresChannel(channel -> channel.anyRequest().requiresSecure());
		}

		return httpPostProcessor.process(http);
	}

	public static HttpSecurity configureAccess(HttpSecurity http, String[] permitAll, ExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor)
			throws Exception {
		if (permitAll.length > 0) {
			http.anonymous(withDefaults());
			http.authorizeHttpRequests(registry -> authorizePostProcessor.authorizeHttpRequests(registry.requestMatchers(Stream.of(permitAll).map(AntPathRequestMatcher::new).toArray(AntPathRequestMatcher[]::new)).permitAll()));
		} else {
			http.authorizeHttpRequests(registry -> authorizePostProcessor.authorizeHttpRequests(registry));
		}
		return http;
	}

	public static HttpSecurity configureCors(HttpSecurity http, CorsProperties[] corsProperties) throws Exception {
		if (corsProperties.length == 0) {
			http.cors(cors -> cors.disable());
		} else {
			final var source = new UrlBasedCorsConfigurationSource();
			for (final var corsProps : corsProperties) {
				final var configuration = new CorsConfiguration();
				configuration.setAllowCredentials(corsProps.getAllowCredentials());
				configuration.setAllowedHeaders(Arrays.asList(corsProps.getAllowedHeaders()));
				configuration.setAllowedMethods(Arrays.asList(corsProps.getAllowedMethods()));
				configuration.setAllowedOriginPatterns(Arrays.asList(corsProps.getAllowedOriginPatterns()));
				configuration.setExposedHeaders(Arrays.asList(corsProps.getExposedHeaders()));
				configuration.setMaxAge(corsProps.getMaxAge());
				source.registerCorsConfiguration(corsProps.getPath(), configuration);
			}
			http.cors(cors -> cors.configurationSource(source));
		}
		return http;
	}

	public static HttpSecurity configureState(HttpSecurity http, boolean isStatless, Csrf csrfEnum) throws Exception {

		if (isStatless) {
			http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		}

		http.csrf(configurer -> {
			final var delegate = new XorCsrfTokenRequestAttributeHandler();
			delegate.setCsrfRequestAttributeName("_csrf");
			switch (csrfEnum) {
			case DISABLE:
				configurer.disable();
				break;
			case DEFAULT:
				if (isStatless) {
					configurer.disable();
				}
				break;
			case SESSION:
				break;
			case COOKIE_HTTP_ONLY:
				configurer.csrfTokenRepository(new CookieCsrfTokenRepository()).csrfTokenRequestHandler(delegate::handle);
				http.addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class);
				break;
			case COOKIE_ACCESSIBLE_FROM_JS:
				// Adapted from
				// https://docs.spring.io/spring-security/reference/5.8/migration/servlet/exploits.html#_i_am_using_angularjs_or_another_javascript_framework
				configurer.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).csrfTokenRequestHandler(delegate::handle);
				http.addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class);
				break;
			}
		});

		return http;
	}

	/**
	 * https://docs.spring.io/spring-security/reference/5.8/migration/servlet/exploits.html#_i_am_using_a_single_page_application_with_cookiecsrftokenrepository
	 */
	private static final class CsrfCookieFilter extends OncePerRequestFilter {

		@Override
		protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
				throws ServletException,
				IOException {
			CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
			// Render the token value to a cookie by causing the deferred token to be loaded
			csrfToken.getToken();

			filterChain.doFilter(request, response);
		}

	}
}
