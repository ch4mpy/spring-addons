package com.c4_soft.springaddons.security.oauth2.config;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2GrantedAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.oidc.SynchronizedJwt2OidcAuthenticationConverter;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * <p>
 * Web-security configuration for servlet APIs using OidcAuthentication.
 * </p>
 * <p>
 * authorizeRequests default behavior is setting \"permitAll\" (see SecurityProperties) endpoints access to anyone and requesting
 * authentication for others.
 * </p>
 * Sample implementation:
 *
 * <pre>
 * public static class WebSecurityConfig extends AbstractServletWebSecurityConfig {
 * 	&#64;Autowired
 * 	public WebSecurityConfig(&#64;Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUri, SecurityProperties securityProperties) {
 * 		super(issuerUri, securityProperties);
 * 	}
 *
 * 	&#64;Override
 * 	protected SynchronizedJwt2GrantedAuthoritiesConverter authoritiesConverter() {
 * 		return new KeycloakJwt2GrantedAuthoritiesConverter(getSecurityProperties());
 * 	}
 * }
 * </pre>
 *
 * @author ch4mp
 */
@Getter
@RequiredArgsConstructor
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Import(SecurityProperties.class)
public abstract class AbstractOidcServletApiSecurityConfig extends WebSecurityConfigurerAdapter {
	@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
	private final String issuerUri;

	private final SecurityProperties securityProperties;

	protected abstract SynchronizedJwt2GrantedAuthoritiesConverter authoritiesConverter();

	protected ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry authorizeRequests(
			ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry registry) {
		return registry.anyRequest().authenticated();
	}

	@Bean
	public JwtDecoder jwtDecoder() {
		return JwtDecoders.fromOidcIssuerLocation(issuerUri);
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		final CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList(securityProperties.getCors().getAllowedOrigins()));
		configuration.setAllowedMethods(Arrays.asList("*"));
		configuration.setExposedHeaders(Arrays.asList("Origin", "Accept", "Content-Type", "Location"));
		final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		for (final String p : securityProperties.getCors().getPath()) {
			source.registerCorsConfiguration(p, configuration);
		}
		return source;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(new SynchronizedJwt2OidcAuthenticationConverter(authoritiesConverter()));

		// @formatter:off
        http.anonymous().and()
            .cors().and()
            .csrf().disable()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
            .exceptionHandling().authenticationEntryPoint((request, response, authException) -> {
                response.addHeader(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"Restricted Content\"");
                response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
            });

        authorizeRequests(http.authorizeRequests().antMatchers(securityProperties.getPermitAll()).permitAll());
        // @formatter:on

		http.requiresChannel().anyRequest().requiresSecure();
	}

}
