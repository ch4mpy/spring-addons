package com.c4_soft.springaddons.security.oauth2.config;

import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.util.StringUtils;
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
 * <p>
 * Quite a few properties allow to configure web security-config {@link SecurityProperties}
 * </p>
 * Here are the defaults
 *
 * <pre>
 * com.c4-soft.springaddons.security.authorities-prefix=
 * com.c4-soft.springaddons.security.uppercase-authorities=false
 * com.c4-soft.springaddons.security.permit-all=/actuator/**,/v3/api-docs/**,/swagger-ui/**,/swagger-ui.html,/webjars/swagger-ui/**,/favicon.ico
 * com.c4-soft.springaddons.security.cors.path=/**
 * com.c4-soft.springaddons.security.cors.allowed-origins=*
 * com.c4-soft.springaddons.security.cors.allowed-methods=*
 * com.c4-soft.springaddons.security.cors.allowed-headers=*
 * com.c4-soft.springaddons.security.cors.exposed-headers=*
 * com.c4-soft.springaddons.security.keycloak.client-id=
 * com.c4-soft.springaddons.security.auth0.roles-claim=https://manage.auth0.com/roles
 * </pre>
 *
 * Sample implementation:
 *
 * <pre>
 * &#64;EnableWebSecurity
 * &#64;EnableGlobalMethodSecurity(prePostEnabled = true)
 * &#64;Import(SecurityProperties.class)
 * public static class WebSecurityConfig extends OidcServletApiSecurityConfig {
 * 	&#64;Autowired
 * 	public WebSecurityConfig(&#64;Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUri, SecurityProperties securityProperties) {
 * 		super(issuerUri, securityProperties);
 * 	}
 * }
 * </pre>
 *
 * @author ch4mp
 */
@Getter
@RequiredArgsConstructor
public class OidcServletApiSecurityConfig extends WebSecurityConfigurerAdapter {
	private final String issuerUri;

	private final SecurityProperties securityProperties;

	protected SynchronizedJwt2GrantedAuthoritiesConverter authoritiesConverter() {
		return this.securityProperties.getKeycloak() != null && StringUtils.hasLength(this.securityProperties.getKeycloak().getClientId())
				? new KeycloakSynchronizedJwt2GrantedAuthoritiesConverter(securityProperties)
				: new Auth0SynchronizedJwt2GrantedAuthoritiesConverter(securityProperties);
	}

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
		final var configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList(securityProperties.getCors().getAllowedOrigins()));
		configuration.setAllowedMethods(Arrays.asList(securityProperties.getCors().getAllowedMethods()));
		configuration.setAllowedHeaders(Arrays.asList(securityProperties.getCors().getAllowedHeaders()));
		configuration.setExposedHeaders(Arrays.asList(securityProperties.getCors().getExposedHeaders()));
		final var source = new UrlBasedCorsConfigurationSource();
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
