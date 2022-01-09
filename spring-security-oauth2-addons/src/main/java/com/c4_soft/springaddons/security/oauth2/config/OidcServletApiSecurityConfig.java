package com.c4_soft.springaddons.security.oauth2.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.Jwt;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * <p>
 * Web-security configuration for servlet APIs using OidcAuthentication.
 * </p>
 * <p>
 * authorizeRequests default behavior is granting access to anyone at \"permitAll\" endpoints 
 * and restricting access to authenticated users everywhere else.
 * You might override authorizeRequests to change second behavior (fined grained access-control to non \"permitAll\" endpoints)
 * </p>
 * <p>
 * Quite a few properties allow to configure web security-config
 * {@link SpringAddonsSecurityProperties}
 * </p>
 * 
 * Here are the defaults:
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
 * <p>
 * You also might provide your own beans to replace some of &#64;ConditionalOnMissingBean exposed by {@link ServletSecurityBeans} (for instance authorities or authentication converters)
 * </p>
 *
 * Sample implementation:
 *
 * <pre>
 * &#64;EnableWebSecurity
 * &#64;EnableGlobalMethodSecurity(prePostEnabled = true)
 * &#64;Import({SpringAddonsSecurityProperties.class, ServletSecurityBeans.class})
 * public static class WebSecurityConfig extends OidcServletApiSecurityConfig {
 * 	&#64;Autowired
 * 	public WebSecurityConfig(Converter&lt;Jwt, ? extends AbstractAuthenticationToken&gt; authenticationConverter, SecurityProperties securityProperties) {
 * 		super(authenticationConverter, securityProperties);
 * 	}
 * 
 *  &#64;Override
 * 	protected ExpressionUrlAuthorizationConfigurer&lt;HttpSecurity&gt;.ExpressionInterceptUrlRegistry authorizeRequests(ExpressionUrlAuthorizationConfigurer&lt;HttpSecurity>.ExpressionInterceptUrlRegistry registry) {
 *  	super.authorizeRequests(registry)
 *  }
 * }
 * </pre>
 *
 * @author ch4mp
 */
@Getter
@RequiredArgsConstructor
public class OidcServletApiSecurityConfig extends WebSecurityConfigurerAdapter {
	private final Converter<Jwt, ? extends AbstractAuthenticationToken> authenticationConverter;
	private final SpringAddonsSecurityProperties securityProperties;

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.oauth2ResourceServer().jwt()
				.jwtAuthenticationConverter(authenticationConverter);

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

	protected ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry authorizeRequests(
			ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry registry) {
		return registry.anyRequest().authenticated();
	}

}
