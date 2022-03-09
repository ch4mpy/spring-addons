package com.c4_soft.springaddons.security.oauth2.config;

import javax.servlet.http.HttpServletRequest;

import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * <p>
 * Web-security configuration for servlet APIs using OidcAuthentication.
 * </p>
 * <p>
 * authorizeRequests default behavior is granting access to anyone at \"permitAll\" endpoints and restricting access to authenticated users
 * everywhere else. You might override authorizeRequests to change second behavior (fined grained access-control to non \"permitAll\"
 * endpoints)
 * </p>
 * <p>
 * Quite a few properties allow to configure web security-config {@link SpringAddonsSecurityProperties}
 * </p>
 * Here are the defaults:
 *
 * <pre>
 * com.c4-soft.springaddons.security.anonymous-enabled=true
 * com.c4-soft.springaddons.security.authorities-claims=realm_access.roles
 * com.c4-soft.springaddons.security.authorities-prefix=
 * com.c4-soft.springaddons.security.authorities-uppercase=false
 * com.c4-soft.springaddons.security.cors[0].path=/**
 * com.c4-soft.springaddons.security.cors[0].allowed-origins=*
 * com.c4-soft.springaddons.security.cors[0].allowedOrigins=*
 * com.c4-soft.springaddons.security.cors[0].allowedMethods=*
 * com.c4-soft.springaddons.security.cors[0].allowedHeaders=*
 * com.c4-soft.springaddons.security.cors[0].exposedHeaders=*
 * com.c4-soft.springaddons.security.csrf-enabled=false
 * com.c4-soft.springaddons.security.permit-all=
 * com.c4-soft.springaddons.security.redirect-to-login-if-unauthorized-on-restricted-content=true
 * com.c4-soft.springaddons.security.statless-sessions=true
 * </pre>
 * <p>
 * You also might provide your own beans to replace some of &#64;ConditionalOnMissingBean exposed by {@link ServletSecurityBeans} (for
 * instance authorities or authentication converters)
 * </p>
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
 * 	protected ExpressionUrlAuthorizationConfigurer&lt;HttpSecurity&gt;.ExpressionInterceptUrlRegistry authorizeRequests(ExpressionUrlAuthorizationConfigurer&lt;HttpSecurity&gt;.ExpressionInterceptUrlRegistry registry) {
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

	private final AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver;

	private final SpringAddonsSecurityProperties securityProperties;

	private final ServerProperties serverProperties;

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.oauth2ResourceServer(oauth2 -> oauth2.authenticationManagerResolver(authenticationManagerResolver));

		if (securityProperties.isAnonymousEnabled()) {
			http.anonymous();
		}

		if (securityProperties.getCors().length > 0) {
			http.cors();
		}

		if (!securityProperties.isCsrfEnabled()) {
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

		authorizeRequests(http.authorizeRequests().antMatchers(securityProperties.getPermitAll()).permitAll());
	}

	protected ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry authorizeRequests(
			ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry registry) {
		return registry.anyRequest().authenticated();
	}

}
