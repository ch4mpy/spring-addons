package com.c4_soft.springaddons.security.oauth2.config.reactive;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.web.server.ServerWebExchange;

import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * <p>
 * Web-security configuration for reactive (webflux) APIs using OidcAuthentication.
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
 * You also might provide your own beans to replace some of &#64;ConditionalOnMissingBean exposed by {@link ReactiveSecurityBeans} (for
 * instance authorities or authentication converters)
 * </p>
 * Sample implementation:
 *
 * <pre>
 * &#64;EnableWebFluxSecurity
 * &#64;EnableWebFluxSecurity
 * &#64;EnableReactiveMethodSecurity
 * &#64;Import({ SpringAddonsSecurityProperties.class, ReactiveSecurityBeans.class })
 * public static class WebSecurityConfig extends OidcReactiveApiSecurityConfig {
 * 	public WebSecurityConfig(
 * 			ReactiveJwt2AuthenticationConverter&lt;? extends AbstractAuthenticationToken&gt; authenticationConverter,
 * 			SpringAddonsSecurityProperties securityProperties) {
 * 		super(authenticationConverter, securityProperties);
 * 	}
 *
 * 	&#64;Override
 * 	protected AuthorizeExchangeSpec authorizeRequests(AuthorizeExchangeSpec spec) {
 * 		return spec.pathMatchers("/secured-endpoint").hasAnyRole("AUTHORIZED_PERSONNEL").anyExchange().authenticated();
 * 	}
 * }
 * </pre>
 *
 * @author ch4mp
 */
@Getter
@RequiredArgsConstructor
@Import({ SpringAddonsSecurityProperties.class })
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class OidcReactiveApiSecurityConfig {

	private final ReactiveAuthenticationManagerResolver<ServerWebExchange> authenticationManagerResolver;

	private final SpringAddonsSecurityProperties securityProperties;

	private final ServerProperties serverProperties;

	@ConditionalOnMissingBean
	@Bean
	public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http, ServerAccessDeniedHandler accessDeniedHandler) {

		http.oauth2ResourceServer().authenticationManagerResolver(authenticationManagerResolver);

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
			http.securityContextRepository(NoOpServerSecurityContextRepository.getInstance());
		}

		if (!securityProperties.isRedirectToLoginIfUnauthorizedOnRestrictedContent()) {
			http.exceptionHandling().accessDeniedHandler(accessDeniedHandler);
		}

		if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
			http.redirectToHttps();
		}

		authorizeRequests(http.authorizeExchange().pathMatchers(securityProperties.getPermitAll()).permitAll());

		return http.build();
	}

	protected ServerHttpSecurity.AuthorizeExchangeSpec authorizeRequests(ServerHttpSecurity.AuthorizeExchangeSpec spec) {
		return spec.anyExchange().authenticated();
	}

}
