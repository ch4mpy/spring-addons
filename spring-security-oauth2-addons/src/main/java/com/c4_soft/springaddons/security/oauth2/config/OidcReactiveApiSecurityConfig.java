package com.c4_soft.springaddons.security.oauth2.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

import com.c4_soft.springaddons.security.oauth2.ReactiveJwt2AuthenticationConverter;

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
public class OidcReactiveApiSecurityConfig {
	private final ReactiveJwt2AuthenticationConverter<? extends AbstractAuthenticationToken> authenticationConverter;

	private final SpringAddonsSecurityProperties securityProperties;

	private final ServerProperties serverProperties;

	@ConditionalOnMissingBean
	@Bean
	public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http, ServerAccessDeniedHandler accessDeniedHandler) {

		http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(authenticationConverter);

		if (securityProperties.isAnonymousEnabled()) {
			http.anonymous();
		}

		if (securityProperties.getCors().length > 0) {
			http.cors();
		}

		if (securityProperties.isCsrfEnabled()) {
			http.csrf();
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
