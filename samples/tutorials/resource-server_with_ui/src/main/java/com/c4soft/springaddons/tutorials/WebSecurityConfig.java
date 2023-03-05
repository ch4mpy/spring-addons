package com.c4soft.springaddons.tutorials;

import java.util.Collection;
import java.util.Map;

import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsOAuth2ClientProperties;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.ExpressionInterceptUrlRegistryPostProcessor;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@Configuration
@EnableMethodSecurity
public class WebSecurityConfig {

	/**
	 * <p>
	 * A default SecurityFilterChain is already defined by spring-addons-webmvc-jwt-resource-server to secure all API endpoints (actuator and REST controllers)
	 * </p>
	 * We define here another SecurityFilterChain for server-side rendered pages:
	 * <ul>
	 * <li>oauth2Login generated page and callback endpoint</li>
	 * <li>Swagger UI</ui>
	 * <li>Thymeleaf pages served by UiController</li>
	 * </ul>
	 * <p>
	 * It important to note that in this scenario, the end-user browser is not an OAuth2 client. Only the part of the server-side part of the Spring application
	 * secured with this filter chain is. Requests between the browser and Spring OAuth2 client are secured with <b>sessions</b>. As so, <b>CSRF protection must
	 * be active</b>.
	 * </p>
	 *
	 * @param  http
	 * @param  serverProperties
	 * @param  authoritiesMapper
	 * @param  appProperties
	 * @param  clientRegistrationRepository
	 * @return                              an additional security filter-chain for UI elements (with OAuth2 login)
	 * @throws Exception
	 */
	@Order(Ordered.HIGHEST_PRECEDENCE)
	@Bean
	SecurityFilterChain uiFilterChain(
			HttpSecurity http,
			ServerProperties serverProperties,
			OAuth2AuthorizationRequestResolver authorizationRequestResolver,
			SpringAddonsOAuth2ClientProperties clientProps,
			SpringAddonsSecurityProperties addonsProps,
			Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter)
			throws Exception {
		boolean isSsl = serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled();

		// @formatter:off
		http.securityMatcher(new OrRequestMatcher(
		    new AntPathRequestMatcher("/"),
		    // UiController pages
		    new AntPathRequestMatcher("/ui/**"),
		    // Swagger pages
		    new AntPathRequestMatcher("/swagger-ui/**"),
		    // spring-boot-starter-oauth2-client pages
		    new AntPathRequestMatcher("/login/**"),
		    new AntPathRequestMatcher("/oauth2/**"),
		    new AntPathRequestMatcher("/logout/**")));

		http.authorizeHttpRequests()
		    .requestMatchers("/", "/ui/", "/login/**", "/oauth2/**", "/logout/**").permitAll()
		    .requestMatchers("/swagger-ui.html", "/swagger-ui/**").permitAll()
		    .anyRequest().authenticated();

		http.anonymous();

		http.oauth2Login()
			.loginPage("%s/login".formatted(clientProps.getClientUri()))
			.authorizationEndpoint().authorizationRequestResolver(authorizationRequestResolver).and()
		    // When SSL is enabled, redirections are made to port 8443 instead of actual client port. Fix that.
		    .defaultSuccessUrl("%s/ui/greet".formatted(clientProps.getClientUri()), true)
		    .userInfoEndpoint().oidcUserService(new C4OAuth2UserService(authoritiesConverter));

	    http.logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"));
		// @formatter:on

		// If SSL enabled, disable http (https only)
		if (isSsl) {
			http.requiresChannel().anyRequest().requiresSecure();
		}

		// compared to API filter-chain:
		// - sessions and CSRF protection are left enabled
		// - unauthorized requests to secured resources will be redirected to login (302
		// to login is Spring's default response when access is
		// denied)

		return http.build();
	}

	@Bean
	ExpressionInterceptUrlRegistryPostProcessor expressionInterceptUrlRegistryPostProcessor() {
		// @formatter:off
        return (AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry) -> registry
            .requestMatchers(HttpMethod.GET, "/actuator/**").hasAuthority("OBSERVABILITY:read")
            .requestMatchers("/actuator/**").hasAuthority("OBSERVABILITY:write")
            .anyRequest().authenticated();
        // @formatter:on
	}

	@Data
	@RequiredArgsConstructor
	static class C4OAuth2UserService implements OAuth2UserService<OidcUserRequest, OidcUser> {
		private final Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter;

		@Override
		public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
			HttpSessionSupport.addIdentity(
					userRequest.getClientRegistration().getRegistrationId(),
					userRequest.getIdToken().getClaims().get(StandardClaimNames.SUB).toString(),
					userRequest.getIdToken().getTokenValue());

			final var authorities = authoritiesConverter.convert(userRequest.getIdToken().getClaims());
			return new DefaultOidcUser(authorities, userRequest.getIdToken());
		}

	}
}