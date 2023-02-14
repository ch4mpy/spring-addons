package com.c4soft.springaddons.tutorials;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

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
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

import com.c4_soft.springaddons.security.oauth2.config.ConfigurableClaimSet2AuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.ExpressionInterceptUrlRegistryPostProcessor;

@Configuration
@EnableMethodSecurity
public class WebSecurityConfig {

	/**
	 * <p>
	 * A default SecurityFilterChain is already defined by spring-addons-webmvc-jwt-resource-server to secure all API endpoints (actuator and
	 * REST controllers)
	 * </p>
	 * We define here another SecurityFilterChain for server-side rendered pages:
	 * <ul>
	 * <li>oauth2Login generated page and callback endpoint</li>
	 * <li>Swagger UI</ui>
	 * <li>Thymeleaf pages served by UiController</li>
	 * </ul>
	 * <p>
	 * It important to note that in this scenario, the end-user browser is not an OAuth2 client. Only the part of the server-side part of the
	 * Spring application secured with this filter chain is. Requests between the browser and Spring OAuth2 client are secured with
	 * <b>sessions</b>. As so, <b>CSRF protection must be active</b>.
	 * </p>
	 *
	 * @param  http
	 * @param  serverProperties
	 * @return                  an additional security filter-chain for UI elements (with OAuth2 login)
	 * @throws Exception
	 */
	@Order(Ordered.HIGHEST_PRECEDENCE)
	@Bean
	SecurityFilterChain uiFilterChain(HttpSecurity http, ServerProperties serverProperties, GrantedAuthoritiesMapper authoritiesMapper) throws Exception {
		boolean isSsl = serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled();

		// @formatter:off
	    http.securityMatcher(new OrRequestMatcher(
	            // UiController pages
	            new AntPathRequestMatcher("/ui/**"),
	            // Swagger pages
	            new AntPathRequestMatcher("/swagger-ui/**"),
	            // those two are required to access Spring generated login page
	            // and OAuth2 client callback endpoints
	            new AntPathRequestMatcher("/login/**"),
	            new AntPathRequestMatcher("/oauth2/**")));

	    http.oauth2Login()
	    		// I don't know quite why we are redirected to authorization-server port by default as initial login page is generated on client :/
			    .loginPage("%s://localhost:%d/oauth2/authorization/spring-addons-public".formatted(isSsl ? "https" : "http", serverProperties.getPort()) )
				// I don't know quite why we are redirected to authorization-server port by default as we initially tried to access a client resource :/
			    .defaultSuccessUrl("%s://localhost:%d/ui/index.html".formatted(isSsl ? "https" : "http", serverProperties.getPort()), true)
				// This is how to map authorities from ID claims issued by an OIDC provider of our choice (instead of just `scp` claim)
				// Here we make use of the authorities mapper already defined by spring-addons for default filter-chain (the one for resource-server)
				// Refer to your authorization doc if it does not include roles to ID-tokens by default. For Keycloak, "realm roles" & "client roles" mappers must be added in clients -> {your client} -> Client scopes -> {your client}-dedicated -> Add mapper.
			    .userInfoEndpoint().userAuthoritiesMapper(authoritiesMapper);

	    http.authorizeHttpRequests()
	            .requestMatchers("/login/**").permitAll()
	            .requestMatchers("/oauth2/**").permitAll()
	            .requestMatchers("/swagger-ui.html", "/swagger-ui/**").permitAll()
	            .anyRequest().authenticated();
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

	/**
	 * @param  authoritiesConverter We are in spring-addons, we have a {@link ConfigurableClaimSet2AuthoritiesConverter} in the context!
	 * @return                      a mapper from oauth2Login result to granted authorities
	 */
	@Bean
	GrantedAuthoritiesMapper userAuthoritiesMapper(Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter) {
		return (authorities) -> {
			Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

			authorities.forEach(authority -> {
				if (authority instanceof OidcUserAuthority oidcAuth) {
					mappedAuthorities.addAll(authoritiesConverter.convert(oidcAuth.getIdToken().getClaims()));

				} else if (authority instanceof OAuth2UserAuthority oauth2Auth) {
					mappedAuthorities.addAll(authoritiesConverter.convert(oauth2Auth.getAttributes()));

				}
			});

			return mappedAuthorities;
		};
	}
}