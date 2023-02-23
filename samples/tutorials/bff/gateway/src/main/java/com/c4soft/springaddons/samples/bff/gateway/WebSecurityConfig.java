package com.c4soft.springaddons.samples.bff.gateway;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.web.server.Ssl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;

@Configuration
@EnableMethodSecurity
public class WebSecurityConfig {

	@Order(Ordered.HIGHEST_PRECEDENCE)
	@Bean
	SecurityWebFilterChain clientFilterChain(
			ServerHttpSecurity http,
			ServerProperties serverProperties,
			ReactiveClientRegistrationRepository clientRegistrationRepository,
			@Value("gateway-uri") String gatewayUri)
			throws Exception {

	    final var isSsl = Optional.ofNullable(serverProperties.getSsl()).map(Ssl::isEnabled).orElse(false);
	    
		// @formatter:off
	    
	    // securityMatcher is restricted to UI resources and we want all to be accessible to anonymous
	    http.authorizeExchange().pathMatchers("/", "/login/**", "/logout", "/oauth2/**", "/ui/**").permitAll()
	    	.anyExchange().authenticated();
	    
	    http.oauth2Login();
	    
	    http.logout().logoutSuccessHandler(
    		oidcLogoutSuccessHandler(clientRegistrationRepository, "%s/ui/".formatted(gatewayUri)));
	    
	    // @formatter:on

		// If SSL enabled, disable http (https only)
		if (isSsl) {
			http.redirectToHttps();
		}

		// sessions and CSRF protection are left enabled in this security filter-chain

		return http.build();
	}

	private ServerLogoutSuccessHandler oidcLogoutSuccessHandler(ReactiveClientRegistrationRepository clientRegistrationRepository, String postLogoutUri) {
		var oidcLogoutSuccessHandler = new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository);

		oidcLogoutSuccessHandler.setPostLogoutRedirectUri(postLogoutUri);

		return oidcLogoutSuccessHandler;
	}
}