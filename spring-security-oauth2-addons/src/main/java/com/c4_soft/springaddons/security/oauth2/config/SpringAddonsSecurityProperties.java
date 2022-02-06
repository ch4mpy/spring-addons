package com.c4_soft.springaddons.security.oauth2.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

/**
 * Used to configure abstract web security-config {@link OidcServletApiSecurityConfig} and {@link OidcReactiveApiSecurityConfig}. Here are
 * defaults:
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
 * @author ch4mp
 */
@Data
@Configuration
@ConfigurationProperties(prefix = "com.c4-soft.springaddons.security")
public class SpringAddonsSecurityProperties {
	private KeycloakProperties keycloak;

	private Auth0Properties auth0;

	private CorsProperties cors;

	private String authoritiesPrefix = "";

	private boolean uppercaseAuthorities = false;

	private String[] permitAll = { "/actuator/**", "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html", "/webjars/swagger-ui/**", "/favicon.ico" };

	@Data
	public static class KeycloakProperties {
		private String clientId;
	}

	@Data
	public static class CorsProperties {
		private String[] path = { "/**" };
		private String[] allowedOrigins = { "*" };
		private String[] allowedMethods = { "*" };
		private String[] allowedHeaders = { "*" };
		private String[] exposedHeaders = { "*" };
	}

	@Data
	public static class Auth0Properties {
		private String rolesClaim = "https://manage.auth0.com/roles";
	}

}