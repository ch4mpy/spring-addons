package com.c4_soft.springaddons.security.oauth2.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Data
@Configuration
@ConfigurationProperties(prefix = "com.c4-soft.springaddons.security")
public class SecurityProperties {
	private KeycloakProperties keycloak;

	private Auth0Properties auth0;

	private CorsProperties cors;

	private String authoritiesPrefix = "";

	private String[] permitAll = { "/actuator/**", "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html", "/webjars/swagger-ui/**", "/favicon.ico" };

	@Data
	public static class KeycloakProperties {
		private String clientId;
	}

	@Data
	public static class CorsProperties {
		private String[] path;
		private String[] allowedOrigins;
	}

	@Data
	public static class Auth0Properties {
		private String rolesClaim = "https://manage.auth0.com/roles";
	}

}