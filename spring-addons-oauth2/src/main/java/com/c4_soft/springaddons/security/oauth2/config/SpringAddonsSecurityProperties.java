package com.c4_soft.springaddons.security.oauth2.config;

import java.net.URL;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Data;

/**
 * Here are defaults:
 *
 * <pre>
 * com.c4-soft.springaddons.security.issuers[0].location=https://localhost:8443/realms/master
 * com.c4-soft.springaddons.security.issuers[0].authorities.claims=realm_access.roles,permissions
 * com.c4-soft.springaddons.security.issuers[0].authorities.prefix=
 * com.c4-soft.springaddons.security.issuers[0].authorities.caze=
 * com.c4-soft.springaddons.security.cors[0].path=/**
 * com.c4-soft.springaddons.security.cors[0].allowed-origins=*
 * com.c4-soft.springaddons.security.cors[0].allowedOrigins=*
 * com.c4-soft.springaddons.security.cors[0].allowedMethods=*
 * com.c4-soft.springaddons.security.cors[0].allowedHeaders=*
 * com.c4-soft.springaddons.security.cors[0].exposedHeaders=*
 * com.c4-soft.springaddons.security.csrf-enabled=true
 * com.c4-soft.springaddons.security.permit-all=
 * com.c4-soft.springaddons.security.redirect-to-login-if-unauthorized-on-restricted-content=true
 * com.c4-soft.springaddons.security.statless-sessions=true
 * </pre>
 *
 * @author ch4mp
 */
@Data
@AutoConfiguration
@ConfigurationProperties(prefix = "com.c4-soft.springaddons.security")
public class SpringAddonsSecurityProperties {
	private IssuerProperties[] issuers = {};
	private CorsProperties[] cors = {};
	private boolean csrfEnabled = true;
	private String[] permitAll = { "/actuator/**", "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html", "/webjars/swagger-ui/**", "/favicon.ico" };
	private boolean redirectToLoginIfUnauthorizedOnRestrictedContent = false;
	private boolean statlessSessions = true;

	@Data
	public static class CorsProperties {
		private String path = "/**";
		private String[] allowedOrigins = { "*" };
		private String[] allowedMethods = { "*" };
		private String[] allowedHeaders = { "*" };
		private String[] exposedHeaders = { "*" };
	}

	@Data
	public static class IssuerProperties {
		private URL location;
		private SimpleAuthoritiesMappingProperties authorities = new SimpleAuthoritiesMappingProperties();
	}

	@Data
	public static class SimpleAuthoritiesMappingProperties {
		private String[] claims = { "realm_access.roles" };
		private String prefix = "";
		private Case caze = Case.UNCHANGED;
	}

	public enum Case {
		UNCHANGED, UPPER, LOWER
	}
}