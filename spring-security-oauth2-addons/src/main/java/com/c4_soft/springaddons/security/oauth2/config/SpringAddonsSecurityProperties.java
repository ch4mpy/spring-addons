package com.c4_soft.springaddons.security.oauth2.config;

import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;

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
	private String[] authoritiesClaims = { "realm_access.roles" };

	private String authoritiesPrefix = "";

	private boolean authoritiesUppercase = false;

	private CorsProperties[] cors = {};

	private boolean anonymousEnabled = true;

	private boolean csrfEnabled = false;

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

	public Stream<GrantedAuthority> getAuthorities(Map<String, Object> claims) {
		return Stream
				.of(authoritiesClaims)
				.flatMap(rolesPath -> getRoles(claims, rolesPath))
				.map(r -> authoritiesPrefix + (authoritiesUppercase ? r.toUpperCase() : r))
				.map(r -> (GrantedAuthority) new SimpleGrantedAuthority(r));

	}

	private static Stream<String> getRoles(Map<String, Object> claims, String rolesPath) {

		final String[] claimsToWalk = rolesPath.split("\\.");
		int i = 0;
		Optional<Map<String, Object>> obj = Optional.of(claims);
		while (i++ < claimsToWalk.length) {
			final String claimName = claimsToWalk[i - 1];
			if (i == claimsToWalk.length) {
				return obj.map(o -> (JSONArray) o.get(claimName)).orElse(new JSONArray()).stream().map(Object::toString);
			}
			obj = obj.map(o -> (JSONObject) o.get(claimName));

		}
		return Stream.empty();
	}

}